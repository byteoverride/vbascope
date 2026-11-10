#!/usr/bin/env python3
"""
vbascope - malicious document static analysis engine.

A FOR610-friendly CLI that extracts VBA/XLM macros from Office documents, RTF
carriers and script files, runs a battery of static detections mapped to MITRE
ATT&CK, scores risk, and emits terminal / JSON / HTML reports.

IMPORTANT: vbascope performs STATIC analysis only. It never executes macro code
or launches the sample. Every string pulled from a sample is treated as
untrusted data.

Usage:
    vbascope analyze <file_or_dir> [options]
    vbascope --setup

See --help for the full option list.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import traceback
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

# --- Package imports (work both as module and as a direct script) ---
_PKG_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from utils import compute_hashes, identify_file, FileType  # noqa: E402
from utils.deps import ensure_dependencies, print_dependency_report, check_system_tools  # noqa: E402
from utils.file_id import FileIdentity  # noqa: E402

from extractors import (  # noqa: E402
    extract_vba, extract_xlm, extract_rtf_objects, extract_metadata,
    extract_onenote, scan_pdf, extract_lnk, check_xll,
)
from extractors.vba_extractor import VBAResult, VBAModule, _extract_with_olevba  # noqa: E402

from analyzers import (  # noqa: E402
    analyze_static, extract_iocs, analyze_obfuscation, scan_yara,
)

from reporters import render_terminal, write_json, write_html, append_csv  # noqa: E402


__version__ = "1.0.0"

# Passwords commonly used on "protected" malspam attachments.
COMMON_PASSWORDS = ["infected", "malware", "virus", "password", "1234"]

# OOXML members worth decompressing into the string-analysis corpus. Office
# payloads (DDE fields, remote-template refs, URLs, embedded script) live in
# these parts and are zip-compressed, so scanning the raw container bytes both
# misses them and produces junk IOCs from compressed data.
_OOXML_TEXT_EXTS = (".xml", ".rels", ".txt", ".vml", ".htm", ".html")

# File extensions we handle directly as script "macros".
SCRIPT_EXTS = {".hta", ".vbs", ".wsf", ".js", ".jse", ".wsh"}
# Container/archive extensions for the bonus recursive mode.
ARCHIVE_EXTS = {".zip", ".rar", ".7z"}


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------
def score_risk(report: dict) -> dict:
    """Compute a 0-100 risk score with an itemised breakdown.

    Weights follow the engagement spec:
        auto-exec +20 each, shell/exec +15, download +15, obfuscation +10,
        embedded PE +25, suspicious metadata +5, YARA match +10. Capped at 100.
    """
    breakdown: List[Dict] = []
    score = 0

    def add(points: int, reason: str) -> None:
        nonlocal score
        score += points
        breakdown.append({"points": points, "reason": reason})

    # Auto-execution triggers (+20 each).
    for trig in report["static"]["autoexec_triggers"]:
        add(20, f"Auto-execution trigger: {trig}")

    # Category-based capability weighting from findings. Each distinct
    # capability (by name) is credited once so repeated hits don't runaway.
    # Per-category weight. Quantitative obfuscation (Chr density, base64,
    # entropy) is scored separately via the obfuscation sub-score, so the
    # generic "obfuscation" category is weighted lightly here and only its
    # genuinely dangerous members (dynamic code execution) are called out.
    _CATEGORY_WEIGHT = {
        "exploit": 20,      # Follina / protocol-handler RCE (T1203/T1218)
        "execution": 15,    # Shell/WMI/PowerShell/mshta = code execution (T1059)
        "download": 15,     # payload retrieval (T1105)
        "smuggling": 12,    # HTML/SVG in-browser payload assembly (T1027.006)
        "client": 10,       # SVG script, JS decode gadgets, clipboard hijack
        "persistence": 10,  # Run keys, scheduled tasks (T1547/T1053)
        "evasion": 10,      # sandbox checks, sleep stalls (T1497)
        "filesystem": 5,    # dropping/staging files
    }
    # Dynamic-execution obfuscation items that warrant execution-grade scoring.
    _DYNAMIC_EXEC_NAMES = {
        "Eval/Execute/ExecuteGlobal": 15,
        "CallByName": 10,
    }
    credited: set = set()
    for finding in report["static"]["findings"]:
        cat = finding["category"]
        name = finding["name"]
        if name in credited:
            continue
        if cat in _CATEGORY_WEIGHT:
            credited.add(name)
            add(_CATEGORY_WEIGHT[cat], f"{cat.title()} capability: {name}")
        elif cat == "obfuscation" and name in _DYNAMIC_EXEC_NAMES:
            credited.add(name)
            add(_DYNAMIC_EXEC_NAMES[name], f"Dynamic execution: {name}")

    # Embedded PE / dropper (+25).
    if report["static"]["has_mz_embedded"]:
        add(25, "Embedded PE executable (self-contained dropper)")
    if report["rtf"].get("object_count"):
        for o in report["rtf"]["objects"]:
            if o.get("contains_pe"):
                add(25, f"RTF-embedded PE in object #{o['index']}")
                break

    # DDE (+20, treated like an auto-exec-grade code path).
    if report["static"]["has_dde"]:
        add(20, "DDE/DDEAUTO command execution field")

    # OneNote embedded payloads.
    one = report.get("onenote", {})
    if one.get("applicable") and one.get("payload_count"):
        if any(p.get("is_pe") for p in one.get("payloads", [])):
            add(25, "OneNote-embedded PE executable (double-click dropper)")
        else:
            add(20, f"OneNote embedded payload(s): {one['payload_count']}")

    # PDF dangerous actions.
    pdf = report.get("pdf", {})
    if pdf.get("applicable"):
        marker_names = {m["name"] for m in pdf.get("markers", [])}
        if pdf.get("has_openaction_js"):
            add(15, "PDF auto-action + embedded JavaScript")
        if "/Launch" in marker_names:
            add(20, "PDF /Launch action (runs external program)")
        if "/EmbeddedFile" in marker_names:
            add(10, "PDF embedded file")

    # XLL add-in (runs regardless of macro policy).
    xll = report.get("xll", {})
    if xll.get("applicable") and xll.get("is_xll"):
        reason = "Excel-DNA XLL add-in" if xll.get("exceldna") else "XLL add-in exports xlAutoOpen"
        add(25, f"Malicious Excel add-in: {reason}")

    # Obfuscation sub-score (already computed, bounded).
    obf_sub = report["obfuscation"].get("score", 0)
    if obf_sub:
        add(min(obf_sub, 30), f"Obfuscation indicators (sub-score {obf_sub})")

    # VBA stomping (+15 defense evasion).
    if report["vba"].get("vba_stomping_detected"):
        add(15, "VBA stomping (p-code/source mismatch, T1564.007)")

    # XLM dangerous calls (+15).
    if report["xlm"].get("dangerous_calls"):
        add(15, f"Excel 4.0 dangerous calls ({len(report['xlm']['dangerous_calls'])})")

    # Suspicious metadata (+5 each flag).
    for flag in report["metadata"].get("flags", []):
        add(5, f"Suspicious metadata: {flag[:60]}")

    # YARA matches (+10 each).
    for m in report["yara"].get("matches", []):
        add(10, f"YARA: {m['rule']}")

    score = min(score, 100)

    if score <= 20:
        classification = "Clean"
    elif score <= 40:
        classification = "Low"
    elif score <= 60:
        classification = "Medium"
    elif score <= 80:
        classification = "High"
    else:
        classification = "Critical"

    return {"score": score, "classification": classification, "breakdown": breakdown}


# ---------------------------------------------------------------------------
# "What to investigate next" generator
# ---------------------------------------------------------------------------
def build_next_steps(report: dict) -> List[str]:
    """Produce actionable analyst follow-ups based on what was found."""
    steps: List[str] = []
    s = report["static"]
    iocs = report["iocs"]

    if report["vba"].get("vba_stomping_detected"):
        steps.append(
            "VBA stomping detected: the readable source may be fake. Dump and "
            "disassemble the p-code (pcodedmp / olevba --show-pcode) - that is "
            "what Office actually runs."
        )
    if iocs["defanged"].get("urls") or iocs["defanged"].get("domains"):
        steps.append(
            "Pivot the extracted URLs/domains in VirusTotal, URLhaus and your "
            "passive DNS. Pull the staged payload in an isolated VM, not on a host."
        )
    if s["has_mz_embedded"]:
        steps.append(
            "Carve the embedded PE (foremost/binwalk or the dumped object), hash "
            "it, and submit the dropper separately to the sandbox and VT."
        )
    if any(fnd["category"] == "execution" and "PowerShell" in fnd["name"] for fnd in s["findings"]):
        steps.append(
            "Decode the PowerShell: base64 -d the -enc blob, then deobfuscate the "
            "download cradle to recover the second-stage URL."
        )
    if report["xlm"].get("has_xlm"):
        steps.append(
            "Excel 4.0 macros present: review the deobfuscated formula flow for "
            "EXEC/CALL/REGISTER and the final command line."
        )
    if report["static"]["has_dde"]:
        steps.append(
            "DDE field present: inspect word/document.xml (or the field codes) for "
            "the DDEAUTO command - this runs without macros being enabled."
        )
    if report["metadata"].get("template"):
        steps.append(
            "Remote template referenced: fetch the .dotm template in a VM; the real "
            "payload often lives there (Template Injection, T1221)."
        )
    if report.get("onenote", {}).get("applicable") and report["onenote"].get("payload_count"):
        steps.append(
            "OneNote embedded payload(s): carve them with onedump.py (Didier Stevens), "
            "hash each dropped file and analyse separately. Watch for ONENOTE.EXE "
            "spawning MSHTA/powershell/cmd in a sandbox."
        )
    if report.get("pdf", {}).get("applicable"):
        steps.append(
            "PDF: run pdfid/peepdf to expand compressed object streams and dump the "
            "JavaScript / Launch / URI actions this static pass may have under-counted."
        )
    if report.get("lnk", {}).get("applicable"):
        steps.append(
            "LNK: review the recovered command line and arguments; decode any base64, "
            "and check the icon/target path for the staging host."
        )
    if report.get("xll", {}).get("applicable") and report["xll"].get("is_xll"):
        steps.append(
            "XLL add-in: it runs on load regardless of macro policy. Disassemble the "
            "xlAutoOpen export (or the Excel-DNA managed assembly) for the payload."
        )
    if s["categories_hit"] and "smuggling" in s["categories_hit"]:
        steps.append(
            "HTML/SVG smuggling: deobfuscate the atob/Blob chain to recover the "
            "dropped filename and content; detonate in a browser sandbox to catch "
            "the auto-download or AiTM redirect."
        )
    if not steps:
        steps.append(
            "Low signal statically. If this was flagged upstream, detonate in a "
            "sandbox and diff process/network behaviour; consider p-code and "
            "stream-level inspection (oledump.py)."
        )
    steps.append(
        "Cross-reference the SHA256 against MalwareBazaar / your internal corpus "
        "before writing it up - you may already have the family and C2."
    )
    return steps


# ---------------------------------------------------------------------------
# Sandbox prep summary
# ---------------------------------------------------------------------------
def build_sandbox_prep(report: dict) -> str:
    """One-paste summary for ANY.RUN / Joe Sandbox / VirusTotal submissions."""
    f = report["file"]
    r = report["risk"]
    lines = [
        "=== vbascope sandbox submission summary ===",
        f"Filename : {f['name']}",
        f"Type     : {f['file_type']}",
        f"SHA256   : {f['hashes']['sha256']}",
        f"MD5      : {f['hashes']['md5']}",
        f"Size     : {f['hashes']['size']} bytes",
        f"Risk     : {r['score']}/100 ({r['classification']})",
        "",
        "Trigger notes:",
    ]
    if report["static"]["autoexec_triggers"]:
        lines.append("  - Enable macros; executes on: " +
                     ", ".join(report["static"]["autoexec_triggers"]))
    else:
        lines.append("  - No VBA auto-exec; may need manual interaction / DDE / XLM path.")
    if report["static"]["has_dde"]:
        lines.append("  - Contains DDE field: accept the 'update links' prompt to trigger.")
    if report["xlm"].get("has_xlm"):
        lines.append("  - Excel 4.0 macros: enable content, watch for EXEC/CALL.")
    lines.append("")
    lines.append("Watch for (expected behaviour):")
    cats = report["static"]["categories_hit"]
    if "download" in cats:
        lines.append("  - Outbound HTTP(S) to stage a second payload.")
    if "execution" in cats:
        lines.append("  - Child processes: powershell / cmd / wscript / mshta.")
    if "persistence" in cats:
        lines.append("  - Run-key writes / scheduled tasks.")
    urls = report["iocs"]["defanged"].get("urls", [])
    if urls:
        lines.append("")
        lines.append("Known IOCs (defanged):")
        for u in urls[:15]:
            lines.append(f"  - {u}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Password-protected handling
# ---------------------------------------------------------------------------
def try_decrypt(path: str) -> Tuple[Optional[str], Optional[str]]:
    """If the file is an encrypted OOXML/OLE, try common passwords.

    Uses msoffcrypto-tool if available (bundled with oletools deps on many
    systems). Returns (decrypted_temp_path, password) or (None, None).
    """
    try:
        import msoffcrypto  # type: ignore
    except Exception:
        return None, None

    try:
        with open(path, "rb") as fh:
            office_file = msoffcrypto.OfficeFile(fh)
            if not office_file.is_encrypted():
                return None, None
            for pw in COMMON_PASSWORDS:
                try:
                    with open(path, "rb") as fh2:
                        of = msoffcrypto.OfficeFile(fh2)
                        of.load_key(password=pw)
                        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".decrypted")
                        of.decrypt(tmp)
                        tmp.close()
                        return tmp.name, pw
                except Exception:
                    continue
    except Exception:
        return None, None
    return None, None


# ---------------------------------------------------------------------------
# Core single-file analysis
# ---------------------------------------------------------------------------
def analyze_file(
    path: str,
    output_dir: str,
    custom_yara: Optional[str] = None,
    dump_vba: bool = False,
    verbose: bool = False,
) -> dict:
    """Run the full pipeline against one file and return a report dict."""
    report: dict = {
        "tool": "vbascope",
        "version": __version__,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "errors": [],
    }

    # --- Read raw bytes once ---
    try:
        with open(path, "rb") as fh:
            raw_bytes = fh.read()
    except Exception as exc:
        report["errors"].append(f"could not read file: {exc}")
        raw_bytes = b""

    # --- Hashing + identification ---
    hashes = compute_hashes(path)
    identity: FileIdentity = identify_file(path)

    report["file"] = {
        "path": os.path.abspath(path),
        "name": os.path.basename(path),
        "extension": identity.extension,
        "file_type": identity.file_type.value,
        "ooxml_subtype": identity.ooxml_subtype,
        "libmagic_mime": identity.libmagic_mime,
        "libmagic_desc": identity.libmagic_desc,
        "hashes": hashes,
        "identification_notes": identity.notes,
    }

    # --- Password-protected? Try to decrypt into a temp file ---
    working_path = path
    decrypted_tmp = None
    if identity.file_type in (FileType.OLE2, FileType.OOXML):
        dec_path, pw = try_decrypt(path)
        if dec_path:
            decrypted_tmp = dec_path
            working_path = dec_path
            report["file"]["decrypted_with_password"] = pw
            report["errors"].append(f"file was encrypted; decrypted with '{pw}'")
            # Re-identify the decrypted content.
            identity = identify_file(working_path)
            try:
                with open(working_path, "rb") as fh:
                    raw_bytes = fh.read()
            except Exception:
                pass

    # --- Initialise result slots ---
    vba_result = VBAResult()
    xlm_result_dict = {"has_xlm": False, "formulas": [], "dangerous_calls": [], "timed_out": False, "errors": []}
    rtf_result_dict = {"object_count": 0, "objects": [], "errors": []}
    meta_dict = {"fields": {}, "template": None, "flags": [], "errors": []}
    onenote_dict = {"applicable": False}
    pdf_dict = {"applicable": False}
    lnk_dict = {"applicable": False}
    xll_dict = {"applicable": False}

    # --- Route by type ---
    # Treat script/markup content (HTA, VBS, WSF, SVG, HTML) as the "macro":
    # the whole file is the code to analyse.
    is_script = (
        identity.file_type in (FileType.SCRIPT, FileType.HTA, FileType.HTML, FileType.SVG)
        or identity.extension in SCRIPT_EXTS
    )
    script_source = ""
    # Bytes recovered by decoding embedded objects (RTF \objdata hex, OneNote
    # FileDataStoreObject payloads). The real payload is encoded/embedded in the
    # carrier, so string/IOC scanning must run over the DECODED content.
    decoded_object_bytes = b""
    # Extra plain text to fold into the string/IOC corpus (LNK command line,
    # PDF URIs, etc.).
    supplemental_text = ""

    try:
        if is_script:
            # Treat the whole file content as the "macro".
            script_source = raw_bytes.decode("latin-1", "ignore")
            type_label = {
                FileType.SVG: "SVG",
                FileType.HTML: "HTML",
                FileType.HTA: "HTA",
            }.get(identity.file_type, "Script")
            vba_result.has_vba = True
            vba_result.extraction_method = "content-passthrough"
            vba_result.modules.append(
                VBAModule(
                    filename=report["file"]["name"],
                    stream_path=report["file"]["name"],
                    module_name=report["file"]["name"],
                    module_type=type_label,
                    source_code=script_source,
                    code_len=len(script_source),
                )
            )
            vba_result.combined_source = script_source

        elif identity.file_type == FileType.ONENOTE:
            one_res = extract_onenote(working_path, raw_bytes=raw_bytes)
            onenote_dict = {
                "applicable": True,
                "payload_count": one_res.payload_count,
                "payloads": [
                    {
                        "index": p.index, "offset": p.offset, "size": p.size,
                        "sniffed_type": p.sniffed_type, "is_pe": p.is_pe, "notes": p.notes,
                    }
                    for p in one_res.payloads
                ],
                "errors": one_res.errors,
            }
            # Fold every carved payload into the analysis corpus + binary buffer.
            decoded_object_bytes = b"".join(p.data for p in one_res.payloads)

        elif identity.file_type == FileType.PDF:
            pdf_res = scan_pdf(working_path, raw_bytes=raw_bytes)
            pdf_dict = {
                "applicable": True,
                "object_count": pdf_res.object_count,
                "has_openaction_js": pdf_res.has_openaction_js,
                "markers": [
                    {"name": n, "severity": s, "mitre": m, "count": c}
                    for (n, s, m, c) in pdf_res.markers
                ],
                "uris": pdf_res.uris,
                "errors": pdf_res.errors,
            }
            supplemental_text += "\n" + "\n".join(pdf_res.uris)

        elif identity.file_type == FileType.LNK:
            lnk_res = extract_lnk(working_path, raw_bytes=raw_bytes)
            lnk_dict = {
                "applicable": True,
                "arguments": lnk_res.arguments,
                "relative_path": lnk_res.relative_path,
                "working_dir": lnk_res.working_dir,
                "icon_location": lnk_res.icon_location,
                "command_text": lnk_res.command_text,
                "errors": lnk_res.errors,
            }
            # The command line is where the payload hides - scan it as text, and
            # also scan the UTF-16LE decode of the whole file for inline commands.
            supplemental_text += "\n" + lnk_res.command_text + "\n" + raw_bytes.decode("utf-16-le", "ignore")

        elif identity.file_type == FileType.XLL:
            xll_res = check_xll(working_path, raw_bytes=raw_bytes)
            xll_dict = {
                "applicable": True,
                "is_xll": xll_res.is_xll,
                "has_xlautoopen": xll_res.has_xlautoopen,
                "exceldna": xll_res.exceldna,
                "exports": xll_res.exports[:50],
                "errors": xll_res.errors,
            }

        elif identity.file_type == FileType.RTF:
            rtf_res = extract_rtf_objects(working_path)
            rtf_result_dict = {
                "object_count": rtf_res.object_count,
                "objects": [
                    {
                        "index": o.index,
                        "class_name": o.class_name,
                        "size": o.size,
                        "is_ole_package": o.is_ole_package,
                        "embedded_filename": o.embedded_filename,
                        "embedded_srcpath": o.embedded_srcpath,
                        "contains_pe": o.contains_pe,
                        "contains_ole2": o.contains_ole2,
                        "notes": o.notes,
                    }
                    for o in rtf_res.objects
                ],
                "errors": rtf_res.errors,
            }
            # Feed every decoded object's bytes into the analysis corpus so
            # string/IOC signatures see the de-hex'd payload, not raw \objdata.
            decoded_object_bytes = b"".join(o.raw for o in rtf_res.objects)

            # Recurse into any embedded OLE2 blob to pull VBA.
            for blob in rtf_res.embedded_ole2_blobs:
                sub = _extract_with_olevba(working_path, data=blob)
                if sub.has_vba:
                    vba_result.has_vba = True
                    vba_result.modules.extend(sub.modules)
                    vba_result.combined_source += "\n" + sub.combined_source
                    if sub.vba_stomping_detected:
                        vba_result.vba_stomping_detected = True
                    vba_result.extraction_method = "rtfobj+olevba"

        else:
            # OLE2 / OOXML documents.
            vba_result = extract_vba(working_path, is_ooxml=identity.is_ooxml)

            # XLM only relevant for Excel.
            is_excel = (
                identity.ooxml_subtype == "excel"
                or identity.extension in {".xls", ".xlsm", ".xlsb", ".xla", ".xlam"}
                or (identity.is_ole2 and identity.extension in {".xls"})
            )
            if is_excel:
                xlm_res = extract_xlm(working_path, timeout=60)
                xlm_result_dict = {
                    "has_xlm": xlm_res.has_xlm,
                    "formulas": xlm_res.formulas,
                    "dangerous_calls": xlm_res.dangerous_calls,
                    "timed_out": xlm_res.timed_out,
                    "errors": xlm_res.errors,
                }

            # Metadata.
            meta_res = extract_metadata(working_path, identity.is_ooxml, identity.is_ole2)
            meta_dict = {
                "fields": meta_res.fields,
                "template": meta_res.template,
                "flags": meta_res.flags,
                "errors": meta_res.errors,
            }
    except Exception as exc:
        report["errors"].append(f"extraction stage failed: {exc}")
        if verbose:
            report["errors"].append(traceback.format_exc())

    # --- Serialise VBA result ---
    report["vba"] = {
        "has_vba": vba_result.has_vba,
        "module_count": vba_result.module_count,
        "vba_stomping_detected": vba_result.vba_stomping_detected,
        "extraction_method": vba_result.extraction_method or "none",
        "modules": [
            {
                "module_name": m.module_name,
                "module_type": m.module_type,
                "stream_path": m.stream_path,
                "code_len": m.code_len,
                "is_stomped": m.is_stomped,
                "notes": m.notes,
                "source_code": m.source_code,
            }
            for m in vba_result.modules
        ],
        "errors": vba_result.errors,
    }
    report["xlm"] = xlm_result_dict
    report["rtf"] = rtf_result_dict
    report["metadata"] = meta_dict
    report["onenote"] = onenote_dict
    report["pdf"] = pdf_dict
    report["lnk"] = lnk_dict
    report["xll"] = xll_dict

    # --- Combined source for analysis ---
    combined_vba = vba_result.combined_source or ""
    if xlm_result_dict["formulas"]:
        combined_vba += "\n' ===== XLM formulas =====\n" + "\n".join(xlm_result_dict["formulas"])

    # --- Build the text corpus for string signatures + IOCs ---
    # For OOXML the payload is zip-compressed, so decompress text parts; for
    # everything else a lenient decode of the raw bytes is the right corpus.
    if identity.is_ooxml:
        text_corpus = _ooxml_text_corpus(working_path)
    else:
        text_corpus = raw_bytes.decode("latin-1", "ignore")
    # Append any decoded embedded-object bytes (RTF \objdata, OneNote payloads).
    if decoded_object_bytes:
        text_corpus += "\n" + decoded_object_bytes.decode("latin-1", "ignore")
    # Append supplemental text (LNK command line, PDF URIs, UTF-16 decodes).
    if supplemental_text:
        text_corpus += "\n" + supplemental_text
    # Fold one base64-decode layer back in so smuggled URLs/commands and
    # PowerShell -enc payloads become visible to the IOC and signature engines.
    decoded_b64 = _decode_base64_layer(text_corpus + "\n" + combined_vba)
    if decoded_b64:
        text_corpus += "\n' ===== base64-decoded layer =====\n" + decoded_b64

    # --- Static analysis ---
    # Include decoded object bytes in the binary buffer too, so an MZ/PE hidden
    # inside a hex-encoded RTF object is caught by the generic embedded-PE scan.
    binary_buffer = raw_bytes + (b"\n" + decoded_object_bytes if decoded_object_bytes else b"")
    static_res = analyze_static(combined_vba, binary_buffer, text_for_strings=text_corpus)
    report["static"] = {
        "findings": [
            {
                "category": fnd.category,
                "name": fnd.name,
                "severity": fnd.severity,
                "mitre": fnd.mitre,
                "description": fnd.description,
                "count": fnd.count,
                "examples": fnd.examples,
            }
            for fnd in static_res.findings
        ],
        "autoexec_triggers": static_res.autoexec_triggers,
        "has_mz_embedded": static_res.has_mz_embedded,
        "has_dde": static_res.has_dde,
        "categories_hit": static_res.categories_hit,
    }

    # --- Obfuscation ---
    module_tuples = [(m.module_name, m.source_code) for m in vba_result.modules]
    obf_res = analyze_obfuscation(module_tuples, text_corpus)
    report["obfuscation"] = {
        "chr_count": obf_res.chr_count,
        "chr_heavy_modules": obf_res.chr_heavy_modules,
        "max_concat_chain": obf_res.max_concat_chain,
        "concat_chain_count": obf_res.concat_chain_count,
        "base64_blobs": obf_res.base64_blobs,
        "base64_decoded_pe": obf_res.base64_decoded_pe,
        "high_entropy_identifiers": obf_res.high_entropy_identifiers,
        "sample_gibberish": obf_res.sample_gibberish,
        "score": obf_res.score,
        "indicators": obf_res.indicators,
    }

    # --- IOCs ---
    ioc_res = extract_iocs([combined_vba, text_corpus, supplemental_text])
    report["iocs"] = {
        "urls": ioc_res.urls,
        "domains": ioc_res.domains,
        "ips": ioc_res.ips,
        "emails": ioc_res.emails,
        "win_paths": ioc_res.win_paths,
        "unc_paths": ioc_res.unc_paths,
        "registry_keys": ioc_res.registry_keys,
        "defanged": ioc_res.defanged,
        "total": ioc_res.total,
    }

    # --- YARA ---
    yara_res = scan_yara(working_path, combined_vba, custom_rules=custom_yara)
    report["yara"] = {
        "available": yara_res.available,
        "match_count": yara_res.match_count,
        "rules_loaded": yara_res.rules_loaded,
        "matches": [
            {
                "rule": m.rule,
                "namespace": m.namespace,
                "tags": m.tags,
                "meta": m.meta,
                "description": m.description,
                "source": m.source,
                "strings": [
                    {"identifier": s.identifier, "offset": s.offset, "data": s.data}
                    for s in m.strings
                ],
            }
            for m in yara_res.matches
        ],
        "errors": yara_res.errors,
    }

    # --- Risk + next steps ---
    report["risk"] = score_risk(report)
    report["next_steps"] = build_next_steps(report)

    # --- Dump VBA modules if requested ---
    if dump_vba and vba_result.modules:
        _dump_vba_modules(report, vba_result, output_dir)

    # --- Cleanup temp decrypted file ---
    if decrypted_tmp:
        try:
            os.unlink(decrypted_tmp)
        except Exception:
            pass

    return report


def _decode_base64_layer(text: str, max_blobs: int = 200) -> str:
    """Decode base64 blobs in ``text`` and return the printable decodings.

    Smuggling payloads and PowerShell -enc hide the real URL/command inside
    base64 (and sometimes base64 of UTF-16LE). Folding one decode layer back
    into the corpus lets the IOC/signature engines see through it. Bounded so a
    pathological file can't blow up runtime.
    """
    import base64 as _b64
    import re as _re

    out: List[str] = []
    seen = 0
    for m in _re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        if seen >= max_blobs:
            break
        blob = m.group(0)
        # base64 length must be a multiple of 4 to decode cleanly; trim.
        trimmed = blob[: (len(blob) // 4) * 4]
        if len(trimmed) < 16:
            continue
        seen += 1
        try:
            raw = _b64.b64decode(trimmed, validate=False)
        except Exception:
            continue
        # Keep ASCII decode if mostly printable.
        printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
        if raw and printable / len(raw) > 0.75:
            out.append(raw.decode("latin-1", "ignore"))
        # Also try UTF-16LE (PowerShell -enc uses it).
        try:
            u16 = raw.decode("utf-16-le")
            if u16 and sum(1 for c in u16 if c.isprintable() or c in "\t\r\n") / len(u16) > 0.8:
                out.append(u16)
        except Exception:
            pass
    return "\n".join(out)


def _ooxml_text_corpus(path: str) -> str:
    """Decompress OOXML text parts into one string for signature/IOC scanning.

    OOXML is a zip, so the human-readable payload is compressed. We pull every
    text-like member (XML, rels, VML) and concatenate it. Non-text members
    (media, vbaProject.bin) are skipped; VBA is handled by the VBA engine.
    """
    chunks: List[str] = []
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                low = name.lower()
                if low.endswith(_OOXML_TEXT_EXTS):
                    try:
                        data = zf.read(name)
                        # Note the member name too so part paths are searchable.
                        chunks.append(f"\n<!-- {name} -->\n")
                        chunks.append(data.decode("utf-8", "ignore"))
                    except Exception:
                        continue
    except Exception:
        return ""
    return "".join(chunks)


def _dump_vba_modules(report: dict, vba_result: VBAResult, output_dir: str) -> None:
    """Write each VBA module and a combined dump to <output_dir>/<sha>_vba/."""
    sha = report["file"]["hashes"]["sha256"][:16]
    dump_dir = os.path.join(output_dir, f"{sha}_vba")
    os.makedirs(dump_dir, exist_ok=True)
    written: List[str] = []
    for i, m in enumerate(vba_result.modules):
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in m.module_name) or f"module_{i}"
        fpath = os.path.join(dump_dir, f"{i:02d}_{safe_name}.vba")
        try:
            with open(fpath, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(m.source_code)
            written.append(fpath)
        except Exception:
            pass
    combined = os.path.join(dump_dir, "_combined.vba")
    try:
        with open(combined, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(vba_result.combined_source)
        written.append(combined)
    except Exception:
        pass
    report["vba"]["dumped_to"] = dump_dir
    report["vba"]["dumped_files"] = written


# ---------------------------------------------------------------------------
# Batch / archive handling
# ---------------------------------------------------------------------------
def _iter_input_files(target: str) -> List[str]:
    """Expand a file or directory into a list of files to analyse."""
    if os.path.isfile(target):
        return [target]
    if os.path.isdir(target):
        files = []
        for root, _, names in os.walk(target):
            for n in names:
                files.append(os.path.join(root, n))
        return sorted(files)
    return []


def _maybe_expand_archive(path: str, verbose: bool) -> List[Tuple[str, Optional[str]]]:
    """If path is a zip archive of documents, extract to temp and return members.

    Returns list of (extracted_path, label). For non-archives returns
    [(path, None)].
    """
    ext = ("." + path.rsplit(".", 1)[-1].lower()) if "." in path else ""
    if ext not in ARCHIVE_EXTS:
        return [(path, None)]
    if ext != ".zip":
        # rar/7z need external tooling; note and skip transparently.
        return [(path, None)]

    members: List[Tuple[str, Optional[str]]] = []
    try:
        tmpdir = tempfile.mkdtemp(prefix="vbascope_zip_")
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                # Zip-slip guard: never let a member escape tmpdir.
                dest = os.path.realpath(os.path.join(tmpdir, info.filename))
                if not dest.startswith(os.path.realpath(tmpdir) + os.sep):
                    continue
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                try:
                    with zf.open(info) as src, open(dest, "wb") as out:
                        out.write(src.read())
                    members.append((dest, f"{os.path.basename(path)}::{info.filename}"))
                except Exception:
                    continue
    except Exception:
        return [(path, None)]
    return members or [(path, None)]


# ---------------------------------------------------------------------------
# Output orchestration
# ---------------------------------------------------------------------------
def _emit_reports(
    report: dict,
    output_dir: str,
    want_json: bool,
    want_html: bool,
    use_color: bool,
    quiet: bool,
    sandbox_prep: bool,
    csv_path: Optional[str] = None,
) -> None:
    """Render terminal output and write JSON/HTML/CSV as requested."""
    render_terminal(report, use_color=use_color, quiet=quiet)

    sha = report["file"]["hashes"]["sha256"][:16]
    base = os.path.join(output_dir, f"{sha}_{report['file']['name']}")

    if want_json:
        jpath = write_json(report, base + ".json")
        print(f"[+] JSON report: {jpath}", file=sys.stderr)
    if want_html:
        hpath = write_html(report, base + ".html")
        print(f"[+] HTML report: {hpath}", file=sys.stderr)
    if csv_path:
        try:
            append_csv(report, csv_path)
        except Exception as exc:
            print(f"[!] CSV append failed: {exc}", file=sys.stderr)

    if sandbox_prep:
        summary = build_sandbox_prep(report)
        print("\n" + summary)
        spath = base + ".sandbox.txt"
        try:
            with open(spath, "w", encoding="utf-8") as fh:
                fh.write(summary)
            print(f"\n[+] Sandbox summary: {spath}", file=sys.stderr)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vbascope",
        description="Malicious document static analysis engine (VBA/XLM extraction + IOC hunting).",
        epilog="Static analysis only - vbascope never executes the sample.",
    )
    parser.add_argument("--version", action="version", version=f"vbascope {__version__}")
    parser.add_argument("--setup", action="store_true",
                        help="check/install dependencies and exit")

    sub = parser.add_subparsers(dest="command")
    an = sub.add_parser("analyze", help="analyze a file or directory")
    an.add_argument("target", help="file or directory to analyze")
    an.add_argument("--output-dir", default="./vbascope_output/",
                    help="output directory (default: ./vbascope_output/)")
    an.add_argument("--json", action="store_true", help="write JSON report")
    an.add_argument("--html", action="store_true", help="write HTML report")
    an.add_argument("--csv", action="store_true",
                    help="write a one-row-per-file CSV (batch triage)")
    an.add_argument("--yara", metavar="RULES_PATH", default=None,
                    help="custom YARA rules file or directory (layered on defaults)")
    an.add_argument("--dump-vba", action="store_true",
                    help="save extracted VBA modules to files")
    an.add_argument("--verbose", action="store_true", help="debug-level logging")
    an.add_argument("--quiet", action="store_true",
                    help="only risk score and critical/high findings")
    an.add_argument("--no-color", action="store_true", help="disable terminal colors")
    an.add_argument("--sandbox-prep", action="store_true",
                    help="emit a sandbox/VT submission summary")
    an.add_argument("--setup", action="store_true",
                    help="check/install dependencies before analyzing")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # --- Top-level --setup (no subcommand) ---
    if getattr(args, "setup", False) and not args.command:
        report = ensure_dependencies(install=True, verbose=getattr(args, "verbose", False))
        print_dependency_report(report)
        return 0

    if args.command != "analyze":
        parser.print_help()
        return 1

    # --- Per-analyze --setup ---
    if args.setup:
        dep_report = ensure_dependencies(install=True, verbose=args.verbose)
        print_dependency_report(dep_report)

    # Warn about missing system tools (non-blocking).
    tools = check_system_tools()
    for tool, present in tools.items():
        if not present:
            print(f"[!] system tool '{tool}' not found in PATH - some checks degraded.",
                  file=sys.stderr)

    if not os.path.exists(args.target):
        print(f"[x] target not found: {args.target}", file=sys.stderr)
        return 2

    os.makedirs(args.output_dir, exist_ok=True)

    inputs = _iter_input_files(args.target)
    if not inputs:
        print(f"[x] no files to analyze under: {args.target}", file=sys.stderr)
        return 2

    use_color = not args.no_color
    exit_code = 0
    analyzed = 0
    # One CSV for the whole batch (append mode). Fresh file per run.
    csv_path = os.path.join(args.output_dir, "vbascope_batch.csv") if args.csv else None
    if csv_path and os.path.isfile(csv_path):
        try:
            os.unlink(csv_path)
        except Exception:
            pass

    for path in inputs:
        for real_path, label in _maybe_expand_archive(path, args.verbose):
            try:
                report = analyze_file(
                    real_path,
                    output_dir=args.output_dir,
                    custom_yara=args.yara,
                    dump_vba=args.dump_vba,
                    verbose=args.verbose,
                )
                if label:
                    report["file"]["archive_member"] = label
                _emit_reports(
                    report,
                    output_dir=args.output_dir,
                    want_json=args.json,
                    want_html=args.html,
                    use_color=use_color,
                    quiet=args.quiet,
                    sandbox_prep=args.sandbox_prep,
                    csv_path=csv_path,
                )
                analyzed += 1
                if report["risk"]["score"] >= 61:
                    exit_code = 3   # non-zero: high/critical found (CI-friendly)
            except Exception as exc:
                print(f"[x] failed to analyze {real_path}: {exc}", file=sys.stderr)
                if args.verbose:
                    traceback.print_exc()

    print(f"\n[=] vbascope analyzed {analyzed} file(s). Output in {args.output_dir}",
          file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
