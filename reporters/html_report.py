"""
Self-contained HTML report writer.

Produces a single .html file with inline CSS and no external dependencies, so
it can be attached to a ticket or shared offline. Includes an executive
summary, collapsible technical sections, light VBA syntax highlighting and a
copy-friendly defanged IOC block.

Everything from the sample is treated as untrusted and HTML-escaped before it
reaches the DOM - the report must never execute the malware's strings.
"""

from __future__ import annotations

import html
from datetime import datetime
from typing import Dict, List

_RISK_HEX = {
    "Clean": "#2e7d32",
    "Low": "#0097a7",
    "Medium": "#f9a825",
    "High": "#ef6c00",
    "Critical": "#c62828",
}
_SEV_HEX = {
    "critical": "#c62828",
    "high": "#ef6c00",
    "medium": "#f9a825",
    "low": "#0097a7",
    "info": "#607d8b",
}

# VBA keywords for a tiny, dependency-free highlighter.
_VBA_KEYWORDS = (
    "Sub", "Function", "End", "Dim", "Set", "If", "Then", "Else", "ElseIf",
    "For", "Next", "Do", "While", "Loop", "Wend", "Call", "CreateObject",
    "Shell", "Private", "Public", "Const", "As", "New", "With", "Select",
    "Case", "Exit", "On", "Error", "Resume", "GoTo", "ByVal", "ByRef",
    "Declare", "Lib", "Attribute", "Environ", "Chr", "ChrW", "StrReverse",
)


def _esc(value) -> str:
    return html.escape(str(value), quote=True)


def _highlight_vba(code: str) -> str:
    """Very small VBA highlighter: keywords, strings and comments -> spans."""
    import re

    escaped = _esc(code)
    # Comments (lines starting with ' after escaping).
    escaped = re.sub(
        r"(^|\n)(\s*&#x27;[^\n]*)",
        lambda m: f"{m.group(1)}<span class='c'>{m.group(2)}</span>",
        escaped,
    )
    # Double-quoted strings (escaped quotes are &quot;).
    escaped = re.sub(
        r"(&quot;.*?&quot;)",
        r"<span class='s'>\1</span>",
        escaped,
    )
    # Keywords.
    kw = r"\b(" + "|".join(_VBA_KEYWORDS) + r")\b"
    escaped = re.sub(kw, r"<span class='k'>\1</span>", escaped)
    return escaped


def _section(title: str, body: str, open_default: bool = False) -> str:
    attr = " open" if open_default else ""
    return (
        f"<details class='sec'{attr}><summary>{_esc(title)}</summary>"
        f"<div class='secbody'>{body}</div></details>"
    )


def _kv_table(pairs: List) -> str:
    rows = "".join(
        f"<tr><td class='k'>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in pairs
    )
    return f"<table class='kv'>{rows}</table>"


def _build_findings_table(findings: List[Dict]) -> str:
    if not findings:
        return "<p class='muted'>No suspicious indicators matched.</p>"
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    rows = []
    for x in sorted(findings, key=lambda k: (-order.get(k["severity"], 0), -k["count"])):
        color = _SEV_HEX.get(x["severity"], "#607d8b")
        examples = "<br>".join(_esc(e) for e in x.get("examples", []))
        rows.append(
            f"<tr>"
            f"<td><span class='pill' style='background:{color}'>{_esc(x['severity'].upper())}</span></td>"
            f"<td>{_esc(x['name'])}</td>"
            f"<td>{_esc(x['category'])}</td>"
            f"<td class='num'>{x['count']}</td>"
            f"<td><code>{_esc(x['mitre'])}</code></td>"
            f"<td class='desc'>{_esc(x['description'])}<div class='ex'>{examples}</div></td>"
            f"</tr>"
        )
    return (
        "<table class='findings'><thead><tr>"
        "<th>Severity</th><th>Indicator</th><th>Category</th><th>Count</th>"
        "<th>MITRE</th><th>Why it matters</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _build_ioc_block(iocs: Dict) -> str:
    def _list(label, items):
        if not items:
            return ""
        lis = "".join(f"<li>{_esc(i)}</li>" for i in items)
        return f"<h4>{_esc(label)} ({len(items)})</h4><ul class='ioc'>{lis}</ul>"

    defanged = iocs.get("defanged", {})
    blocks = [
        _list("URLs", defanged.get("urls", [])),
        _list("Domains", defanged.get("domains", [])),
        _list("IPs", defanged.get("ips", [])),
        _list("Emails", defanged.get("emails", [])),
        _list("Windows paths", iocs.get("win_paths", [])),
        _list("UNC paths", iocs.get("unc_paths", [])),
        _list("Registry keys", iocs.get("registry_keys", [])),
    ]
    body = "".join(b for b in blocks if b)
    if not body:
        return "<p class='muted'>No IOCs extracted.</p>"
    # Copy-friendly combined block.
    all_defanged = (
        defanged.get("urls", []) + defanged.get("domains", []) +
        defanged.get("ips", []) + defanged.get("emails", [])
    )
    combined = "\n".join(all_defanged)
    return body + (
        f"<h4>Copy-friendly (defanged)</h4>"
        f"<textarea class='copybox' readonly rows='{min(12, max(3, len(all_defanged)+1))}'>"
        f"{_esc(combined)}</textarea>"
    )


def _build_vba_block(modules: List[Dict]) -> str:
    if not modules:
        return "<p class='muted'>No VBA modules.</p>"
    out = []
    for mod in modules:
        stomp = " <span class='pill' style='background:#c62828'>STOMPED</span>" if mod.get("is_stomped") else ""
        code = mod.get("source_code", "") or "' (empty - see stomping note)"
        out.append(
            f"<details class='mod'><summary>{_esc(mod['module_name'])} "
            f"<span class='muted'>[{_esc(mod['module_type'])}] {mod.get('code_len',0)}B</span>{stomp}</summary>"
            f"<pre class='code'>{_highlight_vba(code)}</pre></details>"
        )
    return "".join(out)


def write_html(report: dict, out_path: str) -> str:
    """Render the report to a standalone HTML file.

    Args:
        report: Analysis report dict.
        out_path: Destination path.

    Returns:
        The path written.
    """
    f = report["file"]
    r = report["risk"]
    risk_color = _RISK_HEX.get(r["classification"], "#607d8b")

    # Executive summary bullets.
    summary_points = []
    if report["vba"]["has_vba"]:
        summary_points.append(f"{report['vba']['module_count']} VBA module(s) extracted")
    if report["vba"]["vba_stomping_detected"]:
        summary_points.append("VBA stomping detected (T1564.007)")
    if report["static"]["autoexec_triggers"]:
        summary_points.append("Auto-execution: " + ", ".join(report["static"]["autoexec_triggers"]))
    if report["static"]["has_mz_embedded"]:
        summary_points.append("Embedded PE executable")
    if report["static"]["has_dde"]:
        summary_points.append("DDE/DDEAUTO command execution field")
    if report["xlm"]["has_xlm"]:
        summary_points.append(f"{len(report['xlm']['formulas'])} Excel 4.0 (XLM) formula(s)")
    if report["yara"].get("match_count"):
        summary_points.append(f"{report['yara']['match_count']} YARA match(es)")
    if report["iocs"]["total"]:
        summary_points.append(f"{report['iocs']['total']} IOC(s)")
    if not summary_points:
        summary_points.append("No high-signal indicators found.")

    summary_html = "".join(f"<li>{_esc(p)}</li>" for p in summary_points)

    # Risk breakdown table.
    breakdown = report["risk"].get("breakdown", [])
    bd_rows = "".join(
        f"<tr><td>{_esc(b['reason'])}</td><td class='num'>+{b['points']}</td></tr>"
        for b in breakdown
    )
    bd_table = f"<table class='kv'><thead><tr><th>Reason</th><th>Points</th></tr></thead><tbody>{bd_rows}</tbody></table>" if bd_rows else ""

    # File info.
    fileinfo = _kv_table([
        ("File", f["name"]),
        ("Type", f["file_type"] + (f" / {f['ooxml_subtype']}" if f.get("ooxml_subtype") else "")),
        ("MIME (libmagic)", f.get("libmagic_mime") or "n/a"),
        ("libmagic", f.get("libmagic_desc") or "n/a"),
        ("Size", f"{f['hashes']['size']} bytes"),
        ("Magic bytes", f["hashes"]["magic_bytes"]),
        ("MD5", f["hashes"]["md5"]),
        ("SHA1", f["hashes"]["sha1"]),
        ("SHA256", f["hashes"]["sha256"]),
    ])

    # Metadata.
    meta = report["metadata"]
    meta_pairs = [(k, v) for k, v in meta.get("fields", {}).items()]
    meta_table = _kv_table(meta_pairs) if meta_pairs else "<p class='muted'>No metadata.</p>"
    meta_flags = ""
    if meta.get("flags"):
        meta_flags = "<ul class='flags'>" + "".join(f"<li>{_esc(x)}</li>" for x in meta["flags"]) + "</ul>"

    # YARA.
    yr = report["yara"]
    if yr.get("match_count"):
        yrows = []
        for m in yr["matches"]:
            strs = "<br>".join(
                f"<code>{_esc(s['identifier'])}</code> @ {s['offset']}: {_esc(s['data'])}"
                for s in m.get("strings", [])[:6]
            )
            yrows.append(
                f"<tr><td>{_esc(m['rule'])}</td><td>{_esc(m['source'])}</td>"
                f"<td>{_esc(m.get('description',''))}</td><td class='desc'>{strs}</td></tr>"
            )
        yara_html = (
            "<table class='findings'><thead><tr><th>Rule</th><th>Source</th>"
            "<th>Description</th><th>Matched strings</th></tr></thead>"
            f"<tbody>{''.join(yrows)}</tbody></table>"
        )
    elif not yr.get("available"):
        yara_html = "<p class='muted'>yara-python not installed.</p>"
    else:
        yara_html = "<p class='muted'>No YARA matches.</p>"

    # XLM.
    xlm = report["xlm"]
    if xlm["has_xlm"]:
        formulas = "".join(f"<li><code>{_esc(x)}</code></li>" for x in xlm["formulas"][:200])
        xlm_html = f"<p>{len(xlm['formulas'])} formula(s); {len(xlm['dangerous_calls'])} flagged.</p><ul class='ioc'>{formulas}</ul>"
    elif xlm.get("timed_out"):
        xlm_html = "<p class='muted'>XLM deobfuscation timed out (possible anti-analysis stall).</p>"
    else:
        xlm_html = "<p class='muted'>No Excel 4.0 macros.</p>"

    # RTF objects.
    rtf = report["rtf"]
    if rtf.get("object_count"):
        rrows = []
        for o in rtf["objects"]:
            notes = "<br>".join(_esc(n) for n in o.get("notes", []))
            rrows.append(
                f"<tr><td>{o['index']}</td><td>{_esc(o.get('class_name') or 'n/a')}</td>"
                f"<td class='num'>{o['size']}</td><td class='desc'>{notes}</td></tr>"
            )
        rtf_html = (
            "<table class='findings'><thead><tr><th>#</th><th>OLE class</th>"
            "<th>Size</th><th>Notes</th></tr></thead>"
            f"<tbody>{''.join(rrows)}</tbody></table>"
        )
    else:
        rtf_html = "<p class='muted'>No embedded RTF objects.</p>"

    # Modern-format sections.
    def _fmt_section() -> str:
        parts = []
        one = report.get("onenote", {})
        if one.get("applicable") and one.get("payload_count"):
            rows = "".join(
                f"<tr><td>{p['index']}</td><td>{_esc(p['sniffed_type'])}</td>"
                f"<td class='num'>{p['size']}</td><td>{'PE' if p.get('is_pe') else ''}</td></tr>"
                for p in one.get("payloads", [])
            )
            parts.append(
                f"<h4>OneNote embedded payloads ({one['payload_count']})</h4>"
                "<table class='findings'><thead><tr><th>#</th><th>Type</th><th>Size</th>"
                f"<th>PE</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        pdf = report.get("pdf", {})
        if pdf.get("applicable") and pdf.get("markers"):
            rows = "".join(
                f"<tr><td><code>{_esc(m['name'])}</code></td>"
                f"<td><span class='pill' style='background:{_SEV_HEX.get(m['severity'],'#607d8b')}'>"
                f"{_esc(m['severity'].upper())}</span></td><td class='num'>{m['count']}</td>"
                f"<td><code>{_esc(m['mitre'])}</code></td></tr>"
                for m in pdf["markers"]
            )
            parts.append(
                f"<h4>PDF structure ({pdf.get('object_count',0)} objects)</h4>"
                "<table class='findings'><thead><tr><th>Marker</th><th>Severity</th>"
                f"<th>Count</th><th>MITRE</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        lnk = report.get("lnk", {})
        if lnk.get("applicable"):
            parts.append(
                "<h4>LNK shortcut</h4>" + _kv_table([
                    ("Target", lnk.get("relative_path") or ""),
                    ("Arguments", lnk.get("arguments") or ""),
                    ("Working dir", lnk.get("working_dir") or ""),
                    ("Icon", lnk.get("icon_location") or ""),
                ])
            )
        xll = report.get("xll", {})
        if xll.get("applicable"):
            verdict = "MALICIOUS XLL add-in" if xll.get("is_xll") else "PE/XLL (no auto-exec export found)"
            how = "Excel-DNA framework" if xll.get("exceldna") else ("exports xlAutoOpen" if xll.get("has_xlautoopen") else "")
            parts.append(f"<h4>XLL add-in</h4><p><b>{_esc(verdict)}</b> {_esc(how)}</p>")
        return "".join(parts) if parts else "<p class='muted'>No modern-format artefacts.</p>"

    fmt_html = _fmt_section()

    # Next steps.
    steps = report.get("next_steps", [])
    steps_html = "<ul>" + "".join(f"<li>{_esc(s)}</li>" for s in steps) + "</ul>" if steps else ""

    # Obfuscation.
    obf = report["obfuscation"]
    obf_html = ""
    if obf.get("indicators"):
        obf_html = "<ul class='flags'>" + "".join(f"<li>{_esc(i)}</li>" for i in obf["indicators"]) + "</ul>"
    else:
        obf_html = "<p class='muted'>No significant obfuscation.</p>"

    generated = report.get("analyzed_at") or datetime.utcnow().isoformat()

    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vbascope report - {_esc(f['name'])}</title>
<style>
:root {{ color-scheme: light dark; }}
* {{ box-sizing: border-box; }}
body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  margin: 0; background: #f4f5f7; color: #1a1a1a; line-height: 1.5; }}
.wrap {{ max-width: 1000px; margin: 0 auto; padding: 24px 16px 64px; }}
header.top {{ display: flex; flex-wrap: wrap; align-items: center; gap: 16px;
  background: #fff; border-radius: 12px; padding: 20px 24px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
h1 {{ font-size: 20px; margin: 0; }}
h2 {{ font-size: 16px; border-bottom: 2px solid #e0e0e0; padding-bottom: 6px; margin-top: 0; }}
h4 {{ margin: 14px 0 4px; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: #555; }}
.risk {{ margin-left: auto; text-align: center; min-width: 150px; }}
.score {{ font-size: 40px; font-weight: 800; line-height: 1; color: {risk_color}; }}
.badge {{ display: inline-block; padding: 4px 14px; border-radius: 999px; color: #fff;
  font-weight: 700; font-size: 13px; background: {risk_color}; margin-top: 6px; }}
.bar {{ height: 10px; border-radius: 6px; background: #e0e0e0; overflow: hidden; margin-top: 10px; }}
.bar > span {{ display: block; height: 100%; width: {r['score']}%; background: {risk_color}; }}
.card {{ background: #fff; border-radius: 12px; padding: 18px 22px; margin-top: 18px;
  box-shadow: 0 1px 4px rgba(0,0,0,.06); }}
.exec ul {{ margin: 8px 0 0; padding-left: 20px; }}
.exec li {{ margin: 2px 0; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
.kv td {{ padding: 4px 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
.kv td.k {{ color: #666; width: 170px; font-weight: 600; }}
.findings th, .findings td {{ text-align: left; padding: 7px 8px; border-bottom: 1px solid #eee; vertical-align: top; }}
.findings th {{ background: #fafafa; font-size: 12px; text-transform: uppercase; letter-spacing: .03em; color: #555; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.pill {{ display: inline-block; padding: 2px 9px; border-radius: 999px; color: #fff; font-size: 11px; font-weight: 700; }}
.desc {{ color: #333; font-size: 12.5px; }}
.ex {{ color: #888; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11px; margin-top: 3px; white-space: pre-wrap; word-break: break-all; }}
code {{ font-family: ui-monospace, Menlo, Consolas, monospace; background: #f0f0f0; padding: 1px 5px; border-radius: 4px; font-size: 12px; }}
.muted {{ color: #999; font-style: italic; }}
details.sec {{ background: #fff; border-radius: 12px; margin-top: 14px; box-shadow: 0 1px 4px rgba(0,0,0,.06); overflow: hidden; }}
details.sec > summary {{ cursor: pointer; padding: 14px 22px; font-weight: 700; font-size: 15px; list-style: none; }}
details.sec > summary::-webkit-details-marker {{ display: none; }}
details.sec > summary::before {{ content: '▸ '; color: #999; }}
details.sec[open] > summary::before {{ content: '▾ '; }}
.secbody {{ padding: 0 22px 18px; }}
details.mod {{ border: 1px solid #eee; border-radius: 8px; margin: 8px 0; }}
details.mod > summary {{ cursor: pointer; padding: 8px 12px; font-weight: 600; }}
pre.code {{ background: #1e1e2e; color: #e0e0e0; padding: 14px; border-radius: 8px; overflow-x: auto;
  font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; line-height: 1.5; margin: 0; }}
pre.code .k {{ color: #82aaff; }}
pre.code .s {{ color: #c3e88d; }}
pre.code .c {{ color: #697098; font-style: italic; }}
ul.ioc {{ margin: 4px 0; padding-left: 18px; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; word-break: break-all; }}
ul.flags li {{ margin: 3px 0; }}
.copybox {{ width: 100%; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px;
  border: 1px solid #ddd; border-radius: 8px; padding: 10px; background: #fafafa; }}
footer {{ margin-top: 30px; color: #999; font-size: 12px; text-align: center; }}
@media (prefers-color-scheme: dark) {{
  body {{ background: #15161a; color: #e6e6e6; }}
  header.top, .card, details.sec {{ background: #1f2127; box-shadow: none; border: 1px solid #2c2f36; }}
  h2 {{ border-color: #2c2f36; }}
  .kv td.k {{ color: #9aa; }}
  .findings th {{ background: #24262c; color: #aab; }}
  .kv td, .findings td {{ border-color: #2c2f36; }}
  code {{ background: #2a2d34; }}
  .copybox {{ background: #24262c; border-color: #2c2f36; color: #ddd; }}
}}
</style></head>
<body><div class="wrap">
<header class="top">
  <div>
    <h1>{_esc(f['name'])}</h1>
    <div class="muted">{_esc(f['file_type'])}{(' / ' + _esc(f['ooxml_subtype'])) if f.get('ooxml_subtype') else ''} &middot; {f['hashes']['size']} bytes</div>
    <div class="muted" style="font-family:ui-monospace,monospace;font-size:11px">SHA256 {_esc(f['hashes']['sha256'])}</div>
  </div>
  <div class="risk">
    <div class="score">{r['score']}</div>
    <div class="muted" style="font-size:11px">/ 100</div>
    <div class="badge">{_esc(r['classification'].upper())}</div>
    <div class="bar"><span></span></div>
  </div>
</header>

<div class="card exec">
  <h2>Executive summary</h2>
  <ul>{summary_html}</ul>
  {bd_table}
</div>

<div class="card">
  <h2>File identification</h2>
  {fileinfo}
</div>

{_section('Suspicious indicators', _build_findings_table(report['static']['findings']), open_default=True)}
{_section('Modern-format artefacts (OneNote / PDF / LNK / XLL)', fmt_html, open_default=True)}
{_section('Obfuscation analysis', obf_html)}
{_section('Extracted VBA', _build_vba_block(report['vba']['modules']))}
{_section('Excel 4.0 (XLM) macros', xlm_html)}
{_section('RTF embedded objects', rtf_html)}
{_section('YARA matches', yara_html)}
{_section('Document metadata', meta_table + meta_flags)}
{_section('Indicators of Compromise (defanged)', _build_ioc_block(report['iocs']), open_default=True)}

<div class="card">
  <h2>What to investigate next</h2>
  {steps_html or '<p class="muted">No specific follow-ups.</p>'}
</div>

<footer>Generated by vbascope &middot; {_esc(generated)} &middot; static analysis only, sample was never executed</footer>
</div></body></html>"""

    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(doc)
    return out_path
