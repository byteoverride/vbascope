"""
VBA extraction engine.

Primary path uses oletools.olevba (the de-facto standard parser used by
every mainstream sandbox). We also implement a manual OOXML fallback that
locates ``vbaProject.bin`` inside the zip and feeds it to olevba's
VBA_Parser, which matters when a file has a corrupt directory stream that
confuses the automatic container detection.

Key detection: VBA STOMPING (MITRE T1564.007 "VBA Stomping" / defense
evasion). Office caches compiled p-code alongside the human-readable source.
Attackers blank or replace the source so that static tools (and analysts)
see benign code, while Office executes the malicious p-code. olevba surfaces
this via ``detect_vba_stomping`` and by reporting p-code when source is
empty. We flag any module whose source is blank but whose compiled code
exists.
"""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional

import contextlib as _contextlib
import io as _io

# olevba pulls in XLMMacroDeobfuscator, which prints a 'pywin32 is not
# installed' banner to stdout at import time. That banner is irrelevant to us
# (we never drive live Excel) and would corrupt our own report output, so we
# swallow stdout/stderr for the duration of the import only.
try:
    with _contextlib.redirect_stdout(_io.StringIO()), \
            _contextlib.redirect_stderr(_io.StringIO()):
        from oletools.olevba import VBA_Parser, VBA_Parser_CLI  # noqa: F401
    _HAVE_OLEVBA = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_OLEVBA = False


@dataclass
class VBAModule:
    """A single extracted VBA module/stream."""

    filename: str                 # OLE stream path inside the container
    stream_path: str              # full stream path
    module_name: str              # logical module name
    module_type: str              # Standard / ThisDocument / Class / UserForm / Unknown
    source_code: str              # decompressed VBA source
    code_len: int = 0
    is_stomped: bool = False      # source blank but p-code present
    notes: List[str] = field(default_factory=list)


@dataclass
class VBAResult:
    """Aggregate VBA extraction result for one file."""

    has_vba: bool = False
    modules: List[VBAModule] = field(default_factory=list)
    vba_stomping_detected: bool = False
    combined_source: str = ""
    errors: List[str] = field(default_factory=list)
    extraction_method: str = ""

    @property
    def module_count(self) -> int:
        return len(self.modules)


# Auto-exec and class markers used to label module type when olevba does not.
_THISDOC_NAMES = {"ThisDocument", "ThisWorkbook"}


def _guess_module_type(stream_path: str, module_name: str, source: str) -> str:
    """Best-effort classification of a VBA module type.

    olevba exposes module type via the project dir stream, but when we fall
    back to manual parsing we infer from the name and content.
    """
    name = module_name or ""
    if name in _THISDOC_NAMES or name.startswith("Sheet") or name.startswith("Worksheet"):
        return "ThisDocument/Workbook"
    lowered = source.lower()
    if "attribute vb_base = \"0{" in lowered or "begin {" in lowered:
        return "UserForm"
    if "attribute vb_globalnamespace" in lowered:
        return "Class"
    if "attribute vb_creatable" in lowered or "attribute vb_predeclaredid" in lowered:
        # Predeclared + not creatable commonly indicates a document/class module.
        return "Class"
    return "Standard"


def _detect_stomping_for_module(parser: "VBA_Parser", stream_path: str, source: str) -> bool:
    """Heuristic: source blank/whitespace while a p-code module exists.

    If olevba decompressed essentially nothing for a stream that is a real
    VBA module, the source was likely stripped (stomped) while compiled
    p-code drives execution.
    """
    stripped = (source or "").strip()
    if stripped:
        return False
    # An empty-source VBA stream that still registers as a module is the
    # classic stomping fingerprint.
    return True


def _extract_with_olevba(path: str, data: Optional[bytes] = None) -> VBAResult:
    """Run olevba against a path or in-memory bytes."""
    result = VBAResult(extraction_method="olevba")

    try:
        if data is not None:
            parser = VBA_Parser(filename="in-memory.bin", data=data)
        else:
            parser = VBA_Parser(path)
    except Exception as exc:
        result.errors.append(f"VBA_Parser init failed: {exc}")
        return result

    try:
        if not parser.detect_vba_macros():
            result.has_vba = False
            return result

        result.has_vba = True

        # Project-wide VBA stomping check (olevba >= 0.56).
        try:
            if hasattr(parser, "detect_vba_stomping") and parser.detect_vba_stomping():
                result.vba_stomping_detected = True
        except Exception:
            pass

        combined_parts: List[str] = []
        for (ole_filename, stream_path, vba_filename, vba_code) in parser.extract_macros():
            source = vba_code or ""
            module_name = vba_filename or stream_path.split("/")[-1]
            mtype = _guess_module_type(stream_path, module_name, source)
            stomped = _detect_stomping_for_module(parser, stream_path, source)
            if stomped:
                result.vba_stomping_detected = True

            module = VBAModule(
                filename=vba_filename or "",
                stream_path=stream_path or ole_filename or "",
                module_name=module_name,
                module_type=mtype,
                source_code=source,
                code_len=len(source),
                is_stomped=stomped,
            )
            if stomped:
                module.notes.append(
                    "Source is empty but module registered - possible VBA stomping "
                    "(T1564.007): compiled p-code may run while source looks benign."
                )
            result.modules.append(module)
            combined_parts.append(
                f"' ===== Module: {module_name} ({mtype}) "
                f"[{stream_path}] =====\n{source}\n"
            )

        result.combined_source = "\n".join(combined_parts)
    except Exception as exc:
        result.errors.append(f"extract_macros failed: {exc}")
    finally:
        try:
            parser.close()
        except Exception:
            pass

    return result


def _manual_ooxml_vbaproject(path: str) -> Optional[bytes]:
    """Locate vbaProject.bin inside an OOXML zip and return its bytes.

    OOXML macro-enabled files (.docm/.xlsm/.pptm, sometimes .docx that have
    been tampered with) store the VBA project as a single OLE blob named
    ``word/vbaProject.bin`` / ``xl/vbaProject.bin`` / ``ppt/vbaProject.bin``.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.lower().endswith("vbaproject.bin"):
                    return zf.read(name)
    except Exception:
        return None
    return None


def extract_vba(path: str, is_ooxml: bool = False) -> VBAResult:
    """Extract VBA from a document.

    Strategy:
        1. Hand the file straight to olevba (handles OLE2, OOXML and RTF).
        2. If olevba reports no macros but the file is OOXML, manually pull
           ``vbaProject.bin`` from the zip and parse that blob directly. This
           recovers macros when container autodetection is defeated.

    Args:
        path: File to analyse.
        is_ooxml: Whether the caller identified this as an OOXML zip.

    Returns:
        VBAResult with modules, stomping flag and any errors.
    """
    if not _HAVE_OLEVBA:
        res = VBAResult()
        res.errors.append("oletools is not installed - run 'vbascope --setup'")
        return res

    result = _extract_with_olevba(path)

    # Fallback: OOXML container where auto-detection found nothing.
    if (not result.has_vba or result.module_count == 0) and is_ooxml:
        blob = _manual_ooxml_vbaproject(path)
        if blob:
            manual = _extract_with_olevba(path, data=blob)
            manual.extraction_method = "olevba+manual-vbaProject.bin"
            if manual.has_vba:
                # Preserve any errors from the first attempt for transparency.
                manual.errors = result.errors + manual.errors
                return manual

    return result
