"""
XLM / Excel 4.0 macro extraction.

Why it matters:
    Excel 4.0 macros (a.k.a. XLM, boomer macros) predate VBA and live in
    macro sheets, not in a VBA project. Through 2020-2022 they were the most
    common Office malware delivery mechanism precisely because most VBA-focused
    tooling ignored them. They can call Win32 APIs directly via REGISTER/CALL,
    spawn processes via EXEC, and reach the network - all without a single
    line of VBA. MITRE T1059.005 (Visual Basic) / T1137 (Office app startup).

We use XLMMacroDeobfuscator when present. Because deobfuscation emulates the
macro and can hang on adversarial sheets, every run is wrapped in a hard
timeout (default 60s) enforced in a worker process.
"""

from __future__ import annotations

import multiprocessing as mp
import re
from dataclasses import dataclass, field
from typing import List, Optional

def _probe_xlm() -> bool:
    """Check XLMMacroDeobfuscator availability without leaking its import-time
    'pywin32 is not installed' banner to our stderr (it is only needed for live
    Excel, which we never use)."""
    import contextlib
    import io as _io

    try:
        with contextlib.redirect_stderr(_io.StringIO()), \
                contextlib.redirect_stdout(_io.StringIO()):
            import XLMMacroDeobfuscator  # noqa: F401
        return True
    except Exception:  # pragma: no cover - optional dependency
        return False


_HAVE_XLM = _probe_xlm()


# Formula keywords that indicate code execution / API abuse in XLM.
_XLM_DANGER = re.compile(
    r"\b(EXEC|CALL|RUN|REGISTER|FOPEN|FWRITE|FREAD|HALT|WORKBOOK\.ACTIVATE)\b",
    re.IGNORECASE,
)


@dataclass
class XLMResult:
    """Result of Excel 4.0 macro extraction."""

    has_xlm: bool = False
    formulas: List[str] = field(default_factory=list)
    dangerous_calls: List[str] = field(default_factory=list)
    timed_out: bool = False
    errors: List[str] = field(default_factory=list)


def _worker(path: str, queue: "mp.Queue") -> None:
    """Deobfuscate in a child process so we can kill it on timeout."""
    out: dict = {"formulas": [], "errors": []}
    try:
        from XLMMacroDeobfuscator.deobfuscator import process_file

        result = process_file(
            file=path,
            noninteractive=True,
            noindent=True,
            output_formula_format="[[CELL-ADDR]] [[INT-FORMULA]]",
            return_deobfuscated=True,
            timeout=55,
            silent=True,
        )
        if result:
            out["formulas"] = list(result)
    except Exception as exc:  # pragma: no cover - sample dependent
        out["errors"].append(f"XLM deobfuscation error: {exc}")
    try:
        queue.put(out)
    except Exception:
        pass


def extract_xlm(path: str, timeout: int = 60) -> XLMResult:
    """Extract Excel 4.0 macro formulas with a hard timeout.

    Args:
        path: Path to the .xls/.xlsm/.xlsb file.
        timeout: Seconds before the deobfuscation worker is killed.

    Returns:
        XLMResult with formulas and flagged dangerous calls.
    """
    result = XLMResult()

    if not _HAVE_XLM:
        result.errors.append(
            "XLMMacroDeobfuscator not installed - run 'vbascope --setup'"
        )
        return result

    ctx = mp.get_context("spawn")
    queue: "mp.Queue" = ctx.Queue()
    proc = ctx.Process(target=_worker, args=(path, queue))
    proc.start()
    proc.join(timeout)

    if proc.is_alive():
        proc.terminate()
        proc.join(5)
        result.timed_out = True
        result.errors.append(
            f"XLM deobfuscation exceeded {timeout}s and was terminated "
            "(possible anti-analysis stalling loop)."
        )
        return result

    try:
        out = queue.get_nowait()
    except Exception:
        out = {"formulas": [], "errors": ["no output from XLM worker"]}

    formulas = out.get("formulas", [])
    result.errors.extend(out.get("errors", []))

    if formulas:
        result.has_xlm = True
        result.formulas = [str(f) for f in formulas]
        for formula in result.formulas:
            if _XLM_DANGER.search(formula):
                result.dangerous_calls.append(formula)

    return result
