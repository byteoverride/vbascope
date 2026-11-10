"""
vbascope.extractors
~~~~~~~~~~~~~~~~~~~~

Pull raw artefacts out of a document: VBA source, Excel 4.0 (XLM) macros,
RTF-embedded OLE objects and document metadata. Each extractor is defensive:
it returns partial results and records errors rather than raising, so one
malformed stream never kills the whole analysis.
"""

from .vba_extractor import extract_vba, VBAModule, VBAResult
from .xlm_extractor import extract_xlm, XLMResult
from .rtf_extractor import extract_rtf_objects, RTFResult
from .metadata import extract_metadata, MetadataResult
from .modern_formats import (
    extract_onenote, OneNoteResult, EmbeddedPayload,
    scan_pdf, PDFResult,
    extract_lnk, LNKResult,
    check_xll, XLLResult,
)

__all__ = [
    "extract_vba",
    "VBAModule",
    "VBAResult",
    "extract_xlm",
    "XLMResult",
    "extract_rtf_objects",
    "RTFResult",
    "extract_metadata",
    "MetadataResult",
    "extract_onenote",
    "OneNoteResult",
    "EmbeddedPayload",
    "scan_pdf",
    "PDFResult",
    "extract_lnk",
    "LNKResult",
    "check_xll",
    "XLLResult",
]
