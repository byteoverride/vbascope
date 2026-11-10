"""
RTF embedded object extraction.

Why it matters:
    RTF has no macros of its own, so attackers abuse it as a *carrier*. The
    classic pattern: an RTF with an embedded OLE object (often an Equation
    Editor exploit - CVE-2017-11882 / CVE-2018-0802, T1203 exploitation for
    client execution) or an embedded OLE2 document that itself carries VBA.
    RTF also hides payloads with obfuscation: fake control words, nested
    groups, and hex object data split with whitespace to defeat signatures.

oletools.rtfobj walks the RTF and yields embedded objects with their class
name and raw bytes. We surface each object, flag Equation/Package/OLE2
classes, and hand any embedded OLE2 blob back so the VBA engine can recurse
into it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from oletools.rtfobj import RtfObjParser
    _HAVE_RTFOBJ = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_RTFOBJ = False


# OLE class names worth shouting about.
_SUSPICIOUS_CLASSES = {
    "equation.3": "Equation Editor exploit carrier (CVE-2017-11882/0802, T1203)",
    "package": "OLE Package - can drop and launch an arbitrary file (T1204.002)",
    "ole2link": "OLE2Link - remote payload fetch (CVE-2017-0199, T1203)",
    "word.document": "Embedded Word doc - may carry its own VBA project",
    "excel.sheet": "Embedded Excel sheet - may carry VBA or XLM macros",
}

_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_MZ_MAGIC = b"MZ"


@dataclass
class RTFObject:
    """A single embedded object pulled from an RTF carrier."""

    index: int
    class_name: Optional[str]
    size: int
    is_ole_package: bool = False
    embedded_filename: Optional[str] = None
    embedded_srcpath: Optional[str] = None
    temp_path: Optional[str] = None
    raw: bytes = b""
    notes: List[str] = field(default_factory=list)

    @property
    def contains_ole2(self) -> bool:
        return _OLE2_MAGIC in self.raw[:4096] or self.raw.startswith(_OLE2_MAGIC)

    @property
    def contains_pe(self) -> bool:
        return self.raw[:2] == _MZ_MAGIC


@dataclass
class RTFResult:
    """Aggregate RTF extraction result."""

    object_count: int = 0
    objects: List[RTFObject] = field(default_factory=list)
    embedded_ole2_blobs: List[bytes] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def extract_rtf_objects(path: str) -> RTFResult:
    """Parse an RTF file and return its embedded OLE objects.

    Args:
        path: Path to the RTF file.

    Returns:
        RTFResult. ``embedded_ole2_blobs`` holds any OLE2 streams so the
        caller can recurse and pull VBA out of them.
    """
    result = RTFResult()

    if not _HAVE_RTFOBJ:
        result.errors.append("oletools (rtfobj) not installed - run 'vbascope --setup'")
        return result

    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except Exception as exc:
        result.errors.append(f"could not read RTF: {exc}")
        return result

    try:
        parser = RtfObjParser(data)
        parser.parse()
    except Exception as exc:
        result.errors.append(f"rtfobj parse failed: {exc}")
        return result

    for idx, rtfobj in enumerate(parser.objects):
        raw = getattr(rtfobj, "oledata", None) or getattr(rtfobj, "rawdata", b"") or b""
        class_name = None
        if getattr(rtfobj, "is_ole", False):
            class_name = getattr(rtfobj, "class_name", None)
            if isinstance(class_name, bytes):
                class_name = class_name.decode("latin-1", "ignore")

        obj = RTFObject(
            index=idx,
            class_name=class_name,
            size=len(raw),
            is_ole_package=bool(getattr(rtfobj, "is_package", False)),
            raw=raw,
        )

        # Package metadata (filename + source path of the dropped file).
        if getattr(rtfobj, "is_package", False):
            fname = getattr(rtfobj, "filename", None)
            src = getattr(rtfobj, "src_path", None)
            obj.embedded_filename = fname.decode("latin-1", "ignore") if isinstance(fname, bytes) else fname
            obj.embedded_srcpath = src.decode("latin-1", "ignore") if isinstance(src, bytes) else src
            obj.notes.append(
                "OLE Package object: drops a file to disk, often to %TEMP% or Startup."
            )

        # Known-bad class names.
        if class_name:
            key = class_name.lower().strip()
            for bad, why in _SUSPICIOUS_CLASSES.items():
                if bad in key:
                    obj.notes.append(f"Suspicious OLE class '{class_name}': {why}")
                    break

        if obj.contains_pe:
            obj.notes.append("Embedded object starts with MZ - raw PE payload (T1204.002).")
        if obj.contains_ole2:
            obj.notes.append("Embedded OLE2 compound file - recursing for VBA.")
            result.embedded_ole2_blobs.append(raw)

        result.objects.append(obj)

    result.object_count = len(result.objects)
    return result
