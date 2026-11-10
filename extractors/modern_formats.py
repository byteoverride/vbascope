"""
Extractors for post-2022 maldoc formats: OneNote, PDF, LNK and XLL.

These are the delivery vehicles that replaced VBA after Microsoft blocked
internet macros by default in mid-2022. Each function is defensive: it returns
partial results and records errors rather than raising.

References: MS-ONESTORE (OneNote), MS-SHLLINK (LNK), Didier Stevens' onedump,
Cisco Talos 'XLLing in Excel', SANS ISC OneNote diaries.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# OneNote
# ---------------------------------------------------------------------------
# FileDataStoreObject GUID {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC} marks an
# embedded file. Layout (MS-ONESTORE 2.6.13): 16-byte GUID header, then an
# 8-byte cbLength, 4-byte unused, 8-byte reserved (= 36 bytes total) before the
# file data begins. So: length is the LE uint64 at guid_off+16, data starts at
# guid_off+36.
_FDSO_GUID = bytes.fromhex("e716e3bd652611 45a4c48d4d0b7a9eac".replace(" ", ""))
_FDSO_HEADER_LEN = 36


@dataclass
class EmbeddedPayload:
    index: int
    offset: int
    size: int
    sniffed_type: str
    data: bytes = b""
    notes: List[str] = field(default_factory=list)

    @property
    def is_pe(self) -> bool:
        return self.data[:2] == b"MZ"


@dataclass
class OneNoteResult:
    is_onenote: bool = False
    payloads: List[EmbeddedPayload] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def payload_count(self) -> int:
        return len(self.payloads)


def _sniff_embedded(data: bytes) -> str:
    """Identify an embedded OneNote payload by its leading bytes/strings."""
    head = data[:512]
    low = head.lower()
    if head[:2] == b"MZ":
        return "PE executable"
    if b"<hta:application" in low:
        return "HTA application"
    if b"<job" in low or b"<package" in low:
        return "WSF script"
    if low.lstrip().startswith(b"@echo") or b"cmd /c" in low or b"cmd.exe" in low:
        return "Batch/CMD script"
    if b"createobject" in low or low.lstrip().startswith(b"dim "):
        return "VBScript"
    if b"powershell" in low:
        return "PowerShell script"
    if head[:4] == b"\x4c\x00\x00\x00":
        return "LNK shortcut"
    if head[:5] == b"%PDF-":
        return "PDF document"
    if head[:2] == b"PK":
        return "ZIP/OOXML archive"
    return "unknown/data"


def extract_onenote(path: str, raw_bytes: Optional[bytes] = None) -> OneNoteResult:
    """Extract embedded files from a OneNote .one section file.

    Walks every FileDataStoreObject GUID and carves the embedded payload that
    follows, sniffing its type. The carved bytes are returned so the caller can
    run the full static/IOC/YARA pipeline over each dropped payload.
    """
    result = OneNoteResult(is_onenote=True)
    try:
        data = raw_bytes if raw_bytes is not None else open(path, "rb").read()
    except Exception as exc:
        result.errors.append(f"read failed: {exc}")
        return result

    start = 0
    idx = 0
    while True:
        pos = data.find(_FDSO_GUID, start)
        if pos == -1:
            break
        start = pos + 16
        try:
            size = struct.unpack_from("<Q", data, pos + 16)[0]
        except Exception:
            result.errors.append(f"malformed FileDataStoreObject at {pos}")
            continue
        data_off = pos + _FDSO_HEADER_LEN
        # Clamp to a sane bound to avoid giant/overflowed sizes.
        if size <= 0 or size > len(data) or data_off + size > len(data):
            size = max(0, min(size, len(data) - data_off))
        blob = data[data_off:data_off + size] if size else b""
        if not blob:
            continue
        payload = EmbeddedPayload(
            index=idx,
            offset=data_off,
            size=len(blob),
            sniffed_type=_sniff_embedded(blob),
            data=blob,
        )
        payload.notes.append(
            f"Embedded {payload.sniffed_type} carved from OneNote FileDataStoreObject "
            "(double-click lure; OneNote bypasses Mark-of-the-Web)."
        )
        result.payloads.append(payload)
        idx += 1

    return result


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
_PDF_MARKERS = {
    "/JavaScript": ("critical", "T1059.007", "Embedded JavaScript"),
    "/JS": ("high", "T1059.007", "JavaScript action"),
    "/OpenAction": ("high", "T1204.002", "Auto-action on open"),
    "/AA": ("high", "T1204.002", "Additional (auto) actions"),
    "/Launch": ("critical", "T1204.002", "Launch action (runs external program)"),
    "/EmbeddedFile": ("high", "T1027.006", "Embedded file"),
    "/URI": ("medium", "T1566.002", "External URI link"),
    "/SubmitForm": ("medium", "T1566.002", "Form submission to remote URL"),
    "/GoToR": ("medium", "T1204.002", "Remote go-to action"),
    "/RichMedia": ("medium", "T1204.002", "Rich media (Flash/embedded) object"),
}


@dataclass
class PDFResult:
    is_pdf: bool = False
    markers: List[Tuple[str, str, str, int]] = field(default_factory=list)  # name, sev, mitre, count
    uris: List[str] = field(default_factory=list)
    object_count: int = 0
    has_openaction_js: bool = False
    errors: List[str] = field(default_factory=list)


def scan_pdf(path: str, raw_bytes: Optional[bytes] = None) -> PDFResult:
    """Lightweight structural PDF triage (no rendering, no JS execution).

    Counts the dangerous object types and pulls URIs. Does not decompress
    object streams, so a heavily compressed PDF may under-report - that is
    called out, and a sandbox/peepdf pass is the next step.
    """
    result = PDFResult(is_pdf=True)
    try:
        data = raw_bytes if raw_bytes is not None else open(path, "rb").read()
    except Exception as exc:
        result.errors.append(f"read failed: {exc}")
        return result

    result.object_count = len(re.findall(rb"\d+\s+\d+\s+obj", data))

    for marker, (sev, mitre, desc) in _PDF_MARKERS.items():
        count = data.count(marker.encode())
        if count:
            result.markers.append((marker, sev, mitre, count))

    names = {m[0] for m in result.markers}
    if ("/OpenAction" in names or "/AA" in names) and ("/JavaScript" in names or "/JS" in names):
        result.has_openaction_js = True

    for m in re.finditer(rb"/URI\s*\(([^)]{1,2048})\)", data):
        try:
            uri = m.group(1).decode("latin-1", "ignore").strip()
            if uri and uri not in result.uris:
                result.uris.append(uri)
        except Exception:
            continue

    if b"/ObjStm" in data or b"/FlateDecode" in data:
        result.errors.append(
            "PDF uses object/stream compression - some actions may be hidden; "
            "confirm with peepdf/pdfid or a sandbox."
        )
    return result


# ---------------------------------------------------------------------------
# LNK  (MS-SHLLINK)
# ---------------------------------------------------------------------------
@dataclass
class LNKResult:
    is_lnk: bool = False
    arguments: Optional[str] = None
    relative_path: Optional[str] = None
    working_dir: Optional[str] = None
    icon_location: Optional[str] = None
    name_string: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    @property
    def command_text(self) -> str:
        return " ".join(
            x for x in (self.relative_path, self.arguments, self.working_dir) if x
        )


# LinkFlags bits we care about (MS-SHLLINK 2.1.1).
_LF_HAS_TARGET_IDLIST = 0x00000001
_LF_HAS_LINKINFO = 0x00000002
_LF_HAS_NAME = 0x00000004
_LF_HAS_RELATIVE_PATH = 0x00000008
_LF_HAS_WORKING_DIR = 0x00000010
_LF_HAS_ARGUMENTS = 0x00000020
_LF_HAS_ICON_LOCATION = 0x00000040
_LF_IS_UNICODE = 0x00000080


def extract_lnk(path: str, raw_bytes: Optional[bytes] = None) -> LNKResult:
    """Parse a Windows .lnk and recover its command-line arguments.

    The arguments field is where weaponised shortcuts hide the real command
    (powershell -enc ..., cmd /c curl ...). We do a minimal, bounds-checked
    MS-SHLLINK walk to reach the StringData block.
    """
    result = LNKResult(is_lnk=True)
    try:
        data = raw_bytes if raw_bytes is not None else open(path, "rb").read()
    except Exception as exc:
        result.errors.append(f"read failed: {exc}")
        return result

    if len(data) < 76 or struct.unpack_from("<I", data, 0)[0] != 0x4C:
        result.errors.append("not a valid ShellLinkHeader")
        return result

    try:
        flags = struct.unpack_from("<I", data, 20)[0]
        is_unicode = bool(flags & _LF_IS_UNICODE)
        off = 0x4C  # end of fixed header

        # Skip LinkTargetIDList (2-byte size + bytes).
        if flags & _LF_HAS_TARGET_IDLIST:
            idlist_size = struct.unpack_from("<H", data, off)[0]
            off += 2 + idlist_size

        # Skip LinkInfo (its first 4 bytes are its own total size).
        if flags & _LF_HAS_LINKINFO:
            linkinfo_size = struct.unpack_from("<I", data, off)[0]
            off += linkinfo_size

        def read_string(cur: int) -> Tuple[Optional[str], int]:
            """Read one CountCharacters-prefixed StringData entry."""
            if cur + 2 > len(data):
                return None, cur
            count = struct.unpack_from("<H", data, cur)[0]
            cur += 2
            if is_unicode:
                nbytes = count * 2
                raw = data[cur:cur + nbytes]
                text = raw.decode("utf-16-le", "ignore")
            else:
                raw = data[cur:cur + count]
                text = raw.decode("latin-1", "ignore")
                nbytes = count
            return text, cur + nbytes

        if flags & _LF_HAS_NAME:
            result.name_string, off = read_string(off)
        if flags & _LF_HAS_RELATIVE_PATH:
            result.relative_path, off = read_string(off)
        if flags & _LF_HAS_WORKING_DIR:
            result.working_dir, off = read_string(off)
        if flags & _LF_HAS_ARGUMENTS:
            result.arguments, off = read_string(off)
        if flags & _LF_HAS_ICON_LOCATION:
            result.icon_location, off = read_string(off)
    except Exception as exc:
        result.errors.append(f"LNK parse error: {exc}")

    return result


# ---------------------------------------------------------------------------
# XLL  (malicious Excel add-in)
# ---------------------------------------------------------------------------
@dataclass
class XLLResult:
    is_xll: bool = False
    exports: List[str] = field(default_factory=list)
    has_xlautoopen: bool = False
    exceldna: bool = False
    errors: List[str] = field(default_factory=list)


def check_xll(path: str, raw_bytes: Optional[bytes] = None) -> XLLResult:
    """Confirm an Excel XLL add-in by inspecting PE exports for xlAutoOpen.

    XLLs execute via the exported xlAutoOpen()/xlAutoClose() the moment the
    add-in loads - independent of macro settings (T1059). Excel-DNA built XLLs
    hide the export, so we also string-match the framework.
    """
    result = XLLResult()
    try:
        import pefile
    except Exception:
        result.errors.append("pefile not installed - run 'vbascope --setup'")
        return result

    try:
        data = raw_bytes if raw_bytes is not None else open(path, "rb").read()
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
        )
    except Exception as exc:
        result.errors.append(f"PE parse failed: {exc}")
        return result

    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode("latin-1", "ignore")
                    result.exports.append(name)
                    if name.lower() in ("xlautoopen", "xlautoclose", "xladdinmanagerinfo"):
                        result.has_xlautoopen = True
        if result.has_xlautoopen:
            result.is_xll = True
    except Exception as exc:
        result.errors.append(f"export walk failed: {exc}")

    # Excel-DNA detection (string-based; it proxies the real xlAutoOpen).
    low = data.lower()
    if b"exceldna" in low or b"excel-dna" in low:
        result.exceldna = True
        result.is_xll = True

    return result
