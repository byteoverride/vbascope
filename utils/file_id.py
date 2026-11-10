"""
File type identification.

Why it matters:
    Malicious documents routinely lie about what they are. A ``.doc`` may
    actually be an RTF, an MHTML, or a CDFV2 OLE container; a ``.xls`` sent
    by a phishing kit is frequently an OOXML zip renamed to dodge content
    filters. Trusting the extension is how analysts miss the payload, so we
    identify by content first (magic bytes + libmagic) and treat the
    extension only as a hint.
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

try:
    import magic  # python-magic
    _HAVE_MAGIC = True
except Exception:  # pragma: no cover - optional dependency
    _HAVE_MAGIC = False


class FileType(str, Enum):
    """High level container classification used to route extraction."""

    OLE2 = "OLE2 Compound Binary"        # Legacy .doc/.xls/.ppt, vbaProject.bin
    OOXML = "OOXML (ZIP-based)"          # .docx/.docm/.xlsx/.xlsm/.pptx/.pptm
    RTF = "Rich Text Format"            # .rtf, OLE objects embedded as hex
    MHTML = "MHTML / Web Archive"        # .mht single-file web page docs
    HTA = "HTML Application"             # .hta - runs as a trusted WSH host
    HTML = "HTML Document"              # .html/.htm - HTML smuggling carrier
    SCRIPT = "Script (VBS/WSF/JS)"       # .vbs/.wsf/.js standalone scripts
    ONENOTE = "OneNote Section"          # .one - MOTW-bypass embedded-file carrier
    SVG = "SVG Image"                   # .svg - scriptable image, 2025 top vector
    PDF = "PDF Document"                # .pdf - /JS /OpenAction /Launch lures
    LNK = "Windows Shortcut"            # .lnk - weaponised shell link
    XLL = "Excel XLL Add-in"            # PE DLL w/ xlAutoOpen, bypasses macro policy
    ZIP_ARCHIVE = "ZIP/RAR Archive"      # container of other documents
    PE = "PE Executable"                # dropped/embedded Windows binary
    UNKNOWN = "Unknown"


# Canonical magic byte signatures. Kept explicit so an analyst reading the
# source can see exactly what we key on.
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # D0 CF 11 E0 ...
_ZIP_MAGIC = b"PK\x03\x04"                           # Also PK\x05\x06, PK\x07\x08
_ZIP_EMPTY = b"PK\x05\x06"
_ZIP_SPAN = b"PK\x07\x08"
_RTF_MAGIC = b"{\\rt"
_PE_MAGIC = b"MZ"
_PDF_MAGIC = b"%PDF-"
# OneNote .one file-format header GUID {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
_ONENOTE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
# LNK ShellLinkHeader: HeaderSize 0x4C + LinkCLSID {00021401-0000-0000-C000-...46}
_LNK_MAGIC = bytes.fromhex("4c0000000114020000000000c000000000000046")


@dataclass
class FileIdentity:
    """Result of identifying a file."""

    path: str
    extension: str
    file_type: FileType
    libmagic_mime: Optional[str] = None
    libmagic_desc: Optional[str] = None
    ooxml_subtype: Optional[str] = None     # word / excel / powerpoint
    notes: List[str] = field(default_factory=list)

    @property
    def is_ooxml(self) -> bool:
        return self.file_type is FileType.OOXML

    @property
    def is_ole2(self) -> bool:
        return self.file_type is FileType.OLE2

    @property
    def is_rtf(self) -> bool:
        return self.file_type is FileType.RTF


def _read_header(path: str, n: int = 16) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(n)


def _classify_ooxml(path: str) -> Optional[str]:
    """Peek inside an OOXML zip to decide word/excel/powerpoint.

    This drives which internal part we look for (word/vbaProject.bin vs
    xl/vbaProject.bin) and whether XLM (Excel 4.0) detection applies.
    """
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except Exception:
        return None

    if any(n.startswith("word/") for n in names):
        return "word"
    if any(n.startswith("xl/") for n in names):
        return "excel"
    if any(n.startswith("ppt/") for n in names):
        return "powerpoint"
    return None


def identify_file(path: str) -> FileIdentity:
    """Identify a file by content, falling back to extension hints.

    Order of precedence:
        1. Magic bytes we recognise with certainty (OLE2, RTF, PE, ZIP).
        2. libmagic MIME (if python-magic is installed).
        3. Extension-based heuristics for text scripts (.vbs/.hta/.wsf).
    """
    extension = ""
    if "." in path:
        extension = "." + path.rsplit(".", 1)[-1].lower()

    header = _read_header(path, 32)

    libmagic_mime = None
    libmagic_desc = None
    if _HAVE_MAGIC:
        try:
            libmagic_mime = magic.from_file(path, mime=True)
            libmagic_desc = magic.from_file(path)
        except Exception:
            pass

    identity = FileIdentity(
        path=path,
        extension=extension,
        file_type=FileType.UNKNOWN,
        libmagic_mime=libmagic_mime,
        libmagic_desc=libmagic_desc,
    )

    # --- Content-based signatures first (don't trust the extension) ---
    if header.startswith(_ONENOTE_MAGIC):
        identity.file_type = FileType.ONENOTE
        identity.notes.append("OneNote section file - not subject to Mark-of-the-Web")
        return identity

    if header.startswith(_LNK_MAGIC):
        identity.file_type = FileType.LNK
        return identity

    if header.startswith(_PDF_MAGIC):
        identity.file_type = FileType.PDF
        return identity

    if header.startswith(_OLE2_MAGIC):
        identity.file_type = FileType.OLE2
        return identity

    # PE: could be a plain executable or a malicious Excel XLL add-in. The XLL
    # distinction (xlAutoOpen export) needs pefile and is confirmed downstream;
    # here we use the extension as the hint.
    if header.startswith(_PE_MAGIC):
        if extension in {".xll"}:
            identity.file_type = FileType.XLL
            identity.notes.append("PE with .xll extension - Excel add-in, runs regardless of macro policy")
        else:
            identity.file_type = FileType.PE
            identity.notes.append("MZ header - this is a PE binary, not a document")
        return identity

    if header.startswith((_ZIP_MAGIC, _ZIP_EMPTY, _ZIP_SPAN)):
        # Could be OOXML or a plain archive. OOXML zips contain a
        # [Content_Types].xml member at the root.
        subtype = _classify_ooxml(path)
        if subtype is not None:
            identity.file_type = FileType.OOXML
            identity.ooxml_subtype = subtype
        else:
            try:
                with zipfile.ZipFile(path) as zf:
                    if "[Content_Types].xml" in zf.namelist():
                        identity.file_type = FileType.OOXML
                    else:
                        identity.file_type = FileType.ZIP_ARCHIVE
            except Exception:
                identity.file_type = FileType.ZIP_ARCHIVE
        return identity

    if header.startswith(_RTF_MAGIC):
        identity.file_type = FileType.RTF
        return identity

    # --- Text / script / markup based formats ---
    # Sniff a larger text window for SVG/HTML, which may start with an XML
    # declaration, a comment, or a BOM before the real root element.
    text_head = _read_header(path, 1024).decode("latin-1", "ignore").lower()
    lowered_ext = extension

    # SVG: the 2025 top attachment vector. Detect by root element or extension,
    # content-first so a .svg renamed to .jpg is still caught.
    if "<svg" in text_head or lowered_ext == ".svg":
        identity.file_type = FileType.SVG
        return identity

    if lowered_ext in {".vbs", ".wsf", ".js", ".jse", ".wsh"}:
        identity.file_type = FileType.SCRIPT
        return identity
    if lowered_ext == ".hta" or "<hta:application" in text_head:
        identity.file_type = FileType.HTA
        return identity
    if lowered_ext in {".html", ".htm"} or "<!doctype html" in text_head or "<html" in text_head:
        identity.file_type = FileType.HTML
        return identity

    # MHTML single-file web archive (often seen as .doc in CVE-2021-40444 era).
    try:
        text_head = header.decode("latin-1", "ignore").lower()
        if text_head.startswith("mime-version:") or b"multipart/related" in header.lower():
            identity.file_type = FileType.MHTML
            return identity
    except Exception:
        pass

    # libmagic last-resort routing.
    if libmagic_mime:
        if "rtf" in libmagic_mime:
            identity.file_type = FileType.RTF
        elif "zip" in libmagic_mime or "officedocument" in libmagic_mime:
            identity.file_type = FileType.OOXML
        elif "msword" in libmagic_mime or "ole" in (libmagic_desc or "").lower():
            identity.file_type = FileType.OLE2
        elif libmagic_mime.startswith("text/"):
            identity.file_type = FileType.SCRIPT

    return identity
