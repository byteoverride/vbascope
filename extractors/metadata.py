"""
Document metadata extraction.

Why it matters:
    Metadata is cheap attribution and triage. The "last saved by" / author
    fields leak the builder kit or actor handle; a remote template
    (``Template`` pointing at an http URL) is a Template Injection loader
    (MITRE T1221) that fetches the real payload at open time; wildly
    out-of-range creation dates betray a kit that never sets the clock. We
    pull OLE SummaryInformation for legacy files and docProps/*.xml for OOXML,
    then flag the usual tells.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

try:
    from oletools.olefile import OleFileIO, isOleFile
    _HAVE_OLEFILE = True
except Exception:  # pragma: no cover
    try:
        from olefile import OleFileIO, isOleFile
        _HAVE_OLEFILE = True
    except Exception:
        _HAVE_OLEFILE = False


_SUSPICIOUS_AUTHORS = {"user", "admin", "administrator", "john", ""}
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


@dataclass
class MetadataResult:
    """Normalised metadata with suspicion flags."""

    fields: Dict[str, object] = field(default_factory=dict)
    template: Optional[str] = None
    flags: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _flag_common(result: MetadataResult) -> None:
    """Apply shared suspicion heuristics over whatever fields we gathered."""
    author = str(result.fields.get("author", "")).strip().lower()
    last_saved = str(result.fields.get("last_saved_by", "")).strip().lower()

    if author in _SUSPICIOUS_AUTHORS and author != "":
        result.flags.append(f"Generic author name '{author}' - common in malware kits.")
    if last_saved in _SUSPICIOUS_AUTHORS and last_saved != "":
        result.flags.append(f"Generic last-saved-by '{last_saved}'.")

    # Remote template = Template Injection (T1221).
    tmpl = result.template or str(result.fields.get("template", ""))
    if tmpl and _URL_RE.search(tmpl):
        result.flags.append(
            f"Remote template reference '{tmpl}' - Template Injection loader (T1221)."
        )

    # Creation date sanity.
    for key in ("create_time", "created"):
        val = result.fields.get(key)
        if isinstance(val, datetime):
            year = val.year
            now_year = datetime.now(timezone.utc).year
            if year < 1995 or year > now_year + 1:
                result.flags.append(
                    f"Creation date {val.isoformat()} is implausible - timestamp tampering."
                )


def _extract_ole_metadata(path: str) -> MetadataResult:
    """Pull OLE SummaryInformation / DocumentSummaryInformation."""
    result = MetadataResult()
    try:
        ole = OleFileIO(path)
    except Exception as exc:
        result.errors.append(f"OleFileIO failed: {exc}")
        return result

    try:
        meta = ole.get_metadata()
        mapping = {
            "author": meta.author,
            "last_saved_by": meta.last_saved_by,
            "company": meta.company,
            "title": meta.title,
            "subject": meta.subject,
            "keywords": meta.keywords,
            "template": meta.template,
            "create_time": meta.create_time,
            "last_saved_time": meta.last_saved_time,
            "creating_application": meta.creating_application,
            "revision_number": meta.revision_number,
            "num_pages": meta.num_pages,
        }
        for key, val in mapping.items():
            if val is None:
                continue
            if isinstance(val, bytes):
                val = val.decode("latin-1", "ignore")
            result.fields[key] = val
        if meta.template:
            tmpl = meta.template
            result.template = tmpl.decode("latin-1", "ignore") if isinstance(tmpl, bytes) else tmpl
    except Exception as exc:
        result.errors.append(f"OLE metadata parse failed: {exc}")
    finally:
        try:
            ole.close()
        except Exception:
            pass

    _flag_common(result)
    return result


# OOXML core/app property tags we care about -> normalised key.
_CORE_TAGS = {
    "creator": "author",
    "lastModifiedBy": "last_saved_by",
    "title": "title",
    "subject": "subject",
    "keywords": "keywords",
    "created": "created",
    "modified": "modified",
    "revision": "revision_number",
}
_APP_TAGS = {
    "Company": "company",
    "Application": "creating_application",
    "Template": "template",
    "TotalTime": "edit_minutes",
}


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _extract_ooxml_metadata(path: str) -> MetadataResult:
    """Parse docProps/core.xml and docProps/app.xml from the OOXML zip."""
    import xml.etree.ElementTree as ET

    result = MetadataResult()
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())

            if "docProps/core.xml" in names:
                try:
                    root = ET.fromstring(zf.read("docProps/core.xml"))
                    for child in root:
                        tag = _strip_ns(child.tag)
                        if tag in _CORE_TAGS and child.text:
                            result.fields[_CORE_TAGS[tag]] = child.text.strip()
                except Exception as exc:
                    result.errors.append(f"core.xml parse failed: {exc}")

            if "docProps/app.xml" in names:
                try:
                    root = ET.fromstring(zf.read("docProps/app.xml"))
                    for child in root:
                        tag = _strip_ns(child.tag)
                        if tag in _APP_TAGS and child.text:
                            value = child.text.strip()
                            result.fields[_APP_TAGS[tag]] = value
                            if tag == "Template":
                                result.template = value
                except Exception as exc:
                    result.errors.append(f"app.xml parse failed: {exc}")
    except Exception as exc:
        result.errors.append(f"OOXML metadata read failed: {exc}")
        return result

    # Normalise ISO date strings to datetime for the date sanity check.
    for key in ("created", "modified"):
        val = result.fields.get(key)
        if isinstance(val, str):
            try:
                result.fields[key] = datetime.fromisoformat(val.replace("Z", "+00:00"))
            except Exception:
                pass

    _flag_common(result)
    return result


def extract_metadata(path: str, is_ooxml: bool, is_ole2: bool) -> MetadataResult:
    """Dispatch to the right metadata extractor based on container type."""
    if is_ooxml:
        return _extract_ooxml_metadata(path)
    if is_ole2 and _HAVE_OLEFILE:
        return _extract_ole_metadata(path)

    result = MetadataResult()
    if is_ole2 and not _HAVE_OLEFILE:
        result.errors.append("olefile not available for OLE metadata.")
    return result
