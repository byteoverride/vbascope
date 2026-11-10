"""
IOC extraction and defanging.

Why it matters:
    IOCs (URLs, domains, IPs, emails, file paths, registry keys) are the
    product an analyst hands to detection engineering and threat intel. We
    extract them with tuned regexes, deduplicate, and DEFANG every network
    IOC so the report can be pasted into a ticket, chat or email without a
    well-meaning tool turning a live C2 link into a clickable one.

Defanging rules (community standard):
    http  -> hxxp,  https -> hxxps,  ftp -> fxp
    "."   -> "[.]",  "@"   -> "[@]",  "://" -> "[://]"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

# --- Regexes --------------------------------------------------------------
# Stop at whitespace, quotes, brackets, backslash AND any control byte
# (\x00-\x20). Without the control-byte guard, a URL embedded next to a null
# terminator in a binary OLE stream swallows the following bytes (e.g. an
# adjacent MZ/PE header) into the "URL".
_URL_RE = re.compile(
    r"(?:https?|ftp)://[^\x00-\x20\s\"'<>\)\]\}\\,;]+",
    re.IGNORECASE,
)
# Domains: require a dot and a TLD of 2+ letters; avoid matching version nums.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_EMAIL_RE = re.compile(
    r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b",
    re.IGNORECASE,
)
# Windows absolute paths and UNC paths.
_WINPATH_RE = re.compile(
    r"\b[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\?)+"
)
_UNC_RE = re.compile(
    r"\\\\[a-zA-Z0-9._\-]+\\[^\\/:*?\"<>|\r\n]+(?:\\[^\\/:*?\"<>|\r\n]+)*"
)
# Registry keys.
_REG_RE = re.compile(
    r"\b(?:HKCU|HKLM|HKCR|HKU|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS)\\[^\s\"'<>]+",
    re.IGNORECASE,
)

# URL hosts that are XML-namespace / schema boilerplate, never real IOCs.
# OOXML/RTF documents are full of these; emitting them buries the real C2.
_URL_NOISE_HOSTS = {
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "www.w3.org",
    "purl.org",
    "www.purl.org",
    "ns.adobe.com",
    "schemas.openxmlformats.com",
    "go.microsoft.com",
    "www.google.com",      # common in theme/part boilerplate
    "s4ml.org",
}


def _url_host(url: str) -> str:
    m = re.search(r"://([^/\\:?#]+)", url)
    return m.group(1).lower() if m else ""


# Domains that are almost always noise (schema/namespace refs in OOXML/RTF).
_DOMAIN_NOISE = {
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "www.w3.org",
    "purl.org",
    "microsoft.com",
    "go.microsoft.com",
    "schemas.openxmlformats.org",
    "ns.adobe.com",
    "openxmlformats.org",
    "w3.org",
}
# File extensions that are really just OOXML/RTF internals, not domains.
_DOMAIN_TLD_BLOCKLIST = {"xml", "rels", "bin", "png", "jpeg", "jpg", "gif", "emf", "wmf"}

# Allowlist of real TLDs. A "domain" is only accepted if its last label is a
# plausible TLD. Without this, VBA/JS member access like ``WScript.Shell``,
# ``ADODB.Stream`` or a dropped ``payload.exe`` get mis-parsed as domains and
# bury the real indicators. Covers common gTLDs and the ccTLDs that show up in
# malware infrastructure; extend as needed for your corpus.
_COMMON_TLDS = {
    # generic. Deliberately excludes novelty gTLDs that are ordinary English
    # words (stream, download, link, click, app, dev, work, name, host, page,
    # live, store, ...) because they collide with VBA/JS object and method
    # names (ADODB.Stream, Shell.Application) and produce false-positive IOCs.
    "com", "net", "org", "info", "biz", "io", "co", "xyz", "top",
    "club", "shop", "cloud", "fun", "icu", "vip", "cc", "tv", "me", "ws",
    "mobi", "gdn", "monster", "buzz", "pw", "su", "cyou", "sbs",
    # country / regional commonly abused
    "ru", "cn", "br", "in", "ir", "ua", "pl", "de", "fr", "uk", "eu", "nl",
    "it", "es", "tr", "kr", "jp", "vn", "id", "th", "ph", "my", "sg", "hk",
    "tw", "za", "ng", "ke", "ro", "cz", "sk", "hu", "gr", "pt", "se", "no",
    "fi", "dk", "ch", "at", "be", "ca", "au", "nz", "mx", "ar", "cl", "pe",
    "ve", "ec", "gov", "edu", "mil", "int",
}


def _plausible_domain(domain: str) -> bool:
    """True if the last label is a known TLD (keeps IOC domains high-precision)."""
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in _COMMON_TLDS


@dataclass
class IOCResult:
    """Deduplicated IOCs, both raw and defanged."""

    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    win_paths: List[str] = field(default_factory=list)
    unc_paths: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    defanged: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(
            len(x)
            for x in (
                self.urls, self.domains, self.ips, self.emails,
                self.win_paths, self.unc_paths, self.registry_keys,
            )
        )


def defang(value: str) -> str:
    """Render a network IOC inert for safe sharing."""
    out = value
    out = re.sub(r"https://", "hxxps://", out, flags=re.IGNORECASE)
    out = re.sub(r"http://", "hxxp://", out, flags=re.IGNORECASE)
    out = re.sub(r"ftp://", "fxp://", out, flags=re.IGNORECASE)
    out = out.replace("://", "[://]") if "[://]" not in out and "xxp" not in out else out
    out = out.replace(".", "[.]")
    out = out.replace("@", "[@]")
    return out


def _dedup_preserve(items) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            ordered.append(item)
    return ordered


def _clean_domains(domains, found_urls) -> List[str]:
    """Drop namespace noise and TLDs that are really file extensions."""
    url_hosts = set()
    for u in found_urls:
        m = re.search(r"://([^/\\:]+)", u)
        if m:
            url_hosts.add(m.group(1).lower())

    cleaned = []
    for d in domains:
        dl = d.lower()
        if dl in _DOMAIN_NOISE:
            continue
        tld = dl.rsplit(".", 1)[-1]
        if tld in _DOMAIN_TLD_BLOCKLIST:
            continue
        # High-precision gate: only keep names whose TLD is a real TLD, OR
        # that actually appeared as the host of an extracted URL.
        if not _plausible_domain(dl) and dl not in url_hosts:
            continue
        cleaned.append(d)
    return cleaned


def extract_iocs(text_sources: List[str]) -> IOCResult:
    """Extract and defang IOCs from one or more text blobs.

    Args:
        text_sources: e.g. [vba_source, raw_latin1_text].

    Returns:
        IOCResult with raw + defanged, deduplicated indicators.
    """
    blob = "\n".join(t for t in text_sources if t)

    urls = _dedup_preserve(_URL_RE.findall(blob))
    # Strip XML-namespace / schema boilerplate URLs so real C2 stands out.
    urls = [u for u in urls if _url_host(u) not in _URL_NOISE_HOSTS]
    ips = _dedup_preserve(_IPV4_RE.findall(blob))
    emails = _dedup_preserve(_EMAIL_RE.findall(blob))
    win_paths = _dedup_preserve(_WINPATH_RE.findall(blob))
    unc_paths = _dedup_preserve(_UNC_RE.findall(blob))
    reg_keys = _dedup_preserve(_REG_RE.findall(blob))

    raw_domains = _dedup_preserve(_DOMAIN_RE.findall(blob))
    domains = _clean_domains(raw_domains, urls)
    # Remove domains that are purely emails hosts duplication handled; also drop
    # anything that is actually an IP (regex overlap).
    domains = [d for d in domains if not _IPV4_RE.fullmatch(d)]

    result = IOCResult(
        urls=urls,
        domains=domains,
        ips=ips,
        emails=emails,
        win_paths=win_paths,
        unc_paths=unc_paths,
        registry_keys=reg_keys,
    )

    result.defanged = {
        "urls": [defang(u) for u in urls],
        "domains": [defang(d) for d in domains],
        "ips": [defang(i) for i in ips],
        "emails": [defang(e) for e in emails],
    }
    return result
