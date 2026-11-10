"""
YARA integration.

Why it matters:
    YARA is the lingua franca of malware detection. vbascope ships a built-in
    ruleset (rules/default.yar) covering common maldoc tradecraft - PowerShell
    download cradles, base64 PE blobs, Emotet/Dridex-style macro skeletons,
    suspicious OLE structure - and also accepts analyst-supplied rules via
    --yara. We scan BOTH the raw file and the extracted VBA source, because
    decompressed VBA often reveals strings the compressed container hides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import yara
    _HAVE_YARA = True
except Exception:  # pragma: no cover
    _HAVE_YARA = False


@dataclass
class YaraStringHit:
    identifier: str
    offset: int
    data: str


@dataclass
class YaraMatch:
    rule: str
    namespace: str
    tags: List[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings: List[YaraStringHit] = field(default_factory=list)
    source: str = ""     # "file" or "vba"

    @property
    def description(self) -> str:
        return str(self.meta.get("description", ""))


@dataclass
class YaraResult:
    available: bool = True
    matches: List[YaraMatch] = field(default_factory=list)
    rules_loaded: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def match_count(self) -> int:
        return len(self.matches)


def _default_rules_dir() -> str:
    """Path to the shipped rules/ directory relative to the package root."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, "rules")


def _collect_rule_files(custom_path: Optional[str]) -> dict:
    """Build the namespace -> filepath map for compilation.

    Loads EVERY ``.yar``/``.yara`` in the shipped rules/ directory (so an
    analyst can drop new rule files in without touching code), then layers on
    any custom path. Each file gets a stable namespace derived from its name so
    duplicate rule identifiers across files do not collide.
    """
    filepaths: dict = {}

    rules_dir = _default_rules_dir()
    if os.path.isdir(rules_dir):
        for fname in sorted(os.listdir(rules_dir)):
            if fname.endswith((".yar", ".yara")):
                ns = "builtin:" + os.path.splitext(fname)[0]
                filepaths[ns] = os.path.join(rules_dir, fname)

    if custom_path:
        if os.path.isdir(custom_path):
            for fname in sorted(os.listdir(custom_path)):
                if fname.endswith((".yar", ".yara")):
                    ns = "custom:" + os.path.splitext(fname)[0]
                    filepaths[ns] = os.path.join(custom_path, fname)
        elif os.path.isfile(custom_path):
            filepaths["custom:" + os.path.splitext(os.path.basename(custom_path))[0]] = custom_path

    return filepaths


def _compile_rules(custom_path: Optional[str]) -> "yara.Rules":
    """Compile all built-in + optional custom rules into one Rules object.

    If one rule FILE fails to compile we drop it and retry with the rest, so a
    single malformed custom file never blinds the whole scanner (production
    resilience). Raises only if nothing compiles.
    """
    filepaths = _collect_rule_files(custom_path)
    if not filepaths:
        raise FileNotFoundError("no YARA rule files found")

    try:
        return yara.compile(filepaths=filepaths)
    except yara.Error:
        # Isolate the offender(s): compile file-by-file, keep what works.
        good: dict = {}
        for ns, path in filepaths.items():
            try:
                yara.compile(filepaths={ns: path})
                good[ns] = path
            except Exception:
                continue
        if not good:
            raise
        return yara.compile(filepaths=good)


def _normalise_match(m, source: str) -> YaraMatch:
    """Convert a yara.Match to our dataclass, across yara-python versions."""
    hits: List[YaraStringHit] = []
    try:
        # yara-python >= 4.3 exposes StringMatch objects.
        for sm in m.strings:
            if hasattr(sm, "instances"):
                for inst in sm.instances:
                    data = inst.matched_data
                    if isinstance(data, bytes):
                        data = data.decode("latin-1", "ignore")
                    hits.append(YaraStringHit(sm.identifier, inst.offset, data[:80]))
            else:
                # Older tuple form: (offset, identifier, data)
                offset, identifier, data = sm
                if isinstance(data, bytes):
                    data = data.decode("latin-1", "ignore")
                hits.append(YaraStringHit(identifier, offset, data[:80]))
    except Exception:
        pass

    return YaraMatch(
        rule=m.rule,
        namespace=getattr(m, "namespace", ""),
        tags=list(getattr(m, "tags", []) or []),
        meta=dict(getattr(m, "meta", {}) or {}),
        strings=hits,
        source=source,
    )


def scan_yara(file_path: str, vba_source: str, custom_rules: Optional[str] = None) -> YaraResult:
    """Scan a file and its VBA source with default + custom YARA rules.

    Args:
        file_path: Path to the original document.
        vba_source: Extracted VBA source text (scanned as a second buffer).
        custom_rules: Optional path to a .yar file or directory of rules.

    Returns:
        YaraResult with deduplicated matches tagged by source.
    """
    if not _HAVE_YARA:
        return YaraResult(available=False, errors=["yara-python not installed - run 'vbascope --setup'"])

    result = YaraResult()
    try:
        rules = _compile_rules(custom_rules)
    except Exception as exc:
        result.errors.append(f"rule compilation failed: {exc}")
        return result

    # Count loaded rules (best effort).
    try:
        result.rules_loaded = sum(1 for _ in rules)
    except Exception:
        result.rules_loaded = 0

    seen = set()

    # 1) Scan the raw file.
    try:
        for m in rules.match(file_path):
            key = (m.rule, "file")
            if key not in seen:
                seen.add(key)
                result.matches.append(_normalise_match(m, "file"))
    except Exception as exc:
        result.errors.append(f"file scan failed: {exc}")

    # 2) Scan extracted VBA source (as bytes).
    if vba_source:
        try:
            for m in rules.match(data=vba_source.encode("latin-1", "ignore")):
                key = (m.rule, "vba")
                if key not in seen:
                    seen.add(key)
                    result.matches.append(_normalise_match(m, "vba"))
        except Exception as exc:
            result.errors.append(f"vba scan failed: {exc}")

    return result
