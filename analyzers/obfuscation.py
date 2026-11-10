"""
Obfuscation detection and scoring.

Why it matters:
    Benign office macros are rare and almost never obfuscated. Heavy
    Chr()-building, giant concatenation chains, base64 blobs and gibberish
    identifier names are strong signals that someone is hiding intent from
    both analysts and signature engines (MITRE T1027 Obfuscated Files or
    Information). We quantify it so the risk score reflects *how hard* the
    author worked to hide, not just which APIs they called.

Techniques measured:
    * Chr/ChrW/ChrB density per module (flag > 10).
    * Concatenation-chain length ("a" & "b" & "c" ...).
    * Base64 candidate blobs (long [A-Za-z0-9+/=] runs, incl. possible PE).
    * Identifier entropy: random-looking variable/function names.
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Tuple

_CHR_RE = re.compile(r"Chr[WB]?\s*\(", re.IGNORECASE)
_CONCAT_RE = re.compile(r"(?:\"[^\"]*\"\s*&\s*){3,}")   # 3+ concatenations in a row
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# VBA identifier declarations (Dim/Const/Function/Sub names) to entropy-test.
_IDENT_RE = re.compile(
    r"\b(?:Dim|Const|Private|Public|Function|Sub|Set)\s+([A-Za-z_][A-Za-z0-9_]{5,})",
    re.IGNORECASE,
)
_PE_B64_PREFIX = ("TVqQ", "TVpB", "TVoA", "TVpQ")  # base64 of 'MZ..' variants


@dataclass
class ObfuscationResult:
    """Obfuscation metrics for one file (aggregated across modules)."""

    chr_count: int = 0
    chr_heavy_modules: List[str] = field(default_factory=list)
    max_concat_chain: int = 0
    concat_chain_count: int = 0
    base64_blobs: int = 0
    base64_decoded_pe: bool = False
    high_entropy_identifiers: int = 0
    sample_gibberish: List[str] = field(default_factory=list)
    score: int = 0          # obfuscation sub-score contribution
    indicators: List[str] = field(default_factory=list)

    @property
    def is_obfuscated(self) -> bool:
        return self.score > 0


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits/char; random strings trend high (> 3.3)."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_gibberish(identifier: str) -> bool:
    """Heuristic: high entropy and poor vowel ratio => machine-generated name.

    Human names like 'processData' read fine; kit-generated names like
    'Xq3Zb9kWpLm' do not.
    """
    if len(identifier) < 6:
        return False
    entropy = _shannon_entropy(identifier.lower())
    vowels = sum(1 for ch in identifier.lower() if ch in "aeiou")
    vowel_ratio = vowels / len(identifier)
    digit_ratio = sum(1 for ch in identifier if ch.isdigit()) / len(identifier)
    # Random names: entropy high, few vowels, or many embedded digits.
    return (entropy > 3.3 and vowel_ratio < 0.25) or digit_ratio > 0.4


def analyze_obfuscation(modules: List[Tuple[str, str]], raw_text: str) -> ObfuscationResult:
    """Score obfuscation across modules.

    Args:
        modules: list of (module_name, source_code).
        raw_text: raw file text (latin-1) for base64 blob hunting.

    Returns:
        ObfuscationResult with metrics and a capped sub-score.
    """
    result = ObfuscationResult()
    all_source = "\n".join(src for _, src in modules)
    search_space = f"{all_source}\n{raw_text}"

    # --- Chr density per module ---
    for name, src in modules:
        chr_hits = len(_CHR_RE.findall(src))
        result.chr_count += chr_hits
        if chr_hits > 10:
            result.chr_heavy_modules.append(f"{name} ({chr_hits} Chr calls)")

    if result.chr_heavy_modules:
        result.indicators.append(
            f"Heavy Chr()-building in {len(result.chr_heavy_modules)} module(s) "
            "- string literals assembled at runtime to evade scanners (T1027)."
        )

    # --- Concatenation chains ---
    chains = _CONCAT_RE.findall(all_source)
    result.concat_chain_count = len(chains)
    for ch in chains:
        amp = ch.count("&")
        if amp > result.max_concat_chain:
            result.max_concat_chain = amp
    if result.concat_chain_count > 0:
        result.indicators.append(
            f"{result.concat_chain_count} long concatenation chain(s) "
            f"(max {result.max_concat_chain} joins)."
        )

    # --- Base64 blobs (and embedded-PE-in-base64) ---
    for blob in _BASE64_RE.findall(search_space):
        result.base64_blobs += 1
        if blob[:4] in _PE_B64_PREFIX:
            result.base64_decoded_pe = True
        else:
            # Try a cheap decode on the first chunk to see if it's a PE.
            try:
                head = base64.b64decode(blob[: (len(blob) // 4) * 4], validate=False)
                if head[:2] == b"MZ":
                    result.base64_decoded_pe = True
            except Exception:
                pass
    if result.base64_blobs:
        note = f"{result.base64_blobs} base64-like blob(s)."
        if result.base64_decoded_pe:
            note += " At least one decodes to an MZ/PE header (embedded executable, T1027.002)."
        result.indicators.append(note)

    # --- Identifier entropy ---
    for ident in set(_IDENT_RE.findall(all_source)):
        if _looks_gibberish(ident):
            result.high_entropy_identifiers += 1
            if len(result.sample_gibberish) < 8:
                result.sample_gibberish.append(ident)
    if result.high_entropy_identifiers >= 3:
        result.indicators.append(
            f"{result.high_entropy_identifiers} gibberish/high-entropy identifier(s) "
            "- automated name mangling typical of macro builders."
        )

    # --- Sub-score (fed to the risk engine; obfuscation.py owns its weighting) ---
    score = 0
    score += 10 * len(result.chr_heavy_modules)
    score += 10 if result.concat_chain_count >= 3 else (5 if result.concat_chain_count else 0)
    score += 15 if result.base64_decoded_pe else (10 if result.base64_blobs else 0)
    score += 10 if result.high_entropy_identifiers >= 3 else 0
    result.score = min(score, 60)   # obfuscation alone shouldn't dominate

    return result
