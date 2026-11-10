"""
vbascope.analyzers
~~~~~~~~~~~~~~~~~~~

Turn raw extracted content into findings: suspicious API patterns, IOCs,
obfuscation scoring and YARA matches. Analyzers never execute sample code;
everything here is static pattern and entropy analysis.
"""

from .static_analyzer import analyze_static, Finding, StaticResult, SEVERITY_ORDER
from .ioc_extractor import extract_iocs, defang, IOCResult
from .obfuscation import analyze_obfuscation, ObfuscationResult
from .yara_scanner import scan_yara, YaraResult, YaraMatch

__all__ = [
    "analyze_static",
    "Finding",
    "StaticResult",
    "SEVERITY_ORDER",
    "extract_iocs",
    "defang",
    "IOCResult",
    "analyze_obfuscation",
    "ObfuscationResult",
    "scan_yara",
    "YaraResult",
    "YaraMatch",
]
