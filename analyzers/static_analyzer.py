"""
Static suspicious-indicator analysis.

This is the heart of vbascope. Every pattern below maps to a real attacker
technique, annotated with the MITRE ATT&CK technique ID so a FOR610 student
can connect the regex to the behaviour it catches. Detections are organised
into categories, and each category contributes to the risk score.

We scan TWO corpora for every file:
    * extracted VBA source (and XLM formulas), and
    * the raw file bytes (catches payloads outside the VBA project: DDE,
      embedded scripts, MZ headers, raw URLs in object streams).

Matching is case-insensitive and tolerant of VBA's favourite evasion: string
concatenation. We do not try to fully deobfuscate here (that is obfuscation.py
and the XLM emulator's job); we flag the *presence* of the capability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Tuple

# Severity ordering used for sorting / colour in reports.
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    """A single suspicious indicator hit."""

    category: str
    name: str
    severity: str            # critical / high / medium / low / info
    mitre: str               # ATT&CK technique id(s)
    description: str         # why an analyst cares
    count: int = 0
    examples: List[str] = field(default_factory=list)

    @property
    def weight(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


@dataclass
class StaticResult:
    """All findings for one file plus auto-exec detection."""

    findings: List[Finding] = field(default_factory=list)
    autoexec_triggers: List[str] = field(default_factory=list)
    has_mz_embedded: bool = False
    has_dde: bool = False
    categories_hit: List[str] = field(default_factory=list)

    def by_severity(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (f.weight, f.count),
            reverse=True,
        )


# ---------------------------------------------------------------------------
# Signature table.
# Each entry: (category, name, severity, mitre, description, [regex patterns])
# Patterns are raw strings compiled case-insensitively below.
# ---------------------------------------------------------------------------
_SIGNATURES: List[Tuple[str, str, str, str, str, List[str]]] = [
    # ---------------- Execution / Shell (T1059) ----------------
    ("execution", "WScript.Shell", "high", "T1059.001/T1059.005",
     "Instantiates the Windows Script Host shell to run commands.",
     [r"WScript\.Shell", r"Wscript\.Shell", r"CreateObject\(\s*[\"']wscript\.shell"]),
    ("execution", "Shell() function", "high", "T1059",
     "VBA Shell() launches an arbitrary process directly.",
     [r"\bShell\s*\(", r"\bShell\s+\""]),
    ("execution", "Shell.Application", "high", "T1059",
     "Shell.Application / ShellExecute runs files with the shell verb handler.",
     [r"Shell\.Application", r"ShellExecute"]),
    ("execution", "PowerShell invocation", "critical", "T1059.001",
     "Spawns PowerShell - the dominant fileless execution vector.",
     [r"powershell(\.exe)?", r"\bpwsh\b"]),
    ("execution", "PowerShell stealth flags", "critical", "T1059.001/T1564",
     "Encoded/hidden PowerShell: -enc, -nop, -w hidden, -ep bypass.",
     [r"-enc\b", r"-encodedcommand", r"-nop\b", r"-noprofile",
      r"-w\s+hidden", r"-windowstyle\s+hidden", r"-ep\s+bypass",
      r"-executionpolicy\s+bypass"]),
    ("execution", "IEX / Invoke-Expression", "critical", "T1059.001",
     "Dynamic PowerShell execution of a downloaded/decoded string.",
     [r"\bIEX\b", r"Invoke-Expression"]),
    ("execution", "cmd.exe", "high", "T1059.003",
     "Windows command processor used to chain commands / launch payloads.",
     [r"cmd(\.exe)?\s*/[ck]\b", r"cmd\.exe"]),
    ("execution", "WMI process creation", "critical", "T1047",
     "WMI Win32_Process.Create spawns processes, often to evade parent-child "
     "heuristics (Office -> wmiprvse -> payload).",
     [r"winmgmts:", r"Win32_Process", r"\.Create\s*\("]),
    ("execution", "Scheduled task", "high", "T1053.005",
     "schtasks/at.exe create persistence or delayed execution.",
     [r"schtasks", r"\bat\.exe\b", r"Schedule\.Service"]),

    # ---------------- Download / Network (T1105) ----------------
    ("download", "URLDownloadToFile", "critical", "T1105",
     "URLDownloadToFileA imported from urlmon to fetch a payload to disk.",
     [r"URLDownloadToFile"]),
    ("download", "XMLHTTP / ServerXMLHTTP", "high", "T1105",
     "MSXML HTTP objects fetch remote content (payload or C2).",
     [r"MSXML2\.XMLHTTP", r"MSXML2\.ServerXMLHTTP", r"\bXMLHTTP\b",
      r"ServerXMLHTTP"]),
    ("download", "WinHttpRequest", "high", "T1105",
     "WinHttp.WinHttpRequest.5.1 HTTP client used to download payloads.",
     [r"WinHttp\.WinHttpRequest", r"WinHttpRequest"]),
    ("download", "InternetOpenUrl / wininet", "high", "T1105",
     "wininet API download cradle.",
     [r"InternetOpenUrl", r"InternetReadFile", r"InternetOpenA"]),
    ("download", ".NET WebClient", "critical", "T1105",
     "Net.WebClient DownloadString/DownloadFile - PowerShell download cradle.",
     [r"Net\.WebClient", r"DownloadString", r"DownloadFile", r"DownloadData"]),
    ("download", "Invoke-WebRequest", "high", "T1105",
     "PowerShell Invoke-WebRequest / iwr / curl alias fetch.",
     [r"Invoke-WebRequest", r"\biwr\b", r"Start-BitsTransfer"]),
    ("download", "ADODB.Stream write", "high", "T1105",
     "ADODB.Stream commonly pairs with a download to write bytes to disk.",
     [r"ADODB\.Stream"]),

    # ---------------- Obfuscation (T1027) ----------------
    ("obfuscation", "Chr/ChrW/ChrB building", "medium", "T1027",
     "Character-code string building to hide literals from scanners.",
     [r"Chr[WB]?\s*\(", r"Asc[WB]?\s*\("]),
    ("obfuscation", "StrReverse", "medium", "T1027",
     "Reversed strings hide keywords like 'llehsrewop'.",
     [r"StrReverse"]),
    ("obfuscation", "Replace() deobfuscation", "medium", "T1027",
     "Replace() strips junk separators to rebuild hidden strings.",
     [r"\bReplace\s*\("]),
    ("obfuscation", "Hex literal (&H)", "low", "T1027",
     "VBA hex literals used to encode bytes/strings.",
     [r"&H[0-9A-Fa-f]{2,}"]),
    ("obfuscation", "CallByName", "high", "T1027",
     "CallByName invokes methods by string name to dodge static resolution.",
     [r"CallByName"]),
    ("obfuscation", "Eval/Execute/ExecuteGlobal", "critical", "T1059.005/T1027",
     "Runtime evaluation of a dynamically built string - late-bound execution.",
     [r"\bExecuteGlobal\b", r"\bExecute\b", r"\bEval\s*\("]),
    ("obfuscation", "Environ()", "low", "T1027",
     "Environ() resolves %TEMP%/%APPDATA% drop paths at runtime.",
     [r"Environ\s*\("]),

    # ---------------- Persistence / Auto-exec (T1137 / T1547) ----------------
    ("persistence", "Registry Run key", "high", "T1547.001",
     "RegWrite to HKCU/HKLM Run key = autostart persistence.",
     [r"RegWrite", r"RegRead", r"RegDelete",
      r"HKCU\\", r"HKLM\\", r"HKEY_CURRENT_USER", r"HKEY_LOCAL_MACHINE",
      r"CurrentVersion\\Run"]),
    ("persistence", "Application.OnTime / Wait", "medium", "T1497",
     "Delayed/scheduled macro execution; Wait/Sleep also stalls sandboxes.",
     [r"Application\.OnTime", r"Application\.Wait"]),
    ("evasion", "Sleep API", "medium", "T1497.003",
     "Sleep() stalls automated analysis past its timeout (sandbox evasion).",
     [r"\bSleep\s*\(", r"kernel32.*Sleep"]),
    ("evasion", "Sandbox artifact checks", "high", "T1497.001",
     "Checks mouse movement, recent files, CPU count, or VM usernames.",
     [r"RecentFiles\.Count", r"Application\.MouseAvailable",
      r"GetObject\(\s*[\"']winmgmts.*Win32_ComputerSystem",
      r"NumberOfProcessors", r"VMwareVM", r"VBOX", r"sandbox"]),

    # ---------------- Modern delivery (post-2022 macro-block pivot) --------
    ("exploit", "Follina ms-msdt", "critical", "T1218/T1203",
     "ms-msdt: protocol handler abuse (CVE-2022-30190) - code exec via MSDT.",
     [r"ms-msdt:", r"IT_BrowseForFile", r"IT_RebrowseForFile"]),
    ("exploit", "MS protocol handler", "high", "T1218",
     "search-ms/ms-officecmd/ms-cxh handler abuse for execution or file staging.",
     [r"search-ms:", r"ms-officecmd:", r"ms-cxh:"]),
    ("smuggling", "HTML smuggling (blob)", "high", "T1027.006",
     "In-browser payload assembly: atob + Blob + createObjectURL/msSaveOrOpenBlob.",
     [r"msSaveOrOpenBlob", r"createObjectURL", r"new\s+Blob\s*\(",
      r"application/octet-stream"]),
    ("smuggling", "Auto-download trigger", "medium", "T1204.001",
     "Programmatic download/click (download= attribute, element.click()).",
     [r"download\s*=", r"\.click\s*\(\s*\)"]),
    ("client", "Embedded <script> / DOM inject", "high", "T1027.006/T1204.001",
     "Inline <script>, runtime script injection (createElementNS) or SVG "
     "<foreignObject> - markup-based code (SVG smuggling, HTA, HTML).",
     [r"<script", r"createElementNS", r"<foreignObject"]),
    ("client", "JS decode/exec", "medium", "T1027",
     "Runtime decode+exec gadgets (atob/unescape/fromCharCode + eval/Function).",
     [r"\batob\s*\(", r"\bunescape\s*\(", r"fromCharCode", r"decodeURIComponent",
      r"\beval\s*\(", r"new\s+Function\s*\("]),
    ("client", "Clipboard hijack (ClickFix)", "high", "T1204/T1059.001",
     "Writes a command to the clipboard for the victim to paste into Run "
     "(ClickFix / fake-CAPTCHA social engineering).",
     [r"navigator\.clipboard\.writeText", r"execCommand\(\s*['\"]copy",
      r"Win\+R"]),
    ("execution", "mshta", "high", "T1218.005",
     "mshta.exe runs remote/inline HTA - a trusted LOLBin script host.",
     [r"\bmshta(\.exe)?\b"]),
    ("execution", "regsvr32 / rundll32", "high", "T1218.010/T1218.011",
     "Signed-binary proxy execution via regsvr32/rundll32 (incl. scrobj/sct).",
     [r"\bregsvr32\b", r"\brundll32\b", r"scrobj\.dll", r"\.sct\b"]),

    # ---------------- Filesystem / Dropper (T1105 / T1204) ----------------
    ("filesystem", "FileSystemObject write", "medium", "T1105",
     "Scripting.FileSystemObject CreateTextFile/Write drops a file.",
     [r"Scripting\.FileSystemObject", r"CreateTextFile", r"\.WriteLine",
      r"SaveToFile"]),
    ("filesystem", "File ops (Kill/FileCopy/MkDir)", "low", "T1070.004",
     "File manipulation primitives used for staging/cleanup.",
     [r"\bKill\s+", r"\bFileCopy\b", r"\bMkDir\b", r"\bChDir\b"]),
]


def _compile_signatures() -> List[Tuple[str, str, str, str, str, List[Pattern]]]:
    compiled = []
    for category, name, severity, mitre, desc, patterns in _SIGNATURES:
        pats = [re.compile(p, re.IGNORECASE) for p in patterns]
        compiled.append((category, name, severity, mitre, desc, pats))
    return compiled


_COMPILED = _compile_signatures()

# Auto-execution entry points (these make a macro run on open/close = +score).
_AUTOEXEC = re.compile(
    r"\b(Auto_?Open|AutoOpen|Document_Open|Workbook_Open|Auto_?Close|"
    r"AutoClose|Document_Close|Document_BeforeClose|Workbook_Activate|"
    r"Auto_?Exec|AutoExec|Workbook_BeforeClose)\b",
    re.IGNORECASE,
)

# Raw-file-only indicators.
_MZ_EMBEDDED = re.compile(rb"MZ[\x00-\xff]{2}.{0,200}?This program", re.DOTALL)
_DDE_RE = re.compile(r"\bDDE(AUTO)?\b", re.IGNORECASE)


def _collect_examples(pattern: Pattern, text: str, limit: int = 3) -> Tuple[int, List[str]]:
    """Count matches and return a few trimmed example snippets."""
    examples: List[str] = []
    count = 0
    for m in pattern.finditer(text):
        count += 1
        if len(examples) < limit:
            start = max(0, m.start() - 20)
            end = min(len(text), m.end() + 20)
            snippet = text[start:end].replace("\n", " ").replace("\r", " ").strip()
            examples.append(snippet[:120])
    return count, examples


def analyze_static(
    vba_source: str,
    raw_bytes: bytes,
    text_for_strings: str = None,
) -> StaticResult:
    """Run the full static signature sweep.

    Args:
        vba_source: Concatenated VBA (and XLM) source text.
        raw_bytes: The raw file bytes (used for binary checks like the MZ scan).
        text_for_strings: Text corpus to run string signatures against. For
            OOXML this must be the DECOMPRESSED XML parts, since the payload
            (DDE fields, URLs, template refs) lives inside zip-compressed
            members and is invisible in the raw container bytes. When omitted
            we fall back to a lenient decode of ``raw_bytes``.

    Returns:
        StaticResult with deduplicated, counted findings.
    """
    result = StaticResult()

    # Decode raw bytes leniently so string signatures also hit object streams.
    if text_for_strings is None:
        raw_text = raw_bytes.decode("latin-1", "ignore")
    else:
        raw_text = text_for_strings
    haystack = f"{vba_source}\n{raw_text}"

    seen_categories = set()

    for category, name, severity, mitre, desc, patterns in _COMPILED:
        total = 0
        examples: List[str] = []
        for pat in patterns:
            # Prefer VBA source for examples, but count across the full haystack.
            c, ex = _collect_examples(pat, haystack)
            total += c
            for e in ex:
                if len(examples) < 3 and e not in examples:
                    examples.append(e)
        if total > 0:
            result.findings.append(
                Finding(
                    category=category,
                    name=name,
                    severity=severity,
                    mitre=mitre,
                    description=desc,
                    count=total,
                    examples=examples,
                )
            )
            seen_categories.add(category)

    # Auto-exec triggers (reported separately; heavy score weight).
    for m in _AUTOEXEC.finditer(vba_source or ""):
        trig = m.group(0)
        if trig not in result.autoexec_triggers:
            result.autoexec_triggers.append(trig)
    # Also check raw text (OOXML stores macro names there too).
    for m in _AUTOEXEC.finditer(raw_text):
        trig = m.group(0)
        if trig not in result.autoexec_triggers:
            result.autoexec_triggers.append(trig)

    # Embedded PE header.
    if _MZ_EMBEDDED.search(raw_bytes) or b"This program cannot be run in DOS" in raw_bytes:
        result.has_mz_embedded = True
        result.findings.append(
            Finding(
                category="embedded",
                name="Embedded PE (MZ header)",
                severity="critical",
                mitre="T1204.002",
                description="A Windows PE executable is embedded in the document "
                            "- a self-contained dropper.",
                count=1,
                examples=["MZ...This program cannot be run in DOS mode"],
            )
        )
        seen_categories.add("embedded")

    # DDE / DDEAUTO (OOXML field-based code execution, no macros required).
    if _DDE_RE.search(raw_text):
        result.has_dde = True
        result.findings.append(
            Finding(
                category="dde",
                name="DDE / DDEAUTO field",
                severity="critical",
                mitre="T1559.002",
                description="Dynamic Data Exchange field can launch a command "
                            "with no VBA at all (DDEAUTO auto-executes on open).",
                count=1,
                examples=["DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe ..."],
            )
        )
        seen_categories.add("dde")

    result.categories_hit = sorted(seen_categories)
    return result
