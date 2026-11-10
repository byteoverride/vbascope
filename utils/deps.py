"""
Dependency checker / installer.

vbascope leans on a handful of third-party libraries (oletools, yara-python,
XLMMacroDeobfuscator, pefile, python-magic, rich). This module checks whether
they are importable and, when asked, installs the missing ones with pip.

Security note:
    We deliberately never call sudo and never read any ambient password
    variable. Package installs go to the user site (``pip install --user``)
    and only fall back to ``--break-system-packages`` on a PEP-668 managed
    environment. Installing analysis tooling should never require root.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
from shutil import which
from typing import Dict, List, Tuple

# Map of import-name -> pip-install-name. They differ for several packages.
REQUIRED_PACKAGES: Dict[str, str] = {
    "oletools": "oletools",
    "yara": "yara-python",
    "XLMMacroDeobfuscator": "XLMMacroDeobfuscator",
    "pefile": "pefile",
    "magic": "python-magic",
    "rich": "rich",
}

# System binaries that improve results but are not mandatory.
OPTIONAL_SYSTEM_TOOLS: List[str] = ["exiftool", "file", "strings"]


def _is_importable(module_name: str) -> bool:
    try:
        importlib.import_module(module_name)
        return True
    except Exception:
        return False


def check_python_packages() -> Dict[str, bool]:
    """Return a map of import-name -> available(bool)."""
    return {mod: _is_importable(mod) for mod in REQUIRED_PACKAGES}


def check_system_tools() -> Dict[str, bool]:
    """Return a map of system-tool -> present(bool) using PATH lookup."""
    return {tool: which(tool) is not None for tool in OPTIONAL_SYSTEM_TOOLS}


def _pip_install(pip_name: str) -> Tuple[bool, str]:
    """Attempt to install a single package, user-site first.

    Returns (success, combined_output).
    """
    attempts = [
        [sys.executable, "-m", "pip", "install", "--user", pip_name],
        # PEP 668 "externally managed" environments reject the above; the
        # documented escape hatch is --break-system-packages.
        [sys.executable, "-m", "pip", "install", "--break-system-packages", pip_name],
    ]
    combined = []
    for cmd in attempts:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )
            combined.append(proc.stdout + proc.stderr)
            if proc.returncode == 0:
                return True, "\n".join(combined)
        except Exception as exc:  # pragma: no cover - environment dependent
            combined.append(str(exc))
    return False, "\n".join(combined)


def ensure_dependencies(install: bool = False, verbose: bool = False) -> Dict[str, object]:
    """Check (and optionally install) all required packages.

    Args:
        install: When True, pip-install any missing package.
        verbose: When True, echo pip output.

    Returns:
        A report dict with per-package status and the system-tool status.
    """
    report: Dict[str, object] = {
        "packages": {},
        "system_tools": check_system_tools(),
        "installed": [],
        "failed": [],
    }

    status = check_python_packages()
    for mod, available in status.items():
        pip_name = REQUIRED_PACKAGES[mod]
        if available:
            report["packages"][mod] = "present"
            continue

        if not install:
            report["packages"][mod] = "missing"
            continue

        print(f"[deps] installing {pip_name} ...", file=sys.stderr)
        ok, output = _pip_install(pip_name)
        if verbose:
            print(output, file=sys.stderr)
        if ok and _is_importable(mod):
            report["packages"][mod] = "installed"
            report["installed"].append(pip_name)  # type: ignore[attr-defined]
        else:
            report["packages"][mod] = "failed"
            report["failed"].append(pip_name)      # type: ignore[attr-defined]

    return report


def print_dependency_report(report: Dict[str, object]) -> None:
    """Human readable summary printed to stderr."""
    print("\n=== Dependency check ===", file=sys.stderr)
    for mod, state in report["packages"].items():  # type: ignore[union-attr]
        marker = {
            "present": "[ok]",
            "installed": "[+]",
            "missing": "[!]",
            "failed": "[x]",
        }.get(state, "[?]")
        print(f"  {marker} {mod}: {state}", file=sys.stderr)

    print("\n=== System tools (optional) ===", file=sys.stderr)
    for tool, present in report["system_tools"].items():  # type: ignore[union-attr]
        marker = "[ok]" if present else "[!]"
        note = "" if present else "  (not found in PATH - some checks degraded)"
        print(f"  {marker} {tool}{note}", file=sys.stderr)
