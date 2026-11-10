"""
CSV reporter - one row per analyzed file for batch triage.

In production you point vbascope at a directory of quarantined attachments and
want a single spreadsheet to sort by risk, pivot on SHA256, and hand to the
team. This writer appends a row per file so a whole batch lands in one CSV.
"""

from __future__ import annotations

import csv
import os
from typing import List

CSV_FIELDS: List[str] = [
    "filename", "file_type", "risk_score", "classification",
    "sha256", "md5", "size",
    "has_vba", "vba_stomping", "has_xlm", "autoexec",
    "onenote_payloads", "pdf_actions", "is_xll", "lnk_command",
    "yara_matches", "categories", "top_iocs",
]


def _row(report: dict) -> dict:
    f = report["file"]
    static = report["static"]
    iocs = report["iocs"]
    top_iocs = (iocs["defanged"].get("urls", []) + iocs["defanged"].get("ips", []))[:5]

    pdf = report.get("pdf", {})
    pdf_actions = ";".join(m["name"] for m in pdf.get("markers", [])) if pdf.get("applicable") else ""
    one = report.get("onenote", {})
    lnk = report.get("lnk", {})
    xll = report.get("xll", {})

    return {
        "filename": f["name"],
        "file_type": f["file_type"],
        "risk_score": report["risk"]["score"],
        "classification": report["risk"]["classification"],
        "sha256": f["hashes"]["sha256"],
        "md5": f["hashes"]["md5"],
        "size": f["hashes"]["size"],
        "has_vba": report["vba"]["has_vba"],
        "vba_stomping": report["vba"]["vba_stomping_detected"],
        "has_xlm": report["xlm"]["has_xlm"],
        "autoexec": ";".join(static["autoexec_triggers"]),
        "onenote_payloads": one.get("payload_count", 0) if one.get("applicable") else 0,
        "pdf_actions": pdf_actions,
        "is_xll": xll.get("is_xll", False) if xll.get("applicable") else False,
        "lnk_command": (lnk.get("command_text", "") if lnk.get("applicable") else "")[:200],
        "yara_matches": ";".join(sorted({m["rule"] for m in report["yara"].get("matches", [])})),
        "categories": ";".join(static["categories_hit"]),
        "top_iocs": " ".join(top_iocs),
    }


def append_csv(report: dict, out_path: str) -> str:
    """Append one report as a row to a CSV, writing the header if new."""
    exists = os.path.isfile(out_path)
    with open(out_path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        if not exists:
            writer.writeheader()
        writer.writerow(_row(report))
    return out_path
