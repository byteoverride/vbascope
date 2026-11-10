"""
JSON report writer.

Emits the full structured analysis so vbascope can feed a pipeline (SOAR,
MISP, a sandbox submission wrapper, a Jupyter triage notebook). Everything in
the report dict is converted to JSON-safe primitives first.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any


def to_json_safe(obj: Any) -> Any:
    """Recursively convert datetimes, bytes and sets to JSON-safe values."""
    if isinstance(obj, dict):
        return {str(k): to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_json_safe(v) for v in obj]
    if isinstance(obj, set):
        return [to_json_safe(v) for v in sorted(obj, key=str)]
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.decode("latin-1", "ignore")
    return obj


def write_json(report: dict, out_path: str) -> str:
    """Serialise the report to a pretty-printed JSON file.

    Args:
        report: The analysis report dict.
        out_path: Destination path.

    Returns:
        The path written.
    """
    safe = to_json_safe(report)
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(safe, handle, indent=2, ensure_ascii=False)
    return out_path
