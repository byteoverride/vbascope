"""
vbascope.reporters
~~~~~~~~~~~~~~~~~~~

Render the analysis report in three forms: a rich terminal summary, a
machine-parseable JSON document, and a self-contained HTML report. All three
consume the same plain ``report`` dict produced by the orchestrator, so they
never diverge.
"""

from .terminal import render_terminal
from .json_report import write_json, to_json_safe
from .html_report import write_html
from .csv_report import append_csv

__all__ = ["render_terminal", "write_json", "to_json_safe", "write_html", "append_csv"]
