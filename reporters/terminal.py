"""
Terminal reporter (rich).

Produces a colour-coded console summary. Falls back to plain print() if rich
is not installed or --no-color is set, so the tool is never unusable.
"""

from __future__ import annotations

from typing import Dict, List

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    _HAVE_RICH = True
except Exception:  # pragma: no cover
    _HAVE_RICH = False


_RISK_COLORS = {
    "Clean": "green",
    "Low": "cyan",
    "Medium": "yellow",
    "High": "dark_orange",
    "Critical": "red",
}
_SEVERITY_COLORS = {
    "critical": "red",
    "high": "dark_orange",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
}


def _plain(report: dict) -> None:
    """Dependency-free fallback renderer."""
    f = report["file"]
    r = report["risk"]
    print(f"\n==== vbascope :: {f['name']} ====")
    print(f"Type       : {f['file_type']}  (mime: {f.get('libmagic_mime')})")
    print(f"SHA256     : {f['hashes']['sha256']}")
    print(f"Size       : {f['hashes']['size']} bytes   magic: {f['hashes']['magic_bytes']}")
    print(f"RISK SCORE : {r['score']}/100  -> {r['classification']}")
    print("")
    if report["vba"]["has_vba"]:
        print(f"VBA modules: {report['vba']['module_count']} "
              f"(stomping: {report['vba']['vba_stomping_detected']})")
    if report["static"]["autoexec_triggers"]:
        print("Auto-exec  : " + ", ".join(report["static"]["autoexec_triggers"]))
    print("\nSuspicious indicators:")
    for finding in report["static"]["findings"]:
        print(f"  [{finding['severity'].upper():8}] {finding['name']} "
              f"x{finding['count']}  ({finding['mitre']})")
    yr = report["yara"]
    if yr.get("match_count"):
        print("\nYARA matches:")
        for m in yr["matches"]:
            print(f"  - {m['rule']} [{m['source']}] {m.get('description','')}")
    one = report.get("onenote", {})
    if one.get("applicable") and one.get("payload_count"):
        print(f"\nOneNote embedded payloads ({one['payload_count']}):")
        for p in one.get("payloads", []):
            print(f"  #{p['index']} {p['sniffed_type']} {p['size']}B" + (" (PE)" if p.get("is_pe") else ""))
    pdf = report.get("pdf", {})
    if pdf.get("applicable") and pdf.get("markers"):
        print("\nPDF markers:")
        for m in pdf["markers"]:
            print(f"  {m['name']} x{m['count']} ({m['mitre']})")
    lnk = report.get("lnk", {})
    if lnk.get("applicable") and lnk.get("command_text"):
        print(f"\nLNK command: {lnk['command_text']}")
    xll = report.get("xll", {})
    if xll.get("applicable") and xll.get("is_xll"):
        print("\nXLL: MALICIOUS add-in (runs on load, bypasses macro policy)")

    iocs = report["iocs"]
    if iocs["total"]:
        print(f"\nIOCs ({iocs['total']}):")
        for u in iocs["defanged"].get("urls", []):
            print(f"  url: {u}")
        for ip in iocs["defanged"].get("ips", []):
            print(f"  ip : {ip}")
    print("\nWhat to investigate next:")
    for step in report.get("next_steps", []):
        print(f"  * {step}")
    print("")


def render_terminal(
    report: dict,
    use_color: bool = True,
    quiet: bool = False,
    export_svg: Optional[str] = None,
) -> None:
    """Render the report to the terminal.

    Args:
        report: Analysis report dict.
        use_color: Honour --no-color by passing False.
        quiet: Only show risk score + critical findings.
        export_svg: If set (and rich is available), also save the rendered
            output as a standalone SVG "screenshot" at this path.
    """
    if not _HAVE_RICH or (not use_color and not export_svg):
        _plain(report)
        return

    record = export_svg is not None
    console = Console(no_color=not use_color, highlight=False, record=record, width=100)
    f = report["file"]
    r = report["risk"]
    risk_color = _RISK_COLORS.get(r["classification"], "white")

    # --- Header panel ---
    header = Text()
    header.append(f"{f['name']}\n", style="bold white")
    header.append(f"{f['file_type']}", style="white")
    if f.get("ooxml_subtype"):
        header.append(f" / {f['ooxml_subtype']}", style="white")
    header.append(f"   mime: {f.get('libmagic_mime') or 'n/a'}\n", style="dim")
    header.append(f"SHA256 {f['hashes']['sha256']}\n", style="dim")
    header.append(f"MD5    {f['hashes']['md5']}   ", style="dim")
    header.append(f"size {f['hashes']['size']}B   magic {f['hashes']['magic_bytes']}", style="dim")
    console.print(Panel(header, title="vbascope", border_style=risk_color, box=box.ROUNDED))

    # --- Risk banner ---
    score = r["score"]
    bar_len = 30
    filled = int(bar_len * score / 100)
    bar = "█" * filled + "░" * (bar_len - filled)
    risk_text = Text()
    risk_text.append(f" {bar} ", style=risk_color)
    risk_text.append(f"{score}/100  {r['classification'].upper()}", style=f"bold {risk_color}")
    console.print(risk_text)

    if quiet:
        # Only critical/high findings in quiet mode.
        crit = [x for x in report["static"]["findings"] if x["severity"] in ("critical", "high")]
        if crit:
            console.print("\n[bold]Critical / High indicators:[/bold]")
            for x in crit:
                color = _SEVERITY_COLORS.get(x["severity"], "white")
                console.print(f"  [{color}]{x['severity'].upper()}[/{color}] {x['name']} "
                              f"x{x['count']}  ({x['mitre']})")
        return

    # --- VBA summary ---
    vba = report["vba"]
    if vba["has_vba"]:
        line = f"[bold]VBA[/bold]: {vba['module_count']} module(s) via {vba['extraction_method']}"
        if vba["vba_stomping_detected"]:
            line += "   [red bold]VBA STOMPING DETECTED (T1564.007)[/red bold]"
        console.print("\n" + line)
        for mod in vba["modules"]:
            flag = " [red](stomped)[/red]" if mod.get("is_stomped") else ""
            console.print(f"   - {mod['module_name']} [{mod['module_type']}] "
                          f"{mod['code_len']}B{flag}")

    if report["xlm"]["has_xlm"]:
        console.print(f"\n[bold]XLM (Excel 4.0)[/bold]: {len(report['xlm']['formulas'])} formula(s), "
                      f"{len(report['xlm']['dangerous_calls'])} dangerous")

    # --- Auto-exec ---
    if report["static"]["autoexec_triggers"]:
        console.print("\n[bold red]Auto-execution triggers:[/bold red] " +
                      ", ".join(report["static"]["autoexec_triggers"]))

    # --- Suspicious indicators table ---
    findings: List[Dict] = report["static"]["findings"]
    if findings:
        table = Table(title="Suspicious Indicators", box=box.SIMPLE_HEAVY, header_style="bold")
        table.add_column("Severity", no_wrap=True)
        table.add_column("Indicator")
        table.add_column("Cat", no_wrap=True)
        table.add_column("Count", justify="right")
        table.add_column("MITRE", no_wrap=True)
        for x in sorted(findings, key=lambda k: (-{"critical":4,"high":3,"medium":2,"low":1,"info":0}.get(k["severity"],0), -k["count"])):
            color = _SEVERITY_COLORS.get(x["severity"], "white")
            table.add_row(
                f"[{color}]{x['severity'].upper()}[/{color}]",
                x["name"],
                x["category"],
                str(x["count"]),
                x["mitre"],
            )
        console.print(table)

    # --- Obfuscation ---
    obf = report["obfuscation"]
    if obf.get("indicators"):
        console.print("\n[bold]Obfuscation:[/bold]")
        for ind in obf["indicators"]:
            console.print(f"   • {ind}")

    # --- YARA ---
    yr = report["yara"]
    if yr.get("match_count"):
        ytable = Table(title=f"YARA Matches ({yr['rules_loaded']} rules loaded)",
                       box=box.SIMPLE, header_style="bold")
        ytable.add_column("Rule")
        ytable.add_column("Src", no_wrap=True)
        ytable.add_column("Description")
        for m in yr["matches"]:
            ytable.add_row(m["rule"], m["source"], m.get("description", ""))
        console.print(ytable)
    elif not yr.get("available"):
        console.print("\n[dim]YARA unavailable (yara-python not installed).[/dim]")

    # --- Format-specific sections (OneNote / PDF / LNK / XLL) ---
    one = report.get("onenote", {})
    if one.get("applicable") and one.get("payload_count"):
        console.print(f"\n[bold]OneNote embedded payloads ({one['payload_count']}):[/bold]")
        for p in one.get("payloads", []):
            pe = " [red](PE)[/red]" if p.get("is_pe") else ""
            console.print(f"   - #{p['index']} {p['sniffed_type']} {p['size']}B @ {p['offset']}{pe}")

    pdf = report.get("pdf", {})
    if pdf.get("applicable") and pdf.get("markers"):
        console.print(f"\n[bold]PDF structure[/bold] ({pdf.get('object_count',0)} objects):")
        for m in pdf["markers"]:
            color = _SEVERITY_COLORS.get(m["severity"], "white")
            console.print(f"   [{color}]{m['name']}[/{color}] x{m['count']}  ({m['mitre']})")
        for e in pdf.get("errors", []):
            console.print(f"   [dim]{e}[/dim]")

    lnk = report.get("lnk", {})
    if lnk.get("applicable"):
        console.print("\n[bold]LNK shortcut:[/bold]")
        if lnk.get("relative_path"):
            console.print(f"   target : {lnk['relative_path']}")
        if lnk.get("arguments"):
            console.print(f"   args   : [yellow]{lnk['arguments']}[/yellow]")
        if lnk.get("working_dir"):
            console.print(f"   workdir: {lnk['working_dir']}")

    xll = report.get("xll", {})
    if xll.get("applicable"):
        verdict = "[red bold]MALICIOUS XLL[/red bold]" if xll.get("is_xll") else "XLL/PE (no auto-exec export found)"
        extra = " via Excel-DNA" if xll.get("exceldna") else (" (exports xlAutoOpen)" if xll.get("has_xlautoopen") else "")
        console.print(f"\n[bold]XLL add-in:[/bold] {verdict}{extra}")

    # --- Metadata flags ---
    meta = report["metadata"]
    if meta.get("flags"):
        console.print("\n[bold]Metadata flags:[/bold]")
        for fl in meta["flags"]:
            console.print(f"   • {fl}")

    # --- IOCs ---
    iocs = report["iocs"]
    if iocs["total"]:
        itable = Table(title=f"IOCs ({iocs['total']}, defanged)", box=box.SIMPLE, header_style="bold")
        itable.add_column("Type", no_wrap=True)
        itable.add_column("Indicator")
        for u in iocs["defanged"].get("urls", []):
            itable.add_row("url", u)
        for d in iocs["defanged"].get("domains", [])[:20]:
            itable.add_row("domain", d)
        for ip in iocs["defanged"].get("ips", []):
            itable.add_row("ip", ip)
        for em in iocs["defanged"].get("emails", []):
            itable.add_row("email", em)
        for p in iocs.get("win_paths", [])[:10]:
            itable.add_row("path", p)
        for rk in iocs.get("registry_keys", [])[:10]:
            itable.add_row("reg", rk)
        console.print(itable)

    # --- Next steps ---
    steps = report.get("next_steps", [])
    if steps:
        body = "\n".join(f"• {s}" for s in steps)
        console.print(Panel(body, title="What to investigate next", border_style="cyan", box=box.ROUNDED))

    # --- Errors ---
    errs = report.get("errors", [])
    if errs:
        console.print("\n[dim]Notes/errors:[/dim]")
        for e in errs:
            console.print(f"   [dim]- {e}[/dim]")

    # --- Optional SVG "screenshot" export ---
    if export_svg:
        try:
            console.save_svg(export_svg, title=f"vbascope :: {report['file']['name']}")
        except Exception:
            pass
