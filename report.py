import csv
import json

from auditor.base import SgFinding

try:
    from rich.console import Console
    from rich.table import Table
    RICH = True
except ImportError:
    RICH = False


def print_terminal(findings: list[SgFinding]) -> None:
    if not findings:
        print("No findings.")
        return
    if RICH:
        console = Console()
        table = Table(title="AWS Security Group Audit")
        table.add_column("Rule", style="cyan")
        table.add_column("Severity", style="bold")
        table.add_column("SG ID")
        table.add_column("SG Name")
        table.add_column("VPC")
        table.add_column("Title")
        SEV_COLOR = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "green"}
        for f in findings:
            color = SEV_COLOR.get(f.severity, "white")
            table.add_row(f.rule_id, f"[{color}]{f.severity}[/{color}]", f.sg_id, f.sg_name, f.vpc_id, f.title)
        console.print(table)
    else:
        for f in findings:
            print(f"{f.severity} [{f.rule_id}] {f.sg_id} ({f.sg_name}) - {f.title}")


def print_json(findings: list[SgFinding]) -> None:
    import dataclasses
    print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2))


def write_csv(findings: list[SgFinding], path: str) -> None:
    import dataclasses
    if not findings:
        return
    rows = [dataclasses.asdict(f) for f in findings]
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"CSV written to {path}")
