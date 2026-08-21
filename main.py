import argparse
import sys
from auditor.base import AuditConfig, SEVERITY_ORDER
from auditor.collector import collect
from auditor.rules import run_all
from report import print_terminal, print_json, write_csv


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="AWS Security Group Auditor")
    p.add_argument("--profile", help="AWS profile name")
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--vpc-id", help="Limit scan to a specific VPC")
    p.add_argument("--min-severity", default="LOW", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    p.add_argument("--output", default="terminal", choices=["terminal", "json"])
    p.add_argument("--csv-path", help="Write findings to CSV")
    p.add_argument("--fail-on-critical", action="store_true", help="Exit 1 if CRITICAL findings exist")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    config = AuditConfig(
        profile=args.profile,
        region=args.region,
        vpc_id=args.vpc_id,
        min_severity=args.min_severity,
    )
    data = collect(config)
    findings = run_all(data, config)
    threshold = SEVERITY_ORDER.get(args.min_severity, 3)
    findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 4) <= threshold]

    if args.output == "json":
        print_json(findings)
    else:
        print_terminal(findings)

    if args.csv_path:
        write_csv(findings, args.csv_path)

    if args.fail_on_critical:
        if any(f.severity == "CRITICAL" for f in findings):
            sys.exit(1)


if __name__ == "__main__":
    main()
