# aws-sg-auditor

Audit AWS Security Groups for dangerous inbound rules: SSH/RDP open to the internet, unrestricted port ranges, all-traffic rules, and default SG misuse.

![CI](https://github.com/CarlosAlejandroPerezCeron/aws-sg-auditor/actions/workflows/ci.yml/badge.svg)

## Rules

| ID | Severity | Trigger |
|----|----------|---------|
| SG-001 | CRITICAL | SSH (port 22) open to 0.0.0.0/0 or ::/0 |
| SG-002 | CRITICAL | RDP (port 3389) open to 0.0.0.0/0 or ::/0 |
| SG-003 | HIGH | All traffic (protocol -1 or 0–65535) allowed from anywhere |
| SG-004 | HIGH | Any port exposed to the internet |
| SG-005 | MEDIUM | Default security group has inbound or outbound rules |

## Install

```bash
pip install boto3 rich
```

## Usage

```bash
python main.py
python main.py --groups sg-0abc1234 sg-0def5678 --min-severity HIGH
python main.py --output json | jq .
python main.py --csv-path findings.csv --fail-on-critical
python main.py --profile prod --region eu-west-1
```

## Dev

```bash
pip install pytest pytest-cov ruff
ruff check .
pytest tests/ -v --cov=auditor --cov=report
```

## Project structure

```
aws-sg-auditor/
├── auditor/
│   ├── __init__.py
│   ├── base.py        # dataclasses, severity map, CIDR constants
│   ├── collector.py   # boto3 EC2 — describe_security_groups
│   └── rules.py       # 5 detection rules + run_all()
├── tests/
│   └── test_auditor.py  # 21 unit tests, no AWS mocking required
├── report.py          # rich terminal table, JSON, CSV output
├── main.py            # CLI entrypoint
└── .github/workflows/ci.yml
```
