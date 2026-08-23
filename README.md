# aws-sg-auditor

AWS Security Group auditor. Scans EC2 security groups and surfaces misconfigurations that increase attack surface — unrestricted ingress, SSH/RDP exposed to the internet, unused groups, and default SG violations.

## Rules

| ID     | Severity | Description                                      |
|--------|----------|--------------------------------------------------|
| SG-001 | CRITICAL | Unrestricted ingress from 0.0.0.0/0 or ::/0      |
| SG-002 | LOW      | Security group not attached to any ENI            |
| SG-003 | MEDIUM   | Default VPC security group has rules              |
| SG-004 | LOW      | Unrestricted egress to 0.0.0.0/0                 |
| SG-005 | HIGH     | SSH (22) or RDP (3389) open to the world          |

## Requirements

- Python 3.11+
- AWS credentials configured (environment, `~/.aws/credentials`, or IAM role)
- Required IAM permissions: `ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`

## Installation

```bash
pip install boto3 rich
git clone https://github.com/CarlosAlejandroPerezCeron/aws-sg-auditor.git
cd aws-sg-auditor
```

## Usage

```bash
# Scan all security groups in the default region
python main.py

# Scan a specific region with a named AWS profile
python main.py --profile prod --region eu-west-1

# Filter to a specific VPC
python main.py --vpc-id vpc-0abc123def456

# Only show HIGH and CRITICAL findings
python main.py --min-severity HIGH

# Output as JSON
python main.py --output json

# Write findings to CSV
python main.py --csv-path findings.csv

# Exit with code 1 if any CRITICAL finding is detected (useful in CI)
python main.py --fail-on-critical
```

## Options

| Flag               | Default    | Description                                      |
|--------------------|------------|--------------------------------------------------|
| `--profile`        | (default)  | AWS named profile                                |
| `--region`         | us-east-1  | AWS region to scan                               |
| `--vpc-id`         | (all VPCs) | Restrict scan to one VPC                         |
| `--min-severity`   | LOW        | Minimum severity to report (CRITICAL/HIGH/MEDIUM/LOW) |
| `--output`         | terminal   | Output format: `terminal` or `json`               |
| `--csv-path`       | (none)     | Path to write a CSV report                       |
| `--fail-on-critical` | false    | Exit 1 when CRITICAL findings exist              |

## CI Integration

```yaml
- name: Audit Security Groups
  env:
    AWS_DEFAULT_REGION: us-east-1
  run: python main.py --min-severity HIGH --fail-on-critical
```

## Running Tests

```bash
pip install pytest pytest-cov ruff moto boto3 rich
ruff check .
PYTHONPATH=. pytest tests/ -v --cov=auditor --cov=report
```

## Project Structure

```
aws-sg-auditor/
├── auditor/
│   ├── __init__.py
│   ├── base.py        # SgFinding, AuditConfig dataclasses
│   ├── collector.py   # boto3 data collection (SGs + ENIs)
│   └── rules.py       # 5 audit rules
├── report.py          # Terminal (rich), JSON, CSV output
├── main.py            # CLI entry point
├── tests/
│   ├── __init__.py
│   └── test_auditor.py  # 13 unit tests
└── .github/workflows/ci.yml
```
