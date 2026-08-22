from dataclasses import dataclass

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class SgFinding:
    rule_id: str
    severity: str
    sg_id: str
    sg_name: str
    vpc_id: str
    title: str
    detail: str
    remediation: str


@dataclass
class AuditConfig:
    profile: str | None = None
    region: str = "us-east-1"
    min_severity: str = "LOW"
    vpc_id: str | None = None
