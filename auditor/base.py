from dataclasses import dataclass, field

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

ANY_CIDR = {"0.0.0.0/0", "::/0"}

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "Postgres", 27017: "MongoDB"}


@dataclass
class SgFinding:
    rule_id: str
    severity: str
    sg_id: str
    sg_name: str
    title: str
    detail: str
    remediation: str


@dataclass
class AuditConfig:
    profile: str | None = None
    region: str = "us-east-1"
    groups: list[str] = field(default_factory=list)
    min_severity: str = "LOW"


@dataclass
class SgRule:
    protocol: str
    from_port: int
    to_port: int
    cidrs: list[str] = field(default_factory=list)
    ipv6_cidrs: list[str] = field(default_factory=list)


@dataclass
class SecurityGroup:
    sg_id: str
    sg_name: str
    is_default: bool
    inbound: list[SgRule] = field(default_factory=list)
    outbound: list[SgRule] = field(default_factory=list)
