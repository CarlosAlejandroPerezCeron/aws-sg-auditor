from __future__ import annotations

from .base import ANY_CIDR, SEVERITY_ORDER, AuditConfig, SecurityGroup, SgFinding


def _open_to_world(rule) -> bool:
    return any(c in ANY_CIDR for c in rule.cidrs + rule.ipv6_cidrs)


def _port_in_range(port: int, from_port: int, to_port: int) -> bool:
    return from_port <= port <= to_port


def check_ssh_open(sg: SecurityGroup, config: AuditConfig) -> list[SgFinding]:
    """SG-001: SSH (port 22) open to 0.0.0.0/0 or ::/0."""
    findings = []
    for rule in sg.inbound:
        is_match = (rule.protocol in ("-1", "tcp") and _open_to_world(rule)
                    and (rule.protocol == "-1" or _port_in_range(22, rule.from_port, rule.to_port)))
        if is_match:
            findings.append(SgFinding(
                rule_id="SG-001", severity="CRITICAL",
                sg_id=sg.sg_id, sg_name=sg.sg_name,
                title=f"SSH open to the world in {sg.sg_id}",
                detail=f"Port 22 is reachable from 0.0.0.0/0 or ::/0 in '{sg.sg_name}'.",
                remediation="Restrict SSH to specific IP ranges or use AWS Systems Manager Session Manager.",
            ))
            break
    return findings


def check_rdp_open(sg: SecurityGroup, config: AuditConfig) -> list[SgFinding]:
    """SG-002: RDP (port 3389) open to 0.0.0.0/0 or ::/0."""
    findings = []
    for rule in sg.inbound:
        is_match = (rule.protocol in ("-1", "tcp") and _open_to_world(rule)
                    and (rule.protocol == "-1" or _port_in_range(3389, rule.from_port, rule.to_port)))
        if is_match:
            findings.append(SgFinding(
                rule_id="SG-002", severity="CRITICAL",
                sg_id=sg.sg_id, sg_name=sg.sg_name,
                title=f"RDP open to the world in {sg.sg_id}",
                detail=f"Port 3389 is reachable from 0.0.0.0/0 or ::/0 in '{sg.sg_name}'.",
                remediation="Restrict RDP to specific IP ranges or use AWS Systems Manager Fleet Manager.",
            ))
            break
    return findings


def check_all_traffic_open(sg: SecurityGroup, config: AuditConfig) -> list[SgFinding]:
    """SG-003: All traffic allowed inbound from anywhere (protocol -1 or port range 0-65535)."""
    findings = []
    for rule in sg.inbound:
        if not _open_to_world(rule):
            continue
        is_all = rule.protocol == "-1" or (rule.from_port == 0 and rule.to_port == 65535)
        if is_all:
            findings.append(SgFinding(
                rule_id="SG-003", severity="HIGH",
                sg_id=sg.sg_id, sg_name=sg.sg_name,
                title=f"All inbound traffic allowed from anywhere in {sg.sg_id}",
                detail=(f"Protocol '{rule.protocol}' with full port range is open "
                        f"to 0.0.0.0/0/::/0 in '{sg.sg_name}'."),
                remediation="Define explicit ingress rules for required ports only. Remove wildcard allow rules.",
            ))
            break
    return findings


def check_any_port_open(sg: SecurityGroup, config: AuditConfig) -> list[SgFinding]:
    """SG-004: Any port exposed to the internet."""
    findings = []
    seen_ports: set[str] = set()
    for rule in sg.inbound:
        if not _open_to_world(rule):
            continue
        if rule.protocol == "-1":
            key = "all"
        else:
            key = f"{rule.from_port}-{rule.to_port}"
        if key in seen_ports:
            continue
        if rule.protocol == "tcp" and rule.from_port == 22 == rule.to_port:
            continue
        if rule.protocol == "tcp" and rule.from_port == 3389 == rule.to_port:
            continue
        seen_ports.add(key)
        port_desc = "all ports" if rule.protocol == "-1" else f"ports {rule.from_port}-{rule.to_port}"
        findings.append(SgFinding(
            rule_id="SG-004", severity="HIGH",
            sg_id=sg.sg_id, sg_name=sg.sg_name,
            title=f"Port(s) exposed to internet in {sg.sg_id} ({port_desc})",
            detail=f"'{sg.sg_name}' allows inbound {rule.protocol} {port_desc} from 0.0.0.0/0 or ::/0.",
            remediation="Restrict inbound rules to known source IPs or private CIDR ranges.",
        ))
    return findings


def check_default_sg_rules(sg: SecurityGroup, config: AuditConfig) -> list[SgFinding]:
    """SG-005: Default security group has inbound or outbound rules."""
    findings = []
    if sg.is_default and (sg.inbound or sg.outbound):
        findings.append(SgFinding(
            rule_id="SG-005", severity="MEDIUM",
            sg_id=sg.sg_id, sg_name=sg.sg_name,
            title=f"Default security group has active rules in {sg.sg_id}",
            detail=(f"Default SG '{sg.sg_name}' has {len(sg.inbound)} inbound "
                    f"and {len(sg.outbound)} outbound rules."),
            remediation="Remove all rules from the default SG. Assign resources to purpose-built security groups.",
        ))
    return findings


ALL_RULES = [
    check_ssh_open,
    check_rdp_open,
    check_all_traffic_open,
    check_any_port_open,
    check_default_sg_rules,
]


def run_all(groups: list[SecurityGroup], config: AuditConfig | None = None) -> list[SgFinding]:
    if config is None:
        config = AuditConfig()
    results: list[SgFinding] = []
    for sg in groups:
        for rule in ALL_RULES:
            results.extend(rule(sg, config))
    return sorted(results, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
