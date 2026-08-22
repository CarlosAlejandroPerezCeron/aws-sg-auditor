
from .base import AuditConfig, SgFinding
from .collector import ClusterData


def check_unrestricted_ingress(data: ClusterData, config: AuditConfig) -> list[SgFinding]:
    findings = []
    for sg in data.security_groups:
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            for cidr in rule.get("IpRanges", []):
                if cidr.get("CidrIp") == "0.0.0.0/0":
                    findings.append(SgFinding(
                        rule_id="SG-001",
                        severity="CRITICAL",
                        sg_id=sg["GroupId"],
                        sg_name=sg["GroupName"],
                        vpc_id=sg.get("VpcId", ""),
                        title="Unrestricted ingress from 0.0.0.0/0",
                        detail=f"Port range {from_port}-{to_port} open to the world",
                        remediation="Restrict ingress to known CIDR blocks or security groups",
                    ))
            for cidr6 in rule.get("Ipv6Ranges", []):
                if cidr6.get("CidrIpv6") == "::/0":
                    findings.append(SgFinding(
                        rule_id="SG-001",
                        severity="CRITICAL",
                        sg_id=sg["GroupId"],
                        sg_name=sg["GroupName"],
                        vpc_id=sg.get("VpcId", ""),
                        title="Unrestricted ingress from ::/0",
                        detail=f"Port range {from_port}-{to_port} open to the world (IPv6)",
                        remediation="Restrict ingress to known CIDR blocks or security groups",
                    ))
    return findings


def check_unused_sg(data: ClusterData, config: AuditConfig) -> list[SgFinding]:
    findings = []
    for sg in data.security_groups:
        if sg["GroupName"] == "default":
            continue
        if sg["GroupId"] not in data.used_sg_ids:
            findings.append(SgFinding(
                rule_id="SG-002",
                severity="LOW",
                sg_id=sg["GroupId"],
                sg_name=sg["GroupName"],
                vpc_id=sg.get("VpcId", ""),
                title="Unused security group",
                detail="No network interfaces are attached to this security group",
                remediation="Delete unused security groups to reduce attack surface",
            ))
    return findings


def check_default_sg_modified(data: ClusterData, config: AuditConfig) -> list[SgFinding]:
    findings = []
    for sg in data.security_groups:
        if sg["GroupName"] != "default":
            continue
        has_rules = bool(sg.get("IpPermissions") or sg.get("IpPermissionsEgress"))
        if has_rules:
            findings.append(SgFinding(
                rule_id="SG-003",
                severity="MEDIUM",
                sg_id=sg["GroupId"],
                sg_name=sg["GroupName"],
                vpc_id=sg.get("VpcId", ""),
                title="Default security group has rules",
                detail="AWS recommends the default SG should not allow inbound or outbound traffic",
                remediation="Remove all rules from the default security group",
            ))
    return findings


def check_unrestricted_egress(data: ClusterData, config: AuditConfig) -> list[SgFinding]:
    findings = []
    for sg in data.security_groups:
        for rule in sg.get("IpPermissionsEgress", []):
            protocol = rule.get("IpProtocol", "")
            if protocol == "-1":
                for cidr in rule.get("IpRanges", []):
                    if cidr.get("CidrIp") == "0.0.0.0/0":
                        findings.append(SgFinding(
                            rule_id="SG-004",
                            severity="LOW",
                            sg_id=sg["GroupId"],
                            sg_name=sg["GroupName"],
                            vpc_id=sg.get("VpcId", ""),
                            title="Unrestricted egress to 0.0.0.0/0",
                            detail="All outbound traffic is allowed - increases exfiltration risk",
                            remediation="Restrict egress to required destinations and ports",
                        ))
    return findings


def check_ssh_rdp_open(data: ClusterData, config: AuditConfig) -> list[SgFinding]:
    findings = []
    sensitive_ports = {22: "SSH", 3389: "RDP"}
    for sg in data.security_groups:
        for rule in sg.get("IpPermissions", []):
            protocol = rule.get("IpProtocol", "")
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            # protocol -1 = all traffic (no FromPort/ToPort) — treat as all ports open
            all_ports = protocol == "-1"
            for port, service in sensitive_ports.items():
                port_exposed = all_ports or (from_port != -1 and from_port <= port <= to_port)
                if port_exposed:
                    for cidr in rule.get("IpRanges", []):
                        if cidr.get("CidrIp") == "0.0.0.0/0":
                            findings.append(SgFinding(
                                rule_id="SG-005",
                                severity="HIGH",
                                sg_id=sg["GroupId"],
                                sg_name=sg["GroupName"],
                                vpc_id=sg.get("VpcId", ""),
                                title=f"{service} open to the world",
                                detail=f"Port {port} ({service}) is accessible from 0.0.0.0/0",
                                remediation=f"Restrict {service} access to known IP ranges or use a bastion/SSM",
                            ))
    return findings


def run_all(data: ClusterData, config: AuditConfig) -> list[SgFinding]:
    findings: list[SgFinding] = []
    for fn in [
        check_unrestricted_ingress,
        check_unused_sg,
        check_default_sg_modified,
        check_unrestricted_egress,
        check_ssh_rdp_open,
    ]:
        findings.extend(fn(data, config))
    return sorted(findings, key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.severity, 4))
