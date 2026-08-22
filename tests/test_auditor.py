from auditor.base import AuditConfig
from auditor.collector import ClusterData
from auditor.rules import (
    check_default_sg_modified,
    check_ssh_rdp_open,
    check_unrestricted_egress,
    check_unrestricted_ingress,
    check_unused_sg,
    run_all,
)

CFG = AuditConfig()


def _sg(gid, gname, vpc="vpc-0001", ingress=None, egress=None):
    return {
        "GroupId": gid,
        "GroupName": gname,
        "VpcId": vpc,
        "IpPermissions": ingress or [],
        "IpPermissionsEgress": egress or [],
    }


def _rule(from_port, to_port, cidr="0.0.0.0/0", protocol="tcp"):
    return {"FromPort": from_port, "ToPort": to_port, "IpProtocol": protocol,
            "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": [], "UserIdGroupPairs": []}


def _all_traffic_rule(cidr="0.0.0.0/0"):
    """Protocol -1 = all traffic; no FromPort/ToPort."""
    return {"IpProtocol": "-1", "IpRanges": [{"CidrIp": cidr}], "Ipv6Ranges": [], "UserIdGroupPairs": []}


# --- SG-001 unrestricted ingress ---

def test_open_ingress_detected():
    sg = _sg("sg-001", "open", ingress=[_rule(0, 65535)])
    data = ClusterData(security_groups=[sg], used_sg_ids={"sg-001"})
    findings = check_unrestricted_ingress(data, CFG)
    assert any(f.rule_id == "SG-001" and f.sg_id == "sg-001" for f in findings)


def test_restricted_ingress_clean():
    sg = _sg("sg-002", "restricted", ingress=[_rule(443, 443, "10.0.0.0/8")])
    data = ClusterData(security_groups=[sg], used_sg_ids={"sg-002"})
    findings = check_unrestricted_ingress(data, CFG)
    assert not findings


# --- SG-002 unused ---

def test_unused_sg_detected():
    sg = _sg("sg-003", "orphan")
    data = ClusterData(security_groups=[sg], used_sg_ids=set())
    findings = check_unused_sg(data, CFG)
    assert any(f.rule_id == "SG-002" for f in findings)


def test_used_sg_clean():
    sg = _sg("sg-004", "attached")
    data = ClusterData(security_groups=[sg], used_sg_ids={"sg-004"})
    findings = check_unused_sg(data, CFG)
    assert not findings


def test_default_sg_excluded_from_unused():
    sg = _sg("sg-005", "default")
    data = ClusterData(security_groups=[sg], used_sg_ids=set())
    findings = check_unused_sg(data, CFG)
    assert not findings


# --- SG-003 default sg with rules ---

def test_default_sg_with_rules_detected():
    sg = _sg("sg-006", "default", ingress=[_rule(22, 22)])
    data = ClusterData(security_groups=[sg])
    findings = check_default_sg_modified(data, CFG)
    assert any(f.rule_id == "SG-003" for f in findings)


def test_default_sg_no_rules_clean():
    sg = _sg("sg-007", "default")
    data = ClusterData(security_groups=[sg])
    findings = check_default_sg_modified(data, CFG)
    assert not findings


# --- SG-004 unrestricted egress ---

def test_unrestricted_egress_detected():
    egress_rule = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
    sg = _sg("sg-009", "egress-open", egress=[egress_rule])
    data = ClusterData(security_groups=[sg])
    findings = check_unrestricted_egress(data, CFG)
    assert any(f.rule_id == "SG-004" for f in findings)


def test_restricted_egress_clean():
    egress_rule = {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
                   "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}
    sg = _sg("sg-013", "egress-restricted", egress=[egress_rule])
    data = ClusterData(security_groups=[sg])
    findings = check_unrestricted_egress(data, CFG)
    assert not findings


# --- SG-005 ssh/rdp ---

def test_ssh_open_detected():
    sg = _sg("sg-008", "jump", ingress=[_rule(22, 22)])
    data = ClusterData(security_groups=[sg])
    findings = check_ssh_rdp_open(data, CFG)
    assert any(f.rule_id == "SG-005" and "SSH" in f.title for f in findings)


def test_all_traffic_catches_ssh():
    """Protocol -1 (all traffic open) should trigger SG-005 for SSH."""
    sg = _sg("sg-014", "all-open", ingress=[_all_traffic_rule()])
    data = ClusterData(security_groups=[sg])
    findings = check_ssh_rdp_open(data, CFG)
    assert any(f.rule_id == "SG-005" for f in findings)


# --- run_all ---

def test_run_all_returns_sorted():
    sg_open = _sg("sg-010", "open", ingress=[_rule(0, 65535)])
    sg_ssh = _sg("sg-011", "ssh", ingress=[_rule(22, 22)])
    data = ClusterData(security_groups=[sg_open, sg_ssh], used_sg_ids={"sg-010", "sg-011"})
    findings = run_all(data, CFG)
    severities = [f.severity for f in findings]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    assert severities == sorted(severities, key=lambda s: order.get(s, 4))


def test_finding_fields_populated():
    sg = _sg("sg-012", "test", ingress=[_rule(22, 22)])
    data = ClusterData(security_groups=[sg], used_sg_ids={"sg-012"})
    f = check_ssh_rdp_open(data, CFG)[0]
    assert f.rule_id and f.severity and f.sg_id and f.sg_name and f.title and f.detail and f.remediation
