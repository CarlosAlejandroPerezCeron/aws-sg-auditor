from auditor.base import AuditConfig, SecurityGroup, SgRule
from auditor.rules import (
    check_all_traffic_open,
    check_any_port_open,
    check_default_sg_rules,
    check_rdp_open,
    check_ssh_open,
    run_all,
)

CFG = AuditConfig()


def _sg(sg_id="sg-123", name="my-sg", is_default=False, inbound=None, outbound=None):
    return SecurityGroup(
        sg_id=sg_id,
        sg_name=name,
        is_default=is_default,
        inbound=inbound or [],
        outbound=outbound or [],
    )


def _rule(proto="tcp", from_port=0, to_port=65535, cidrs=None, ipv6=None):
    return SgRule(
        protocol=proto,
        from_port=from_port,
        to_port=to_port,
        cidrs=cidrs or [],
        ipv6_cidrs=ipv6 or [],
    )


# --- SG-001 SSH ---

def test_ssh_open_to_world_flagged():
    sg = _sg(inbound=[_rule("tcp", 22, 22, cidrs=["0.0.0.0/0"])])
    findings = check_ssh_open(sg, CFG)
    assert any(f.rule_id == "SG-001" and f.severity == "CRITICAL" for f in findings)


def test_ssh_open_ipv6_flagged():
    sg = _sg(inbound=[_rule("tcp", 22, 22, ipv6=["::/0"])])
    findings = check_ssh_open(sg, CFG)
    assert any(f.rule_id == "SG-001" for f in findings)


def test_ssh_restricted_ip_clean():
    sg = _sg(inbound=[_rule("tcp", 22, 22, cidrs=["10.0.0.0/8"])])
    assert check_ssh_open(sg, CFG) == []


def test_ssh_all_traffic_protocol_flagged():
    sg = _sg(inbound=[_rule("-1", 0, 65535, cidrs=["0.0.0.0/0"])])
    findings = check_ssh_open(sg, CFG)
    assert any(f.rule_id == "SG-001" for f in findings)


# --- SG-002 RDP ---

def test_rdp_open_to_world_flagged():
    sg = _sg(inbound=[_rule("tcp", 3389, 3389, cidrs=["0.0.0.0/0"])])
    findings = check_rdp_open(sg, CFG)
    assert any(f.rule_id == "SG-002" and f.severity == "CRITICAL" for f in findings)


def test_rdp_open_ipv6_flagged():
    sg = _sg(inbound=[_rule("tcp", 3389, 3389, ipv6=["::/0"])])
    findings = check_rdp_open(sg, CFG)
    assert any(f.rule_id == "SG-002" for f in findings)


def test_rdp_restricted_clean():
    sg = _sg(inbound=[_rule("tcp", 3389, 3389, cidrs=["192.168.1.0/24"])])
    assert check_rdp_open(sg, CFG) == []


# --- SG-003 All Traffic ---

def test_all_traffic_minus1_flagged():
    sg = _sg(inbound=[_rule("-1", 0, 65535, cidrs=["0.0.0.0/0"])])
    findings = check_all_traffic_open(sg, CFG)
    assert any(f.rule_id == "SG-003" and f.severity == "HIGH" for f in findings)


def test_full_port_range_tcp_flagged():
    sg = _sg(inbound=[_rule("tcp", 0, 65535, cidrs=["0.0.0.0/0"])])
    findings = check_all_traffic_open(sg, CFG)
    assert any(f.rule_id == "SG-003" for f in findings)


def test_specific_port_not_all_traffic():
    sg = _sg(inbound=[_rule("tcp", 443, 443, cidrs=["0.0.0.0/0"])])
    assert check_all_traffic_open(sg, CFG) == []


def test_all_traffic_restricted_cidr_clean():
    sg = _sg(inbound=[_rule("-1", 0, 65535, cidrs=["10.0.0.0/8"])])
    assert check_all_traffic_open(sg, CFG) == []


# --- SG-004 Any Port Open ---

def test_http_open_flagged():
    sg = _sg(inbound=[_rule("tcp", 80, 80, cidrs=["0.0.0.0/0"])])
    findings = check_any_port_open(sg, CFG)
    assert any(f.rule_id == "SG-004" for f in findings)


def test_https_open_flagged():
    sg = _sg(inbound=[_rule("tcp", 443, 443, cidrs=["0.0.0.0/0"])])
    findings = check_any_port_open(sg, CFG)
    assert any(f.rule_id == "SG-004" for f in findings)


def test_private_cidr_not_flagged():
    sg = _sg(inbound=[_rule("tcp", 443, 443, cidrs=["10.0.0.0/8"])])
    assert check_any_port_open(sg, CFG) == []


# --- SG-005 Default SG ---

def test_default_sg_with_rules_flagged():
    sg = _sg(name="default", is_default=True,
             inbound=[_rule("tcp", 443, 443, cidrs=["0.0.0.0/0"])],
             outbound=[_rule("-1", 0, 65535, cidrs=["0.0.0.0/0"])])
    findings = check_default_sg_rules(sg, CFG)
    assert any(f.rule_id == "SG-005" and f.severity == "MEDIUM" for f in findings)


def test_default_sg_no_rules_clean():
    sg = _sg(name="default", is_default=True)
    assert check_default_sg_rules(sg, CFG) == []


def test_non_default_sg_with_rules_not_flagged():
    sg = _sg(name="web-sg", is_default=False,
             inbound=[_rule("tcp", 443, 443, cidrs=["0.0.0.0/0"])])
    assert check_default_sg_rules(sg, CFG) == []


# --- run_all ---

def test_run_all_clean_sg():
    sg = _sg()
    assert run_all([sg], CFG) == []


def test_run_all_severity_order():
    sg = _sg(inbound=[
        _rule("tcp", 22, 22, cidrs=["0.0.0.0/0"]),
        _rule("tcp", 443, 443, cidrs=["0.0.0.0/0"]),
    ])
    findings = run_all([sg], CFG)
    from auditor.base import SEVERITY_ORDER
    sevs = [f.severity for f in findings]
    assert sevs == sorted(sevs, key=lambda s: SEVERITY_ORDER.get(s, 99))


def test_run_all_empty():
    assert run_all([], CFG) == []


def test_multiple_sgs_findings_per_sg():
    sg1 = _sg("sg-a", inbound=[_rule("tcp", 22, 22, cidrs=["0.0.0.0/0"])])
    sg2 = _sg("sg-b", inbound=[_rule("tcp", 3389, 3389, cidrs=["0.0.0.0/0"])])
    findings = run_all([sg1, sg2], CFG)
    sg_ids = {f.sg_id for f in findings}
    assert "sg-a" in sg_ids and "sg-b" in sg_ids
