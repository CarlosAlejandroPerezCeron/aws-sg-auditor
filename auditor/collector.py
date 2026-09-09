from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from .base import AuditConfig, SecurityGroup, SgRule


def _parse_rules(permissions: list[dict]) -> list[SgRule]:
    rules = []
    for perm in permissions:
        proto = perm.get("IpProtocol", "-1")
        from_port = perm.get("FromPort", 0)
        to_port = perm.get("ToPort", 65535)
        cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
        ipv6 = [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", [])]
        rules.append(SgRule(protocol=proto, from_port=from_port, to_port=to_port,
                            cidrs=cidrs, ipv6_cidrs=ipv6))
    return rules


def collect(config: AuditConfig) -> list[SecurityGroup]:
    session = boto3.Session(profile_name=config.profile, region_name=config.region)
    ec2 = session.client("ec2")
    try:
        kwargs: dict = {}
        if config.groups:
            kwargs["GroupIds"] = config.groups
        resp = ec2.describe_security_groups(**kwargs)
    except ClientError:
        return []

    result = []
    for sg in resp.get("SecurityGroups", []):
        result.append(SecurityGroup(
            sg_id=sg["GroupId"],
            sg_name=sg.get("GroupName", ""),
            is_default=sg.get("GroupName", "") == "default",
            inbound=_parse_rules(sg.get("IpPermissions", [])),
            outbound=_parse_rules(sg.get("IpPermissionsEgress", [])),
        ))
    return result
