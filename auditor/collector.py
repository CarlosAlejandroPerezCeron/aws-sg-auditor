import boto3
from dataclasses import dataclass, field
from typing import List, Dict, Set
from .base import AuditConfig


@dataclass
class ClusterData:
    security_groups: List[Dict] = field(default_factory=list)
    used_sg_ids: Set[str] = field(default_factory=set)


def collect(config: AuditConfig) -> ClusterData:
    session = boto3.Session(profile_name=config.profile, region_name=config.region)
    ec2 = session.client("ec2")
    data = ClusterData()

    # Fetch security groups
    filters = []
    if config.vpc_id:
        filters.append({"Name": "vpc-id", "Values": [config.vpc_id]})
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate(Filters=filters):
        data.security_groups.extend(page["SecurityGroups"])

    # Collect SG IDs referenced by network interfaces (used SGs)
    ni_paginator = ec2.get_paginator("describe_network_interfaces")
    for page in ni_paginator.paginate():
        for ni in page["NetworkInterfaces"]:
            for sg in ni.get("Groups", []):
                data.used_sg_ids.add(sg["GroupId"])

    return data
