#!/usr/bin/env python3
"""
AWS Security Group SSH Open Access Check
Identifies security groups that allow unrestricted inbound SSH access (port 22)
from 0.0.0.0/0 or ::/0.

Required environment variables:
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_REGION (or --region parameter)

Output: JSON array of Finding objects to stdout.
"""

import json
import os
import sys


def parse_args(argv):
    """Parse command-line arguments."""
    region = os.environ.get("AWS_REGION", "us-east-1")

    i = 1
    while i < len(argv):
        if argv[i] == "--region" and i + 1 < len(argv):
            region = argv[i + 1]
            i += 2
        elif argv[i].startswith("--region="):
            region = argv[i].split("=", 1)[1]
            i += 1
        else:
            i += 1

    return region


def is_port_open_to_world(security_group, port):
    """Check if a specific port in a security group is open to 0.0.0.0/0 or ::/0."""
    open_cidrs = []

    for rule in security_group.get("IpPermissions", []):
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 0)
        ip_protocol = rule.get("IpProtocol", "")

        # Check if rule covers the target port
        # IpProtocol "-1" means all traffic
        port_match = (
            ip_protocol == "-1"
            or (from_port <= port <= to_port)
        )

        if not port_match:
            continue

        # Check IPv4 ranges
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                open_cidrs.append(cidr)

        # Check IPv6 ranges
        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6", "")
            if cidr == "::/0":
                open_cidrs.append(cidr)

    return open_cidrs


def main():
    findings = []
    region = parse_args(sys.argv)

    try:
        import boto3
    except ImportError:
        findings.append({
            "resource_id": "boto3-dependency",
            "resource_type": "AWS::EC2::SecurityGroup",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        ec2 = session.client("ec2")

        paginator = ec2.get_paginator("describe_security_groups")
        security_groups = []
        for page in paginator.paginate():
            security_groups.extend(page.get("SecurityGroups", []))

        if not security_groups:
            findings.append({
                "resource_id": "sg-ssh-check",
                "resource_type": "AWS::EC2::SecurityGroup",
                "status": "PASS",
                "message": "No security groups found in region"
            })
            json.dump(findings, sys.stdout, indent=2)
            return

        for sg in security_groups:
            sg_id = sg.get("GroupId", "unknown")
            sg_name = sg.get("GroupName", "unknown")
            vpc_id = sg.get("VpcId", "N/A")

            open_cidrs = is_port_open_to_world(sg, 22)

            if open_cidrs:
                findings.append({
                    "resource_id": sg_id,
                    "resource_type": "AWS::EC2::SecurityGroup",
                    "status": "FAIL",
                    "message": (
                        f"Security group '{sg_name}' ({sg_id}) allows SSH (port 22) "
                        f"from {', '.join(open_cidrs)}"
                    ),
                    "details": json.dumps({
                        "group_id": sg_id,
                        "group_name": sg_name,
                        "vpc_id": vpc_id,
                        "port": 22,
                        "open_cidrs": open_cidrs
                    })
                })
            else:
                findings.append({
                    "resource_id": sg_id,
                    "resource_type": "AWS::EC2::SecurityGroup",
                    "status": "PASS",
                    "message": f"Security group '{sg_name}' ({sg_id}) does not allow unrestricted SSH access",
                    "details": json.dumps({
                        "group_id": sg_id,
                        "group_name": sg_name,
                        "vpc_id": vpc_id,
                        "port": 22
                    })
                })

    except Exception as e:
        findings.append({
            "resource_id": "sg-ssh-check",
            "resource_type": "AWS::EC2::SecurityGroup",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
