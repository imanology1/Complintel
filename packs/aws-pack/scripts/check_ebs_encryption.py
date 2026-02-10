#!/usr/bin/env python3
"""
AWS EBS Volume Encryption Check
Verifies that all EBS volumes are encrypted.

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


def main():
    findings = []
    region = parse_args(sys.argv)

    try:
        import boto3
    except ImportError:
        findings.append({
            "resource_id": "boto3-dependency",
            "resource_type": "AWS::EC2::Volume",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        ec2 = session.client("ec2")

        paginator = ec2.get_paginator("describe_volumes")
        volumes = []
        for page in paginator.paginate():
            volumes.extend(page.get("Volumes", []))

        if not volumes:
            findings.append({
                "resource_id": "ebs-encryption-check",
                "resource_type": "AWS::EC2::Volume",
                "status": "PASS",
                "message": f"No EBS volumes found in region {region}"
            })
            json.dump(findings, sys.stdout, indent=2)
            return

        for volume in volumes:
            volume_id = volume.get("VolumeId", "unknown")
            encrypted = volume.get("Encrypted", False)
            volume_type = volume.get("VolumeType", "N/A")
            size_gb = volume.get("Size", 0)
            state = volume.get("State", "N/A")
            kms_key_id = volume.get("KmsKeyId", "N/A")

            # Get attached instance info
            attachments = volume.get("Attachments", [])
            attached_instances = [
                a.get("InstanceId", "N/A") for a in attachments
            ]

            if encrypted:
                findings.append({
                    "resource_id": volume_id,
                    "resource_type": "AWS::EC2::Volume",
                    "status": "PASS",
                    "message": f"EBS volume {volume_id} is encrypted",
                    "details": json.dumps({
                        "volume_id": volume_id,
                        "encrypted": True,
                        "kms_key_id": kms_key_id,
                        "volume_type": volume_type,
                        "size_gb": size_gb,
                        "state": state,
                        "attached_instances": attached_instances
                    })
                })
            else:
                findings.append({
                    "resource_id": volume_id,
                    "resource_type": "AWS::EC2::Volume",
                    "status": "FAIL",
                    "message": f"EBS volume {volume_id} is NOT encrypted",
                    "details": json.dumps({
                        "volume_id": volume_id,
                        "encrypted": False,
                        "volume_type": volume_type,
                        "size_gb": size_gb,
                        "state": state,
                        "attached_instances": attached_instances
                    })
                })

    except Exception as e:
        findings.append({
            "resource_id": "ebs-encryption-check",
            "resource_type": "AWS::EC2::Volume",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
