#!/usr/bin/env python3
"""
AWS RDS Encryption Check
Verifies that all RDS instances have storage encryption enabled.

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
            "resource_type": "AWS::RDS::DBInstance",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        rds = session.client("rds")

        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))

        if not instances:
            findings.append({
                "resource_id": "rds-encryption-check",
                "resource_type": "AWS::RDS::DBInstance",
                "status": "PASS",
                "message": f"No RDS instances found in region {region}"
            })
            json.dump(findings, sys.stdout, indent=2)
            return

        for instance in instances:
            db_id = instance.get("DBInstanceIdentifier", "unknown")
            db_arn = instance.get("DBInstanceArn", db_id)
            encrypted = instance.get("StorageEncrypted", False)
            engine = instance.get("Engine", "N/A")
            instance_class = instance.get("DBInstanceClass", "N/A")
            kms_key_id = instance.get("KmsKeyId", "N/A")

            if encrypted:
                findings.append({
                    "resource_id": db_arn,
                    "resource_type": "AWS::RDS::DBInstance",
                    "status": "PASS",
                    "message": f"RDS instance '{db_id}' has storage encryption enabled",
                    "details": json.dumps({
                        "db_instance_id": db_id,
                        "storage_encrypted": True,
                        "kms_key_id": kms_key_id,
                        "engine": engine,
                        "instance_class": instance_class
                    })
                })
            else:
                findings.append({
                    "resource_id": db_arn,
                    "resource_type": "AWS::RDS::DBInstance",
                    "status": "FAIL",
                    "message": f"RDS instance '{db_id}' does NOT have storage encryption enabled",
                    "details": json.dumps({
                        "db_instance_id": db_id,
                        "storage_encrypted": False,
                        "engine": engine,
                        "instance_class": instance_class
                    })
                })

    except Exception as e:
        findings.append({
            "resource_id": "rds-encryption-check",
            "resource_type": "AWS::RDS::DBInstance",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
