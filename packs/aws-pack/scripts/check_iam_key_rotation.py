#!/usr/bin/env python3
"""
AWS IAM Access Key Rotation Check
Verifies that IAM access keys are not older than a specified number of days.

Required environment variables:
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_REGION (or --region parameter)

Parameters:
  --region        AWS region
  --max_age_days  Maximum allowed age for access keys in days (default: 90)

Output: JSON array of Finding objects to stdout.
"""

import json
import os
import sys
from datetime import datetime, timezone


def parse_args(argv):
    """Parse command-line arguments."""
    region = os.environ.get("AWS_REGION", "us-east-1")
    max_age_days = 90

    i = 1
    while i < len(argv):
        if argv[i] == "--region" and i + 1 < len(argv):
            region = argv[i + 1]
            i += 2
        elif argv[i].startswith("--region="):
            region = argv[i].split("=", 1)[1]
            i += 1
        elif argv[i] == "--max_age_days" and i + 1 < len(argv):
            max_age_days = int(argv[i + 1])
            i += 2
        elif argv[i].startswith("--max_age_days="):
            max_age_days = int(argv[i].split("=", 1)[1])
            i += 1
        else:
            i += 1

    return region, max_age_days


def main():
    findings = []
    region, max_age_days = parse_args(sys.argv)

    try:
        import boto3
    except ImportError:
        findings.append({
            "resource_id": "boto3-dependency",
            "resource_type": "AWS::IAM::AccessKey",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        iam = session.client("iam")
        now = datetime.now(timezone.utc)

        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))

        if not users:
            findings.append({
                "resource_id": "iam-key-rotation-check",
                "resource_type": "AWS::IAM::AccessKey",
                "status": "PASS",
                "message": "No IAM users found in account"
            })
            json.dump(findings, sys.stdout, indent=2)
            return

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]

            try:
                keys_response = iam.list_access_keys(UserName=username)
                access_keys = keys_response.get("AccessKeyMetadata", [])

                if not access_keys:
                    findings.append({
                        "resource_id": user_arn,
                        "resource_type": "AWS::IAM::AccessKey",
                        "status": "PASS",
                        "message": f"User '{username}' has no access keys",
                        "details": json.dumps({
                            "user_name": username,
                            "access_key_count": 0
                        })
                    })
                    continue

                for key in access_keys:
                    access_key_id = key["AccessKeyId"]
                    key_status = key["Status"]
                    create_date = key.get("CreateDate")

                    if create_date is None:
                        findings.append({
                            "resource_id": access_key_id,
                            "resource_type": "AWS::IAM::AccessKey",
                            "status": "ERROR",
                            "message": f"Access key for user '{username}' has no CreateDate",
                            "details": json.dumps({
                                "user_name": username,
                                "access_key_id": access_key_id,
                                "key_status": key_status
                            })
                        })
                        continue

                    age_days = (now - create_date).days

                    if key_status != "Active":
                        findings.append({
                            "resource_id": access_key_id,
                            "resource_type": "AWS::IAM::AccessKey",
                            "status": "PASS",
                            "message": (
                                f"Access key for user '{username}' is inactive "
                                f"(age: {age_days} days)"
                            ),
                            "details": json.dumps({
                                "user_name": username,
                                "access_key_id": access_key_id,
                                "key_status": key_status,
                                "age_days": age_days,
                                "max_age_days": max_age_days,
                                "create_date": create_date.isoformat()
                            })
                        })
                        continue

                    if age_days > max_age_days:
                        findings.append({
                            "resource_id": access_key_id,
                            "resource_type": "AWS::IAM::AccessKey",
                            "status": "FAIL",
                            "message": (
                                f"Access key for user '{username}' is {age_days} days old "
                                f"(threshold: {max_age_days} days) and needs rotation"
                            ),
                            "details": json.dumps({
                                "user_name": username,
                                "access_key_id": access_key_id,
                                "key_status": key_status,
                                "age_days": age_days,
                                "max_age_days": max_age_days,
                                "create_date": create_date.isoformat()
                            })
                        })
                    else:
                        findings.append({
                            "resource_id": access_key_id,
                            "resource_type": "AWS::IAM::AccessKey",
                            "status": "PASS",
                            "message": (
                                f"Access key for user '{username}' is {age_days} days old "
                                f"(within {max_age_days}-day threshold)"
                            ),
                            "details": json.dumps({
                                "user_name": username,
                                "access_key_id": access_key_id,
                                "key_status": key_status,
                                "age_days": age_days,
                                "max_age_days": max_age_days,
                                "create_date": create_date.isoformat()
                            })
                        })

            except Exception as e:
                findings.append({
                    "resource_id": user_arn,
                    "resource_type": "AWS::IAM::AccessKey",
                    "status": "ERROR",
                    "message": f"Could not check access keys for user '{username}': {str(e)}"
                })

    except Exception as e:
        findings.append({
            "resource_id": "iam-key-rotation-check",
            "resource_type": "AWS::IAM::AccessKey",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
