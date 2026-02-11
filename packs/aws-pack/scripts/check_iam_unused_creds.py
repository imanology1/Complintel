#!/usr/bin/env python3
"""
AWS IAM Unused Credentials Check
Identifies IAM access keys that have not been used within a specified number of days.

Required environment variables:
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_REGION (or --region parameter)

Parameters:
  --region        AWS region
  --max_age_days  Maximum number of days since last use (default: 90)

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
                "resource_id": "iam-unused-creds-check",
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

                    if key_status != "Active":
                        findings.append({
                            "resource_id": access_key_id,
                            "resource_type": "AWS::IAM::AccessKey",
                            "status": "PASS",
                            "message": f"Access key for user '{username}' is inactive",
                            "details": json.dumps({
                                "user_name": username,
                                "access_key_id": access_key_id,
                                "key_status": key_status
                            })
                        })
                        continue

                    last_used_response = iam.get_access_key_last_used(
                        AccessKeyId=access_key_id
                    )
                    last_used_info = last_used_response.get("AccessKeyLastUsed", {})
                    last_used_date = last_used_info.get("LastUsedDate")

                    if last_used_date is None:
                        # Key has never been used
                        create_date = key.get("CreateDate")
                        if create_date:
                            age_days = (now - create_date).days
                        else:
                            age_days = max_age_days + 1  # Treat as exceeded

                        if age_days > max_age_days:
                            findings.append({
                                "resource_id": access_key_id,
                                "resource_type": "AWS::IAM::AccessKey",
                                "status": "FAIL",
                                "message": (
                                    f"Access key for user '{username}' has never been used "
                                    f"and was created {age_days} days ago (threshold: {max_age_days} days)"
                                ),
                                "details": json.dumps({
                                    "user_name": username,
                                    "access_key_id": access_key_id,
                                    "last_used": "never",
                                    "created_days_ago": age_days,
                                    "max_age_days": max_age_days
                                })
                            })
                        else:
                            findings.append({
                                "resource_id": access_key_id,
                                "resource_type": "AWS::IAM::AccessKey",
                                "status": "PASS",
                                "message": (
                                    f"Access key for user '{username}' has never been used "
                                    f"but was created {age_days} days ago (within {max_age_days}-day threshold)"
                                ),
                                "details": json.dumps({
                                    "user_name": username,
                                    "access_key_id": access_key_id,
                                    "last_used": "never",
                                    "created_days_ago": age_days,
                                    "max_age_days": max_age_days
                                })
                            })
                    else:
                        days_since_use = (now - last_used_date).days

                        if days_since_use > max_age_days:
                            findings.append({
                                "resource_id": access_key_id,
                                "resource_type": "AWS::IAM::AccessKey",
                                "status": "FAIL",
                                "message": (
                                    f"Access key for user '{username}' last used {days_since_use} "
                                    f"days ago (threshold: {max_age_days} days)"
                                ),
                                "details": json.dumps({
                                    "user_name": username,
                                    "access_key_id": access_key_id,
                                    "last_used_date": last_used_date.isoformat(),
                                    "days_since_use": days_since_use,
                                    "max_age_days": max_age_days
                                })
                            })
                        else:
                            findings.append({
                                "resource_id": access_key_id,
                                "resource_type": "AWS::IAM::AccessKey",
                                "status": "PASS",
                                "message": (
                                    f"Access key for user '{username}' last used {days_since_use} "
                                    f"days ago (within {max_age_days}-day threshold)"
                                ),
                                "details": json.dumps({
                                    "user_name": username,
                                    "access_key_id": access_key_id,
                                    "last_used_date": last_used_date.isoformat(),
                                    "days_since_use": days_since_use,
                                    "max_age_days": max_age_days
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
            "resource_id": "iam-unused-creds-check",
            "resource_type": "AWS::IAM::AccessKey",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
