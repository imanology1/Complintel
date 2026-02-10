#!/usr/bin/env python3
"""
AWS IAM MFA Check
Verifies that all IAM users with console access (login profile) have MFA enabled.

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
        from botocore.exceptions import ClientError
    except ImportError:
        findings.append({
            "resource_id": "boto3-dependency",
            "resource_type": "AWS::IAM::User",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        iam = session.client("iam")

        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page.get("Users", []))

        if not users:
            findings.append({
                "resource_id": "iam-mfa-check",
                "resource_type": "AWS::IAM::User",
                "status": "PASS",
                "message": "No IAM users found in account"
            })
            json.dump(findings, sys.stdout, indent=2)
            return

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]

            try:
                # Check if user has a login profile (console access)
                has_console_access = False
                try:
                    iam.get_login_profile(UserName=username)
                    has_console_access = True
                except ClientError as e:
                    if e.response["Error"]["Code"] == "NoSuchEntity":
                        has_console_access = False
                    else:
                        raise

                if not has_console_access:
                    findings.append({
                        "resource_id": user_arn,
                        "resource_type": "AWS::IAM::User",
                        "status": "PASS",
                        "message": f"User '{username}' does not have console access (no login profile); MFA not required",
                        "details": json.dumps({
                            "user_name": username,
                            "has_console_access": False
                        })
                    })
                    continue

                # Check MFA devices for users with console access
                mfa_response = iam.list_mfa_devices(UserName=username)
                mfa_devices = mfa_response.get("MFADevices", [])

                if mfa_devices:
                    serial_numbers = [d["SerialNumber"] for d in mfa_devices]
                    findings.append({
                        "resource_id": user_arn,
                        "resource_type": "AWS::IAM::User",
                        "status": "PASS",
                        "message": f"User '{username}' has MFA enabled ({len(mfa_devices)} device(s))",
                        "details": json.dumps({
                            "user_name": username,
                            "has_console_access": True,
                            "mfa_device_count": len(mfa_devices),
                            "mfa_serial_numbers": serial_numbers
                        })
                    })
                else:
                    findings.append({
                        "resource_id": user_arn,
                        "resource_type": "AWS::IAM::User",
                        "status": "FAIL",
                        "message": f"User '{username}' has console access but MFA is NOT enabled",
                        "details": json.dumps({
                            "user_name": username,
                            "has_console_access": True,
                            "mfa_device_count": 0
                        })
                    })

            except Exception as e:
                findings.append({
                    "resource_id": user_arn,
                    "resource_type": "AWS::IAM::User",
                    "status": "ERROR",
                    "message": f"Could not check MFA for user '{username}': {str(e)}"
                })

    except Exception as e:
        findings.append({
            "resource_id": "iam-mfa-check",
            "resource_type": "AWS::IAM::User",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
