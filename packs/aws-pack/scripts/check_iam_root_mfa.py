#!/usr/bin/env python3
"""
AWS IAM Root Account MFA Check
Verifies that the root account has MFA enabled using the IAM account summary.

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
            "resource_type": "AWS::IAM::RootAccount",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        iam = session.client("iam")

        summary = iam.get_account_summary()
        summary_map = summary.get("SummaryMap", {})

        account_mfa_enabled = summary_map.get("AccountMFAEnabled", 0)

        if account_mfa_enabled == 1:
            findings.append({
                "resource_id": "root-account",
                "resource_type": "AWS::IAM::RootAccount",
                "status": "PASS",
                "message": "Root account has MFA enabled",
                "details": json.dumps({"AccountMFAEnabled": account_mfa_enabled})
            })
        else:
            findings.append({
                "resource_id": "root-account",
                "resource_type": "AWS::IAM::RootAccount",
                "status": "FAIL",
                "message": "Root account does NOT have MFA enabled",
                "details": json.dumps({"AccountMFAEnabled": account_mfa_enabled})
            })

    except Exception as e:
        findings.append({
            "resource_id": "root-account-mfa-check",
            "resource_type": "AWS::IAM::RootAccount",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
