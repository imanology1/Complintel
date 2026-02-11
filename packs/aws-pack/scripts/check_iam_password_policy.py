#!/usr/bin/env python3
"""
AWS IAM Password Policy Check
Verifies that the IAM account password policy meets security requirements:
  - MinimumPasswordLength >= 14
  - RequireUppercaseCharacters = True
  - RequireLowercaseCharacters = True
  - RequireNumbers = True
  - RequireSymbols = True
  - MaxPasswordAge <= 90

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
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        iam = session.client("iam")

        try:
            response = iam.get_account_password_policy()
            policy = response["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                findings.append({
                    "resource_id": "iam-password-policy",
                    "resource_type": "AWS::IAM::AccountPasswordPolicy",
                    "status": "FAIL",
                    "message": "No custom password policy is configured; AWS default policy is in use"
                })
                json.dump(findings, sys.stdout, indent=2)
                return
            raise

        # Check MinimumPasswordLength >= 14
        min_length = policy.get("MinimumPasswordLength", 0)
        findings.append({
            "resource_id": "iam-password-policy-min-length",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "status": "PASS" if min_length >= 14 else "FAIL",
            "message": f"Minimum password length is {min_length} (required: >= 14)",
            "details": json.dumps({"MinimumPasswordLength": min_length})
        })

        # Check RequireUppercaseCharacters
        require_upper = policy.get("RequireUppercaseCharacters", False)
        findings.append({
            "resource_id": "iam-password-policy-uppercase",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "status": "PASS" if require_upper else "FAIL",
            "message": f"Require uppercase characters: {require_upper}",
            "details": json.dumps({"RequireUppercaseCharacters": require_upper})
        })

        # Check RequireLowercaseCharacters
        require_lower = policy.get("RequireLowercaseCharacters", False)
        findings.append({
            "resource_id": "iam-password-policy-lowercase",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "status": "PASS" if require_lower else "FAIL",
            "message": f"Require lowercase characters: {require_lower}",
            "details": json.dumps({"RequireLowercaseCharacters": require_lower})
        })

        # Check RequireNumbers
        require_numbers = policy.get("RequireNumbers", False)
        findings.append({
            "resource_id": "iam-password-policy-numbers",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "status": "PASS" if require_numbers else "FAIL",
            "message": f"Require numbers: {require_numbers}",
            "details": json.dumps({"RequireNumbers": require_numbers})
        })

        # Check RequireSymbols
        require_symbols = policy.get("RequireSymbols", False)
        findings.append({
            "resource_id": "iam-password-policy-symbols",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "status": "PASS" if require_symbols else "FAIL",
            "message": f"Require symbols: {require_symbols}",
            "details": json.dumps({"RequireSymbols": require_symbols})
        })

        # Check MaxPasswordAge <= 90
        max_age = policy.get("MaxPasswordAge", None)
        if max_age is None:
            findings.append({
                "resource_id": "iam-password-policy-max-age",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "status": "FAIL",
                "message": "Password expiration is not configured (MaxPasswordAge not set)",
                "details": json.dumps({"MaxPasswordAge": None})
            })
        else:
            findings.append({
                "resource_id": "iam-password-policy-max-age",
                "resource_type": "AWS::IAM::AccountPasswordPolicy",
                "status": "PASS" if max_age <= 90 else "FAIL",
                "message": f"Maximum password age is {max_age} days (required: <= 90)",
                "details": json.dumps({"MaxPasswordAge": max_age})
            })

    except Exception as e:
        findings.append({
            "resource_id": "iam-password-policy-check",
            "resource_type": "AWS::IAM::AccountPasswordPolicy",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
