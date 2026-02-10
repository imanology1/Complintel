#!/usr/bin/env python3
"""
AWS CloudTrail Log File Validation Check
Verifies that CloudTrail trails have log file validation enabled.

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
            "resource_type": "AWS::CloudTrail::Trail",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        cloudtrail = session.client("cloudtrail")

        response = cloudtrail.describe_trails(includeShadowTrails=False)
        trails = response.get("trailList", [])

        if not trails:
            findings.append({
                "resource_id": "cloudtrail-validation-check",
                "resource_type": "AWS::CloudTrail::Trail",
                "status": "FAIL",
                "message": "No CloudTrail trails found in account"
            })
            json.dump(findings, sys.stdout, indent=2)
            return

        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", trail_name)
            log_file_validation = trail.get("LogFileValidationEnabled", False)

            if log_file_validation:
                findings.append({
                    "resource_id": trail_arn,
                    "resource_type": "AWS::CloudTrail::Trail",
                    "status": "PASS",
                    "message": f"Trail '{trail_name}' has log file validation enabled",
                    "details": json.dumps({
                        "trail_name": trail_name,
                        "log_file_validation_enabled": True
                    })
                })
            else:
                findings.append({
                    "resource_id": trail_arn,
                    "resource_type": "AWS::CloudTrail::Trail",
                    "status": "FAIL",
                    "message": f"Trail '{trail_name}' does NOT have log file validation enabled",
                    "details": json.dumps({
                        "trail_name": trail_name,
                        "log_file_validation_enabled": False
                    })
                })

    except Exception as e:
        findings.append({
            "resource_id": "cloudtrail-validation-check",
            "resource_type": "AWS::CloudTrail::Trail",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
