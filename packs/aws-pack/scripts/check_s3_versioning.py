#!/usr/bin/env python3
"""
AWS S3 Versioning Check
Verifies that all S3 buckets have versioning enabled.

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
            "resource_type": "AWS::S3::Bucket",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    try:
        session = boto3.Session(region_name=region)
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        if not buckets:
            findings.append({
                "resource_id": "s3-versioning-check",
                "resource_type": "AWS::S3::Bucket",
                "status": "PASS",
                "message": "No S3 buckets found in account"
            })

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                response = s3.get_bucket_versioning(Bucket=bucket_name)
                status = response.get("Status", "Disabled")

                if status == "Enabled":
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "PASS",
                        "message": "Bucket versioning is enabled",
                        "details": json.dumps({"versioning_status": status})
                    })
                else:
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "FAIL",
                        "message": f"Bucket versioning is not enabled (status: {status})",
                        "details": json.dumps({"versioning_status": status})
                    })
            except Exception as e:
                findings.append({
                    "resource_id": bucket_name,
                    "resource_type": "AWS::S3::Bucket",
                    "status": "ERROR",
                    "message": f"Could not check versioning: {str(e)}"
                })

    except Exception as e:
        findings.append({
            "resource_id": "s3-versioning-check",
            "resource_type": "AWS::S3::Bucket",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
