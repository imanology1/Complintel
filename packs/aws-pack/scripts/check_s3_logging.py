#!/usr/bin/env python3
"""
AWS S3 Server Access Logging Check
Verifies that all S3 buckets have server access logging enabled.

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
                "resource_id": "s3-logging-check",
                "resource_type": "AWS::S3::Bucket",
                "status": "PASS",
                "message": "No S3 buckets found in account"
            })

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                response = s3.get_bucket_logging(Bucket=bucket_name)
                logging_config = response.get("LoggingEnabled")

                if logging_config:
                    target_bucket = logging_config.get("TargetBucket", "N/A")
                    target_prefix = logging_config.get("TargetPrefix", "")
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "PASS",
                        "message": f"Server access logging is enabled (target: {target_bucket}/{target_prefix})",
                        "details": json.dumps({
                            "target_bucket": target_bucket,
                            "target_prefix": target_prefix
                        })
                    })
                else:
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "FAIL",
                        "message": "Server access logging is not enabled"
                    })
            except Exception as e:
                findings.append({
                    "resource_id": bucket_name,
                    "resource_type": "AWS::S3::Bucket",
                    "status": "ERROR",
                    "message": f"Could not check logging configuration: {str(e)}"
                })

    except Exception as e:
        findings.append({
            "resource_id": "s3-logging-check",
            "resource_type": "AWS::S3::Bucket",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
