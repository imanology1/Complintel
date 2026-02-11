#!/usr/bin/env python3
"""
AWS S3 Encryption Check Agent
Verifies that all S3 buckets have default server-side encryption enabled.

Required environment variables:
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_REGION (or --region parameter)

Output: JSON array of Finding objects to stdout.
"""

import json
import os
import sys

def main():
    findings = []

    region = os.environ.get("AWS_REGION", "us-east-1")

    # Parse --region from args if provided
    for arg in sys.argv[1:]:
        if arg.startswith("--region="):
            region = arg.split("=", 1)[1]

    try:
        import boto3
        session = boto3.Session(region_name=region)
        s3 = session.client("s3")

        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "PASS",
                        "message": f"Bucket has default encryption enabled",
                        "details": json.dumps(rules[0])
                    })
                else:
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "FAIL",
                        "message": "Bucket has encryption configuration but no rules defined"
                    })
            except s3.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "FAIL",
                        "message": "Bucket does NOT have default encryption enabled"
                    })
                else:
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "ERROR",
                        "message": f"Could not check encryption: {error_code}",
                        "details": str(e)
                    })

    except ImportError:
        findings.append({
            "resource_id": "boto3-dependency",
            "resource_type": "AWS::S3::Bucket",
            "status": "ERROR",
            "message": "boto3 library is not installed. Run: pip install boto3"
        })
    except Exception as e:
        findings.append({
            "resource_id": "aws-s3-encryption-check",
            "resource_type": "AWS::S3::Bucket",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)

if __name__ == "__main__":
    main()
