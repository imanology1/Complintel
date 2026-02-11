#!/usr/bin/env python3
"""
AWS S3 Public Access Check Agent
Verifies that S3 buckets have public access blocked.

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
                pab = s3.get_public_access_block(Bucket=bucket_name)
                config = pab.get("PublicAccessBlockConfiguration", {})

                all_blocked = (
                    config.get("BlockPublicAcls", False) and
                    config.get("IgnorePublicAcls", False) and
                    config.get("BlockPublicPolicy", False) and
                    config.get("RestrictPublicBuckets", False)
                )

                if all_blocked:
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "PASS",
                        "message": "All public access is blocked",
                        "details": json.dumps(config)
                    })
                else:
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "FAIL",
                        "message": "Public access is NOT fully blocked",
                        "details": json.dumps(config)
                    })

            except s3.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "FAIL",
                        "message": "No public access block configuration exists"
                    })
                else:
                    findings.append({
                        "resource_id": bucket_name,
                        "resource_type": "AWS::S3::Bucket",
                        "status": "ERROR",
                        "message": f"Could not check public access: {error_code}",
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
            "resource_id": "aws-s3-public-access-check",
            "resource_type": "AWS::S3::Bucket",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)

if __name__ == "__main__":
    main()
