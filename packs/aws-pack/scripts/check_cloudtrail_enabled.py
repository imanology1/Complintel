#!/usr/bin/env python3
"""
AWS CloudTrail Enabled Check
Verifies that CloudTrail is enabled with multi-region trail and active logging.

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
                "resource_id": "cloudtrail-enabled-check",
                "resource_type": "AWS::CloudTrail::Trail",
                "status": "FAIL",
                "message": "No CloudTrail trails found in account"
            })
            json.dump(findings, sys.stdout, indent=2)
            return

        has_compliant_trail = False

        for trail in trails:
            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", trail_name)
            is_multi_region = trail.get("IsMultiRegionTrail", False)

            # Get logging status
            try:
                status_response = cloudtrail.get_trail_status(Name=trail_arn)
                is_logging = status_response.get("IsLogging", False)
            except Exception as e:
                findings.append({
                    "resource_id": trail_arn,
                    "resource_type": "AWS::CloudTrail::Trail",
                    "status": "ERROR",
                    "message": f"Could not retrieve trail status for '{trail_name}': {str(e)}"
                })
                continue

            compliant = is_multi_region and is_logging
            if compliant:
                has_compliant_trail = True

            issues = []
            if not is_multi_region:
                issues.append("multi-region is disabled")
            if not is_logging:
                issues.append("logging is disabled")

            if compliant:
                findings.append({
                    "resource_id": trail_arn,
                    "resource_type": "AWS::CloudTrail::Trail",
                    "status": "PASS",
                    "message": f"Trail '{trail_name}' is multi-region and logging is active",
                    "details": json.dumps({
                        "trail_name": trail_name,
                        "is_multi_region": is_multi_region,
                        "is_logging": is_logging,
                        "s3_bucket": trail.get("S3BucketName", "N/A")
                    })
                })
            else:
                findings.append({
                    "resource_id": trail_arn,
                    "resource_type": "AWS::CloudTrail::Trail",
                    "status": "FAIL",
                    "message": f"Trail '{trail_name}' is non-compliant: {', '.join(issues)}",
                    "details": json.dumps({
                        "trail_name": trail_name,
                        "is_multi_region": is_multi_region,
                        "is_logging": is_logging,
                        "s3_bucket": trail.get("S3BucketName", "N/A")
                    })
                })

        if not has_compliant_trail:
            findings.append({
                "resource_id": "cloudtrail-enabled-check",
                "resource_type": "AWS::CloudTrail::Trail",
                "status": "FAIL",
                "message": "No compliant multi-region trail with active logging found"
            })

    except Exception as e:
        findings.append({
            "resource_id": "cloudtrail-enabled-check",
            "resource_type": "AWS::CloudTrail::Trail",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
