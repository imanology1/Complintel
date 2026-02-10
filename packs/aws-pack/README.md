# AWS Agent Pack

Compliance checks for Amazon Web Services infrastructure.

## Checks

| ID | Description | Severity | Frameworks |
|----|-------------|----------|------------|
| `s3-encryption` | Verify all S3 buckets have default encryption enabled | High | SOC2, NIST-800-53, CIS-AWS |
| `s3-public-access` | Verify S3 buckets do not allow public access | Critical | SOC2, PCI-DSS, CIS-AWS |

## Prerequisites

- Python 3.6+
- `boto3` library: `pip install boto3`

## Required Credentials

Set the following environment variables (or configure in `config.yaml` under `credentials`):

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `AWS_REGION` | AWS region (default: `us-east-1`) |

Alternatively, configure an AWS profile and set `AWS_PROFILE`.

## Example Findings

```json
[
  {
    "resource_id": "my-secure-bucket",
    "resource_type": "AWS::S3::Bucket",
    "status": "PASS",
    "message": "Bucket has default encryption enabled"
  },
  {
    "resource_id": "my-open-bucket",
    "resource_type": "AWS::S3::Bucket",
    "status": "FAIL",
    "message": "Bucket does NOT have default encryption enabled"
  }
]
```
