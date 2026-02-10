# GitHub Agent Pack

Security and compliance checks for GitHub repositories.

## Checks

| ID | Description | Severity | Frameworks |
|----|-------------|----------|------------|
| `branch-protection` | Verify default branches have protection rules (reviews, status checks, no force push) | High | SOC2, CIS-GitHub |

## Prerequisites

- Python 3.6+ (uses only standard library)

## Required Credentials

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | Personal access token with `repo` scope |

## Parameters

### branch-protection

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `org` | Yes | — | GitHub organization name |
| `repo` | No | *(all repos)* | Specific repository to check |

## Example Findings

```json
[
  {
    "resource_id": "my-org/my-repo:main",
    "resource_type": "GitHub::BranchProtection",
    "status": "PASS",
    "message": "Required approving reviews: 2"
  },
  {
    "resource_id": "my-org/my-repo:main",
    "resource_type": "GitHub::BranchProtection",
    "status": "FAIL",
    "message": "Force push is ALLOWED"
  }
]
```
