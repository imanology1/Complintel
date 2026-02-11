#!/usr/bin/env python3
"""
GitHub Organization 2FA Enforcement Check
Verifies that two-factor authentication is required for all members of the
organization, and reports any members who do not have 2FA enabled.

Required environment variables:
  GITHUB_TOKEN  -- Personal access token with admin:org scope

Parameters:
  --org=ORG      GitHub organization name (required)

Output: JSON array of Finding objects to stdout.
"""

import json
import os
import sys
import urllib.request
import urllib.error

GITHUB_API = "https://api.github.com"


def main():
    findings = []

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        findings.append({
            "resource_id": "GITHUB_TOKEN",
            "resource_type": "GitHub::Credential",
            "status": "ERROR",
            "message": "GITHUB_TOKEN environment variable is not set",
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    org = ""

    for arg in sys.argv[1:]:
        if arg.startswith("--org="):
            org = arg.split("=", 1)[1]

    if not org:
        findings.append({
            "resource_id": "org-parameter",
            "resource_type": "GitHub::Organization",
            "status": "ERROR",
            "message": "The 'org' parameter is required",
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "comply-intel-agent",
    }

    try:
        # -----------------------------------------------------------------
        # 1. Check the org-level 2FA requirement setting
        # -----------------------------------------------------------------
        org_data = api_get(f"{GITHUB_API}/orgs/{org}", headers)
        two_factor_required = org_data.get("two_factor_requirement_enabled", False)

        if two_factor_required:
            findings.append({
                "resource_id": org,
                "resource_type": "GitHub::Organization",
                "status": "PASS",
                "message": "Two-factor authentication requirement is enforced at the organization level",
            })
        else:
            findings.append({
                "resource_id": org,
                "resource_type": "GitHub::Organization",
                "status": "FAIL",
                "message": "Two-factor authentication requirement is NOT enforced at the organization level",
                "details": {
                    "recommendation": (
                        "Enable the 'Require two-factor authentication' "
                        "setting under Organization Settings > Authentication security"
                    ),
                },
            })

        # -----------------------------------------------------------------
        # 2. List members who have NOT enabled 2FA
        # -----------------------------------------------------------------
        try:
            non_2fa_members = list_members_without_2fa(org, headers)
            if non_2fa_members:
                logins = [m.get("login", "unknown") for m in non_2fa_members]
                findings.append({
                    "resource_id": org,
                    "resource_type": "GitHub::OrganizationMembers",
                    "status": "FAIL",
                    "message": (
                        f"{len(non_2fa_members)} organization member(s) do not "
                        "have two-factor authentication enabled"
                    ),
                    "details": {
                        "members_without_2fa": logins,
                        "recommendation": (
                            "Contact these members and require them to enable "
                            "2FA on their GitHub accounts"
                        ),
                    },
                })
            else:
                findings.append({
                    "resource_id": org,
                    "resource_type": "GitHub::OrganizationMembers",
                    "status": "PASS",
                    "message": "All organization members have two-factor authentication enabled",
                })
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                findings.append({
                    "resource_id": org,
                    "resource_type": "GitHub::OrganizationMembers",
                    "status": "ERROR",
                    "message": (
                        "Unable to list members without 2FA (HTTP 403). "
                        "The token may lack the admin:org scope, or "
                        "you may not be an organization owner."
                    ),
                })
            else:
                findings.append({
                    "resource_id": org,
                    "resource_type": "GitHub::OrganizationMembers",
                    "status": "ERROR",
                    "message": f"API error {exc.code}: {exc.reason}",
                })

    except urllib.error.HTTPError as exc:
        findings.append({
            "resource_id": org,
            "resource_type": "GitHub::Organization",
            "status": "ERROR",
            "message": f"API error {exc.code}: {exc.reason}",
        })
    except Exception as exc:
        findings.append({
            "resource_id": org,
            "resource_type": "GitHub::Organization",
            "status": "ERROR",
            "message": f"Unexpected error: {str(exc)}",
        })

    json.dump(findings, sys.stdout, indent=2)


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def api_get(url, headers):
    """Perform a GET request and return the parsed JSON body."""
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def list_members_without_2fa(org, headers):
    """Return organization members who have 2FA disabled (paginated).

    Uses the ``filter=2fa_disabled`` query parameter which requires the
    authenticated user to be an organization owner.
    """
    members = []
    page = 1
    while True:
        url = (
            f"{GITHUB_API}/orgs/{org}/members"
            f"?filter=2fa_disabled&per_page=100&page={page}"
        )
        batch = api_get(url, headers)
        if not batch:
            break
        members.extend(batch)
        page += 1
        if len(batch) < 100:
            break
    return members


if __name__ == "__main__":
    main()
