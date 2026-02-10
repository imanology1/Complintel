#!/usr/bin/env python3
"""
GitHub Dependabot Alerts Check
Identifies repositories with unresolved critical or high Dependabot vulnerability
alerts.

Required environment variables:
  GITHUB_TOKEN  -- Personal access token with repo and security_events scope

Parameters:
  --org=ORG      GitHub organization name (required)
  --repo=REPO    Specific repo to check (optional; checks all org repos if empty)

Output: JSON array of Finding objects to stdout.
"""

import json
import os
import sys
import urllib.request
import urllib.error

GITHUB_API = "https://api.github.com"

# Severity levels we treat as actionable.
CRITICAL_SEVERITIES = {"critical", "high"}


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
    repo_filter = ""

    for arg in sys.argv[1:]:
        if arg.startswith("--org="):
            org = arg.split("=", 1)[1]
        elif arg.startswith("--repo="):
            repo_filter = arg.split("=", 1)[1]

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
        if repo_filter:
            repo_names = [repo_filter]
        else:
            repo_names = [r["name"] for r in list_repos(org, headers)]

        for repo_name in repo_names:
            full_name = f"{org}/{repo_name}"
            try:
                alerts = fetch_open_alerts(org, repo_name, headers)
                critical_alerts = [
                    a for a in alerts
                    if a.get("security_vulnerability", {})
                        .get("severity", "").lower() in CRITICAL_SEVERITIES
                    or a.get("security_advisory", {})
                        .get("severity", "").lower() in CRITICAL_SEVERITIES
                ]

                if not alerts:
                    findings.append({
                        "resource_id": full_name,
                        "resource_type": "GitHub::DependabotAlerts",
                        "status": "PASS",
                        "message": "No open Dependabot alerts",
                    })
                elif not critical_alerts:
                    findings.append({
                        "resource_id": full_name,
                        "resource_type": "GitHub::DependabotAlerts",
                        "status": "PASS",
                        "message": (
                            f"{len(alerts)} open Dependabot alert(s) found, "
                            "but none are critical or high severity"
                        ),
                        "details": {
                            "total_open_alerts": len(alerts),
                        },
                    })
                else:
                    by_severity = {}
                    for a in critical_alerts:
                        sev = (
                            a.get("security_vulnerability", {})
                             .get("severity", "unknown").lower()
                            or a.get("security_advisory", {})
                                .get("severity", "unknown").lower()
                        )
                        by_severity[sev] = by_severity.get(sev, 0) + 1

                    findings.append({
                        "resource_id": full_name,
                        "resource_type": "GitHub::DependabotAlerts",
                        "status": "FAIL",
                        "message": (
                            f"{len(critical_alerts)} unresolved critical/high "
                            "Dependabot alert(s)"
                        ),
                        "details": {
                            "total_open_alerts": len(alerts),
                            "critical_high_breakdown": by_severity,
                            "recommendation": "Review and remediate critical and "
                                              "high alerts in the Security tab",
                        },
                    })

            except urllib.error.HTTPError as exc:
                if exc.code == 403:
                    # Dependabot alerts may not be enabled or token lacks scope.
                    findings.append({
                        "resource_id": full_name,
                        "resource_type": "GitHub::DependabotAlerts",
                        "status": "ERROR",
                        "message": (
                            "Unable to access Dependabot alerts (HTTP 403). "
                            "Ensure Dependabot alerts are enabled and the "
                            "token has the security_events scope."
                        ),
                    })
                elif exc.code == 404:
                    findings.append({
                        "resource_id": full_name,
                        "resource_type": "GitHub::DependabotAlerts",
                        "status": "ERROR",
                        "message": (
                            "Dependabot alerts endpoint returned 404. "
                            "The feature may not be enabled for this repository."
                        ),
                    })
                else:
                    findings.append({
                        "resource_id": full_name,
                        "resource_type": "GitHub::DependabotAlerts",
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


def list_repos(org, headers):
    """Return all repositories for *org* using pagination."""
    repos = []
    page = 1
    while True:
        url = f"{GITHUB_API}/orgs/{org}/repos?per_page=100&page={page}"
        batch = api_get(url, headers)
        if not batch:
            break
        repos.extend(batch)
        page += 1
        if len(batch) < 100:
            break
    return repos


def fetch_open_alerts(org, repo, headers):
    """Return all open Dependabot alerts for a repository (paginated)."""
    alerts = []
    page = 1
    while True:
        url = (
            f"{GITHUB_API}/repos/{org}/{repo}/dependabot/alerts"
            f"?state=open&per_page=100&page={page}"
        )
        batch = api_get(url, headers)
        if not batch:
            break
        alerts.extend(batch)
        page += 1
        if len(batch) < 100:
            break
    return alerts


if __name__ == "__main__":
    main()
