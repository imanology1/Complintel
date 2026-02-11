#!/usr/bin/env python3
"""
GitHub Secret Scanning Check
Verifies that secret scanning (and push protection) is enabled on repositories.

Required environment variables:
  GITHUB_TOKEN  -- Personal access token with repo and admin:org scope

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
            repos = [fetch_repo(org, repo_filter, headers)]
        else:
            repos = list_repos(org, headers)

        for repo in repos:
            repo_name = repo["name"]
            full_name = f"{org}/{repo_name}"
            is_private = repo.get("visibility", "public") != "public"

            # Secret scanning
            ss_enabled = repo.get("security_and_analysis", {}) \
                             .get("secret_scanning", {}) \
                             .get("status", "disabled") == "enabled"

            if ss_enabled:
                findings.append({
                    "resource_id": full_name,
                    "resource_type": "GitHub::Repository",
                    "status": "PASS",
                    "message": "Secret scanning is enabled",
                })
            else:
                findings.append({
                    "resource_id": full_name,
                    "resource_type": "GitHub::Repository",
                    "status": "FAIL",
                    "message": "Secret scanning is NOT enabled",
                    "details": {
                        "visibility": repo.get("visibility", "unknown"),
                        "recommendation": "Enable secret scanning in repository "
                                          "Settings > Code security and analysis",
                    },
                })

            # Push protection (only meaningful when secret scanning is on)
            pp_enabled = repo.get("security_and_analysis", {}) \
                             .get("secret_scanning_push_protection", {}) \
                             .get("status", "disabled") == "enabled"

            if pp_enabled:
                findings.append({
                    "resource_id": full_name,
                    "resource_type": "GitHub::Repository",
                    "status": "PASS",
                    "message": "Secret scanning push protection is enabled",
                })
            else:
                findings.append({
                    "resource_id": full_name,
                    "resource_type": "GitHub::Repository",
                    "status": "FAIL",
                    "message": "Secret scanning push protection is NOT enabled",
                    "details": {
                        "recommendation": "Enable push protection in repository "
                                          "Settings > Code security and analysis",
                    },
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


def fetch_repo(org, repo, headers):
    """Fetch metadata for a single repository."""
    url = f"{GITHUB_API}/repos/{org}/{repo}"
    return api_get(url, headers)


if __name__ == "__main__":
    main()
