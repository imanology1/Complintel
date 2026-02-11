#!/usr/bin/env python3
"""
GitHub Repository Visibility Audit
Identifies repositories with public visibility so that organizations can
verify none are unintentionally exposed.

Required environment variables:
  GITHUB_TOKEN  -- Personal access token with repo scope

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
        repos = list_repos(org, headers)

        public_repos = []
        for repo in repos:
            repo_name = repo["name"]
            full_name = f"{org}/{repo_name}"
            visibility = repo.get("visibility", "unknown")
            is_private = repo.get("private", False)
            is_fork = repo.get("fork", False)
            is_archived = repo.get("archived", False)

            if not is_private:
                public_repos.append(full_name)
                findings.append({
                    "resource_id": full_name,
                    "resource_type": "GitHub::Repository",
                    "status": "FAIL",
                    "message": f"Repository has public visibility",
                    "details": {
                        "visibility": visibility,
                        "fork": is_fork,
                        "archived": is_archived,
                        "html_url": repo.get("html_url", ""),
                        "recommendation": (
                            "Verify this repository is intentionally public. "
                            "If not, change visibility to private or internal "
                            "under Settings > Danger Zone."
                        ),
                    },
                })
            else:
                findings.append({
                    "resource_id": full_name,
                    "resource_type": "GitHub::Repository",
                    "status": "PASS",
                    "message": f"Repository visibility is {visibility}",
                })

        # Provide an org-level summary finding for quick triage.
        total = len(repos)
        public_count = len(public_repos)
        if public_count == 0:
            findings.append({
                "resource_id": org,
                "resource_type": "GitHub::Organization",
                "status": "PASS",
                "message": f"All {total} repositories are private or internal",
            })
        else:
            findings.append({
                "resource_id": org,
                "resource_type": "GitHub::Organization",
                "status": "FAIL",
                "message": (
                    f"{public_count} of {total} repositories have public visibility"
                ),
                "details": {
                    "public_repositories": public_repos,
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


if __name__ == "__main__":
    main()
