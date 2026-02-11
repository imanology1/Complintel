#!/usr/bin/env python3
"""
GitHub Branch Protection Check Agent
Verifies that repositories have branch protection rules on their default branch.

Required environment variables:
  GITHUB_TOKEN  — Personal access token with repo scope

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
            "message": "GITHUB_TOKEN environment variable is not set"
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
            "message": "The 'org' parameter is required"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "comply-intel-agent"
    }

    try:
        if repo_filter:
            repos = [{"name": repo_filter, "default_branch": get_default_branch(org, repo_filter, headers)}]
        else:
            repos = list_repos(org, headers)

        for repo_info in repos:
            repo_name = repo_info["name"]
            default_branch = repo_info.get("default_branch", "main")
            full_name = f"{org}/{repo_name}"

            try:
                protection = get_branch_protection(org, repo_name, default_branch, headers)
                checks = evaluate_protection(full_name, default_branch, protection)
                findings.extend(checks)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    findings.append({
                        "resource_id": f"{full_name}:{default_branch}",
                        "resource_type": "GitHub::BranchProtection",
                        "status": "FAIL",
                        "message": f"No branch protection rules on '{default_branch}'"
                    })
                else:
                    findings.append({
                        "resource_id": f"{full_name}:{default_branch}",
                        "resource_type": "GitHub::BranchProtection",
                        "status": "ERROR",
                        "message": f"API error {e.code}: {e.reason}"
                    })

    except Exception as e:
        findings.append({
            "resource_id": org,
            "resource_type": "GitHub::Organization",
            "status": "ERROR",
            "message": f"Unexpected error: {str(e)}"
        })

    json.dump(findings, sys.stdout, indent=2)


def api_get(url, headers):
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def list_repos(org, headers):
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


def get_default_branch(org, repo, headers):
    url = f"{GITHUB_API}/repos/{org}/{repo}"
    data = api_get(url, headers)
    return data.get("default_branch", "main")


def get_branch_protection(org, repo, branch, headers):
    url = f"{GITHUB_API}/repos/{org}/{repo}/branches/{branch}/protection"
    return api_get(url, headers)


def evaluate_protection(full_name, branch, protection):
    findings = []
    resource_base = f"{full_name}:{branch}"

    # Check: Require pull request reviews
    pr_reviews = protection.get("required_pull_request_reviews")
    if pr_reviews:
        count = pr_reviews.get("required_approving_review_count", 0)
        findings.append({
            "resource_id": resource_base,
            "resource_type": "GitHub::BranchProtection",
            "status": "PASS" if count >= 1 else "FAIL",
            "message": f"Required approving reviews: {count}"
        })
    else:
        findings.append({
            "resource_id": resource_base,
            "resource_type": "GitHub::BranchProtection",
            "status": "FAIL",
            "message": "Pull request reviews are NOT required"
        })

    # Check: Require status checks
    status_checks = protection.get("required_status_checks")
    if status_checks and status_checks.get("strict", False):
        findings.append({
            "resource_id": resource_base,
            "resource_type": "GitHub::BranchProtection",
            "status": "PASS",
            "message": "Status checks are required and must be up-to-date"
        })
    else:
        findings.append({
            "resource_id": resource_base,
            "resource_type": "GitHub::BranchProtection",
            "status": "FAIL",
            "message": "Strict status checks are NOT enforced"
        })

    # Check: No force push
    allow_force = protection.get("allow_force_pushes", {}).get("enabled", False)
    findings.append({
        "resource_id": resource_base,
        "resource_type": "GitHub::BranchProtection",
        "status": "PASS" if not allow_force else "FAIL",
        "message": "Force push is disabled" if not allow_force else "Force push is ALLOWED"
    })

    # Check: No deletions
    allow_delete = protection.get("allow_deletions", {}).get("enabled", False)
    findings.append({
        "resource_id": resource_base,
        "resource_type": "GitHub::BranchProtection",
        "status": "PASS" if not allow_delete else "FAIL",
        "message": "Branch deletion is prevented" if not allow_delete else "Branch deletion is ALLOWED"
    })

    return findings


if __name__ == "__main__":
    main()
