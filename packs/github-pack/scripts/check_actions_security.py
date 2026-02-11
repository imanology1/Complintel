#!/usr/bin/env python3
"""
GitHub Actions Security Check
Audits GitHub Actions workflow default permissions and the allowed-actions
policy at the organization and repository level.

Checks performed:
  1. Organization-level default workflow permissions (should be "read").
  2. Organization-level allowed-actions policy (should not be "all").
  3. Per-repository default workflow permissions (should be "read").
  4. Per-repository allowed-actions policy (should not be "all").

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

    # -----------------------------------------------------------------
    # 1. Organization-level Actions permissions
    # -----------------------------------------------------------------
    findings.extend(check_org_actions(org, headers))

    # -----------------------------------------------------------------
    # 2. Repository-level Actions permissions
    # -----------------------------------------------------------------
    try:
        if repo_filter:
            repo_names = [repo_filter]
        else:
            repo_names = [r["name"] for r in list_repos(org, headers)]

        for repo_name in repo_names:
            findings.extend(check_repo_actions(org, repo_name, headers))

    except urllib.error.HTTPError as exc:
        findings.append({
            "resource_id": org,
            "resource_type": "GitHub::Organization",
            "status": "ERROR",
            "message": f"API error listing repos: {exc.code} {exc.reason}",
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
# Check helpers
# ---------------------------------------------------------------------------

def check_org_actions(org, headers):
    """Check org-level default permissions and allowed-actions policy."""
    findings = []

    # -- Default workflow permissions --
    try:
        perms = api_get(
            f"{GITHUB_API}/orgs/{org}/actions/permissions/workflow", headers
        )
        default_perm = perms.get("default_workflow_permissions", "unknown")
        can_approve = perms.get("can_approve_pull_request_reviews", False)

        if default_perm == "read":
            findings.append({
                "resource_id": org,
                "resource_type": "GitHub::OrganizationActions",
                "status": "PASS",
                "message": "Organization default workflow permissions are set to read-only",
            })
        else:
            findings.append({
                "resource_id": org,
                "resource_type": "GitHub::OrganizationActions",
                "status": "FAIL",
                "message": (
                    f"Organization default workflow permissions are '{default_perm}' "
                    "(expected 'read')"
                ),
                "details": {
                    "default_workflow_permissions": default_perm,
                    "can_approve_pull_request_reviews": can_approve,
                    "recommendation": (
                        "Set default workflow permissions to 'Read repository "
                        "contents' under Organization Settings > Actions > General"
                    ),
                },
            })
    except urllib.error.HTTPError as exc:
        findings.append({
            "resource_id": org,
            "resource_type": "GitHub::OrganizationActions",
            "status": "ERROR",
            "message": (
                f"Unable to retrieve org workflow permissions "
                f"(HTTP {exc.code}): {exc.reason}"
            ),
        })

    # -- Allowed actions policy --
    try:
        policy = api_get(
            f"{GITHUB_API}/orgs/{org}/actions/permissions", headers
        )
        allowed = policy.get("allowed_actions", "unknown")
        enabled = policy.get("enabled_repositories", "unknown")

        if allowed == "all":
            findings.append({
                "resource_id": org,
                "resource_type": "GitHub::OrganizationActions",
                "status": "FAIL",
                "message": "Organization allows ALL GitHub Actions to run without restriction",
                "details": {
                    "allowed_actions": allowed,
                    "enabled_repositories": enabled,
                    "recommendation": (
                        "Restrict allowed actions to 'selected' or "
                        "'local-only' under Organization Settings > Actions > General"
                    ),
                },
            })
        else:
            findings.append({
                "resource_id": org,
                "resource_type": "GitHub::OrganizationActions",
                "status": "PASS",
                "message": f"Organization allowed-actions policy is '{allowed}'",
                "details": {
                    "allowed_actions": allowed,
                    "enabled_repositories": enabled,
                },
            })
    except urllib.error.HTTPError as exc:
        findings.append({
            "resource_id": org,
            "resource_type": "GitHub::OrganizationActions",
            "status": "ERROR",
            "message": (
                f"Unable to retrieve org actions policy "
                f"(HTTP {exc.code}): {exc.reason}"
            ),
        })

    return findings


def check_repo_actions(org, repo_name, headers):
    """Check repository-level default permissions and allowed-actions policy."""
    findings = []
    full_name = f"{org}/{repo_name}"

    # -- Default workflow permissions --
    try:
        perms = api_get(
            f"{GITHUB_API}/repos/{org}/{repo_name}/actions/permissions/workflow",
            headers,
        )
        default_perm = perms.get("default_workflow_permissions", "unknown")
        can_approve = perms.get("can_approve_pull_request_reviews", False)

        if default_perm == "read":
            findings.append({
                "resource_id": full_name,
                "resource_type": "GitHub::RepositoryActions",
                "status": "PASS",
                "message": "Repository default workflow permissions are set to read-only",
            })
        else:
            findings.append({
                "resource_id": full_name,
                "resource_type": "GitHub::RepositoryActions",
                "status": "FAIL",
                "message": (
                    f"Repository default workflow permissions are '{default_perm}' "
                    "(expected 'read')"
                ),
                "details": {
                    "default_workflow_permissions": default_perm,
                    "can_approve_pull_request_reviews": can_approve,
                    "recommendation": (
                        "Set default workflow permissions to 'Read repository "
                        "contents' under Repository Settings > Actions > General"
                    ),
                },
            })
    except urllib.error.HTTPError as exc:
        if exc.code == 409:
            # Actions may be disabled for this repo -- not an error per se.
            findings.append({
                "resource_id": full_name,
                "resource_type": "GitHub::RepositoryActions",
                "status": "PASS",
                "message": "GitHub Actions is disabled for this repository",
            })
        else:
            findings.append({
                "resource_id": full_name,
                "resource_type": "GitHub::RepositoryActions",
                "status": "ERROR",
                "message": (
                    f"Unable to retrieve repo workflow permissions "
                    f"(HTTP {exc.code}): {exc.reason}"
                ),
            })

    # -- Allowed actions policy --
    try:
        policy = api_get(
            f"{GITHUB_API}/repos/{org}/{repo_name}/actions/permissions",
            headers,
        )
        allowed = policy.get("allowed_actions", "unknown")
        enabled = policy.get("enabled", False)

        if not enabled:
            findings.append({
                "resource_id": full_name,
                "resource_type": "GitHub::RepositoryActions",
                "status": "PASS",
                "message": "GitHub Actions is disabled for this repository",
            })
        elif allowed == "all":
            findings.append({
                "resource_id": full_name,
                "resource_type": "GitHub::RepositoryActions",
                "status": "FAIL",
                "message": "Repository allows ALL GitHub Actions without restriction",
                "details": {
                    "allowed_actions": allowed,
                    "recommendation": (
                        "Restrict allowed actions to 'selected' or "
                        "'local-only' under Repository Settings > Actions > General"
                    ),
                },
            })
        else:
            findings.append({
                "resource_id": full_name,
                "resource_type": "GitHub::RepositoryActions",
                "status": "PASS",
                "message": f"Repository allowed-actions policy is '{allowed}'",
            })
    except urllib.error.HTTPError as exc:
        if exc.code != 409:
            findings.append({
                "resource_id": full_name,
                "resource_type": "GitHub::RepositoryActions",
                "status": "ERROR",
                "message": (
                    f"Unable to retrieve repo actions policy "
                    f"(HTTP {exc.code}): {exc.reason}"
                ),
            })

    return findings


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
