#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# check_image_vulnerabilities.sh
# Check for containers running images with known vulnerabilities
# Frameworks: CIS-Docker-4.1, NIST-SI-2, PCI-DSS-6.2, SOC2-CC7.1
###############################################################################

findings="[]"

add_finding() {
  local resource_id="$1"
  local resource_type="$2"
  local status="$3"
  local message="$4"
  findings=$(printf '%s' "$findings" | jq -c \
    --arg rid "$resource_id" \
    --arg rt "$resource_type" \
    --arg s "$status" \
    --arg m "$message" \
    '. + [{"resource_id": $rid, "resource_type": $rt, "status": $s, "message": $m}]')
}

# Check if docker CLI is available
if ! command -v docker &>/dev/null; then
  add_finding "docker-cli" "image" "ERROR" "Docker CLI is not installed or not in PATH"
  printf '%s\n' "$findings"
  exit 0
fi

# Check if Docker daemon is running
if ! docker info &>/dev/null; then
  add_finding "docker-daemon" "image" "ERROR" "Docker daemon is not running or not accessible"
  printf '%s\n' "$findings"
  exit 0
fi

# Determine available scanner
scanner="none"
if command -v docker &>/dev/null && docker scout version &>/dev/null 2>&1; then
  scanner="scout"
elif command -v trivy &>/dev/null; then
  scanner="trivy"
elif command -v grype &>/dev/null; then
  scanner="grype"
fi

# Get list of running containers and their images
container_ids=$(docker ps -q 2>/dev/null || true)

if [[ -z "$container_ids" ]]; then
  add_finding "no-containers" "image" "PASS" "No running containers found"
  printf '%s\n' "$findings"
  exit 0
fi

# Collect unique images from running containers
declare -A checked_images

for cid in $container_ids; do
  container_name=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||' || echo "$cid")
  image=$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null || echo "unknown")
  image_id=$(docker inspect --format '{{.Image}}' "$cid" 2>/dev/null || echo "unknown")
  resource_id="${container_name}(${cid:0:12})"

  # ---- Check 1: Image tag ----
  if [[ "$image" == *":latest" || "$image" != *":"* ]]; then
    add_finding "$resource_id" "image" "FAIL" "Container uses 'latest' or untagged image '$image'; pin to a specific version"
  else
    add_finding "$resource_id" "image" "PASS" "Container uses a pinned image tag: $image"
  fi

  # ---- Check 2: Image age / creation date ----
  created=$(docker inspect --format '{{.Created}}' "$image_id" 2>/dev/null || echo "")
  if [[ -n "$created" ]]; then
    created_epoch=$(date -d "$created" +%s 2>/dev/null || echo "0")
    now_epoch=$(date +%s)
    age_days=$(( (now_epoch - created_epoch) / 86400 ))
    if [[ "$age_days" -gt 90 ]]; then
      add_finding "$resource_id" "image" "FAIL" "Image '$image' is $age_days days old (>90 days); consider rebuilding with updated base"
    elif [[ "$age_days" -gt 30 ]]; then
      add_finding "$resource_id" "image" "FAIL" "Image '$image' is $age_days days old (>30 days); review for updates"
    else
      add_finding "$resource_id" "image" "PASS" "Image '$image' is $age_days days old (within acceptable age)"
    fi
  fi

  # ---- Check 3: Image digest pinning ----
  repo_digests=$(docker inspect --format '{{json .RepoDigests}}' "$image_id" 2>/dev/null || echo "null")
  if [[ "$repo_digests" == "null" || "$repo_digests" == "[]" ]]; then
    add_finding "$resource_id" "image" "FAIL" "Image '$image' has no repo digest; it may be a locally-built image without verification"
  else
    add_finding "$resource_id" "image" "PASS" "Image '$image' has repo digest(s) for provenance verification"
  fi

  # ---- Check 4: Vulnerability scan (if scanner available) ----
  # Only scan each unique image once
  if [[ -z "${checked_images[$image]:-}" ]]; then
    checked_images[$image]=1

    case "$scanner" in
      trivy)
        vuln_output=$(trivy image --severity HIGH,CRITICAL --format json --quiet "$image" 2>/dev/null || echo "")
        if [[ -n "$vuln_output" ]]; then
          high_count=$(printf '%s' "$vuln_output" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' 2>/dev/null || echo "0")
          critical_count=$(printf '%s' "$vuln_output" | jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' 2>/dev/null || echo "0")
          if [[ "$critical_count" -gt 0 || "$high_count" -gt 0 ]]; then
            add_finding "$resource_id" "image" "FAIL" "Image '$image' has $critical_count CRITICAL and $high_count HIGH vulnerabilities (trivy)"
          else
            add_finding "$resource_id" "image" "PASS" "Image '$image' has no HIGH/CRITICAL vulnerabilities (trivy)"
          fi
        fi
        ;;
      grype)
        vuln_output=$(grype "$image" -o json --only-fixed 2>/dev/null || echo "")
        if [[ -n "$vuln_output" ]]; then
          high_count=$(printf '%s' "$vuln_output" | jq '[.matches[]? | select(.vulnerability.severity == "High")] | length' 2>/dev/null || echo "0")
          critical_count=$(printf '%s' "$vuln_output" | jq '[.matches[]? | select(.vulnerability.severity == "Critical")] | length' 2>/dev/null || echo "0")
          if [[ "$critical_count" -gt 0 || "$high_count" -gt 0 ]]; then
            add_finding "$resource_id" "image" "FAIL" "Image '$image' has $critical_count CRITICAL and $high_count HIGH fixable vulnerabilities (grype)"
          else
            add_finding "$resource_id" "image" "PASS" "Image '$image' has no HIGH/CRITICAL fixable vulnerabilities (grype)"
          fi
        fi
        ;;
      scout)
        vuln_output=$(docker scout cves "$image" --format json --only-severity critical,high 2>/dev/null || echo "")
        if [[ -n "$vuln_output" ]]; then
          vuln_count=$(printf '%s' "$vuln_output" | jq '.vulnerabilities | length' 2>/dev/null || echo "0")
          if [[ "$vuln_count" -gt 0 ]]; then
            add_finding "$resource_id" "image" "FAIL" "Image '$image' has $vuln_count HIGH/CRITICAL vulnerabilities (docker scout)"
          else
            add_finding "$resource_id" "image" "PASS" "Image '$image' has no HIGH/CRITICAL vulnerabilities (docker scout)"
          fi
        fi
        ;;
      none)
        add_finding "$resource_id" "image" "ERROR" "No vulnerability scanner found (install trivy, grype, or docker scout for full scanning)"
        ;;
    esac
  fi

  # ---- Check 5: Image has HEALTHCHECK defined ----
  healthcheck=$(docker inspect --format '{{json .Config.Healthcheck}}' "$cid" 2>/dev/null || echo "null")
  if [[ "$healthcheck" == "null" || "$healthcheck" == "{}" ]]; then
    add_finding "$resource_id" "image" "FAIL" "Container has no HEALTHCHECK defined in its image"
  else
    add_finding "$resource_id" "image" "PASS" "Container has a HEALTHCHECK defined"
  fi
done

printf '%s\n' "$findings"
