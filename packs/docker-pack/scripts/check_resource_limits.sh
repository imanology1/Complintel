#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# check_resource_limits.sh
# Verify containers have CPU and memory limits set
# Frameworks: CIS-Docker-5.10, NIST-SC-6, SOC2-A1.2
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
  add_finding "docker-cli" "container" "ERROR" "Docker CLI is not installed or not in PATH"
  printf '%s\n' "$findings"
  exit 0
fi

# Check if Docker daemon is running
if ! docker info &>/dev/null; then
  add_finding "docker-daemon" "container" "ERROR" "Docker daemon is not running or not accessible"
  printf '%s\n' "$findings"
  exit 0
fi

# Get list of running containers
container_ids=$(docker ps -q 2>/dev/null || true)

if [[ -z "$container_ids" ]]; then
  add_finding "no-containers" "container" "PASS" "No running containers found"
  printf '%s\n' "$findings"
  exit 0
fi

for cid in $container_ids; do
  container_name=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||' || echo "$cid")
  resource_id="${container_name}(${cid:0:12})"

  # ---- Check 1: Memory limit ----
  memory_limit=$(docker inspect --format '{{.HostConfig.Memory}}' "$cid" 2>/dev/null || echo "0")
  if [[ "$memory_limit" -eq 0 ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container has no memory limit set (unlimited)"
  else
    mem_mb=$((memory_limit / 1024 / 1024))
    add_finding "$resource_id" "container" "PASS" "Container has memory limit set: ${mem_mb}MB"
  fi

  # ---- Check 2: Memory reservation (soft limit) ----
  memory_reservation=$(docker inspect --format '{{.HostConfig.MemoryReservation}}' "$cid" 2>/dev/null || echo "0")
  if [[ "$memory_reservation" -eq 0 ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container has no memory reservation (soft limit) set"
  else
    res_mb=$((memory_reservation / 1024 / 1024))
    add_finding "$resource_id" "container" "PASS" "Container has memory reservation set: ${res_mb}MB"
  fi

  # ---- Check 3: CPU limit (NanoCPUs or CpuQuota) ----
  nano_cpus=$(docker inspect --format '{{.HostConfig.NanoCPUs}}' "$cid" 2>/dev/null || echo "0")
  cpu_quota=$(docker inspect --format '{{.HostConfig.CpuQuota}}' "$cid" 2>/dev/null || echo "0")
  cpu_period=$(docker inspect --format '{{.HostConfig.CpuPeriod}}' "$cid" 2>/dev/null || echo "0")
  cpus_set=$(docker inspect --format '{{.HostConfig.CpusetCpus}}' "$cid" 2>/dev/null || echo "")

  if [[ "$nano_cpus" -gt 0 ]]; then
    cpu_val=$(awk "BEGIN {printf \"%.2f\", $nano_cpus / 1000000000}")
    add_finding "$resource_id" "container" "PASS" "Container has CPU limit set: ${cpu_val} CPUs (NanoCPUs)"
  elif [[ "$cpu_quota" -gt 0 && "$cpu_period" -gt 0 ]]; then
    cpu_val=$(awk "BEGIN {printf \"%.2f\", $cpu_quota / $cpu_period}")
    add_finding "$resource_id" "container" "PASS" "Container has CPU limit set: ${cpu_val} CPUs (CpuQuota/CpuPeriod)"
  elif [[ -n "$cpus_set" ]]; then
    add_finding "$resource_id" "container" "PASS" "Container is pinned to specific CPUs: $cpus_set"
  else
    add_finding "$resource_id" "container" "FAIL" "Container has no CPU limit set (unlimited)"
  fi

  # ---- Check 4: CPU shares (relative weight) ----
  cpu_shares=$(docker inspect --format '{{.HostConfig.CpuShares}}' "$cid" 2>/dev/null || echo "0")
  if [[ "$cpu_shares" -eq 0 || "$cpu_shares" -eq 1024 ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container uses default CPU shares (1024); consider tuning for relative priority"
  else
    add_finding "$resource_id" "container" "PASS" "Container has custom CPU shares: $cpu_shares"
  fi

  # ---- Check 5: PIDs limit ----
  pids_limit=$(docker inspect --format '{{.HostConfig.PidsLimit}}' "$cid" 2>/dev/null || echo "0")
  # PidsLimit of -1 or 0 means unlimited
  if [[ "$pids_limit" -le 0 ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container has no PIDs limit (fork bomb risk)"
  else
    add_finding "$resource_id" "container" "PASS" "Container has PIDs limit set: $pids_limit"
  fi

  # ---- Check 6: Restart policy ----
  restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$cid" 2>/dev/null || echo "")
  max_retry=$(docker inspect --format '{{.HostConfig.RestartPolicy.MaximumRetryCount}}' "$cid" 2>/dev/null || echo "0")
  if [[ "$restart_policy" == "always" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container uses restart policy 'always'; prefer 'on-failure' with max retries to prevent infinite loops"
  elif [[ "$restart_policy" == "on-failure" && "$max_retry" -eq 0 ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container uses restart policy 'on-failure' without max retry count"
  elif [[ "$restart_policy" == "on-failure" && "$max_retry" -gt 0 ]]; then
    add_finding "$resource_id" "container" "PASS" "Container uses restart policy 'on-failure' with max retries: $max_retry"
  elif [[ "$restart_policy" == "unless-stopped" ]]; then
    add_finding "$resource_id" "container" "PASS" "Container uses restart policy 'unless-stopped'"
  elif [[ -z "$restart_policy" || "$restart_policy" == "no" ]]; then
    add_finding "$resource_id" "container" "PASS" "Container uses restart policy 'no' (will not auto-restart)"
  fi

  # ---- Check 7: OOM kill disabled ----
  oom_kill_disable=$(docker inspect --format '{{.HostConfig.OomKillDisable}}' "$cid" 2>/dev/null || echo "false")
  if [[ "$oom_kill_disable" == "true" ]]; then
    if [[ "$memory_limit" -eq 0 ]]; then
      add_finding "$resource_id" "container" "FAIL" "Container has OOM killer disabled without a memory limit; this can exhaust host memory"
    else
      add_finding "$resource_id" "container" "PASS" "Container has OOM killer disabled but has a memory limit set"
    fi
  else
    add_finding "$resource_id" "container" "PASS" "Container OOM killer is enabled"
  fi
done

printf '%s\n' "$findings"
