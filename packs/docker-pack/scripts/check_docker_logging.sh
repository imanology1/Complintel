#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# check_docker_logging.sh
# Verify container logging driver is configured
# Frameworks: CIS-Docker-2.12, NIST-AU-2, PCI-DSS-10.2, SOC2-CC7.2
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
  add_finding "docker-cli" "logging" "ERROR" "Docker CLI is not installed or not in PATH"
  printf '%s\n' "$findings"
  exit 0
fi

# Check if Docker daemon is running
if ! docker info &>/dev/null; then
  add_finding "docker-daemon" "logging" "ERROR" "Docker daemon is not running or not accessible"
  printf '%s\n' "$findings"
  exit 0
fi

# ---- Daemon-level logging check ----
daemon_log_driver=$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || echo "unknown")
if [[ "$daemon_log_driver" == "none" ]]; then
  add_finding "docker-daemon" "daemon" "FAIL" "Daemon default logging driver is 'none'; container logs will not be captured by default"
elif [[ "$daemon_log_driver" == "unknown" ]]; then
  add_finding "docker-daemon" "daemon" "ERROR" "Unable to determine daemon default logging driver"
else
  add_finding "docker-daemon" "daemon" "PASS" "Daemon default logging driver is '$daemon_log_driver'"
fi

# ---- Check log-opts for json-file driver (max-size, max-file) ----
daemon_json="/etc/docker/daemon.json"
if [[ -f "$daemon_json" ]]; then
  log_opts=$(jq -r '.["log-opts"] // "not-set"' "$daemon_json" 2>/dev/null || echo "not-set")
  if [[ "$log_opts" != "not-set" && "$log_opts" != "null" ]]; then
    max_size=$(printf '%s' "$log_opts" | jq -r '.["max-size"] // "not-set"' 2>/dev/null || echo "not-set")
    max_file=$(printf '%s' "$log_opts" | jq -r '.["max-file"] // "not-set"' 2>/dev/null || echo "not-set")
    if [[ "$max_size" != "not-set" ]]; then
      add_finding "docker-daemon" "daemon" "PASS" "Daemon log-opts max-size is configured: $max_size"
    else
      add_finding "docker-daemon" "daemon" "FAIL" "Daemon log-opts max-size is not configured; logs may grow unbounded"
    fi
    if [[ "$max_file" != "not-set" ]]; then
      add_finding "docker-daemon" "daemon" "PASS" "Daemon log-opts max-file is configured: $max_file"
    else
      add_finding "docker-daemon" "daemon" "FAIL" "Daemon log-opts max-file is not configured; log rotation file count not limited"
    fi
  else
    add_finding "docker-daemon" "daemon" "FAIL" "Daemon log-opts not configured in daemon.json; log rotation may not be active"
  fi
else
  add_finding "docker-daemon" "daemon" "FAIL" "Docker daemon.json not found; cannot verify log rotation settings"
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

  # ---- Check 1: Container-level logging driver ----
  log_driver=$(docker inspect --format '{{.HostConfig.LogConfig.Type}}' "$cid" 2>/dev/null || echo "unknown")
  if [[ "$log_driver" == "none" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container logging driver is set to 'none'; no logs are being captured"
  elif [[ "$log_driver" == "unknown" ]]; then
    add_finding "$resource_id" "container" "ERROR" "Unable to determine container logging driver"
  else
    add_finding "$resource_id" "container" "PASS" "Container logging driver is '$log_driver'"
  fi

  # ---- Check 2: Container-level log options (max-size, max-file) ----
  log_config=$(docker inspect --format '{{json .HostConfig.LogConfig.Config}}' "$cid" 2>/dev/null || echo "{}")
  if [[ "$log_driver" == "json-file" || "$log_driver" == "local" ]]; then
    c_max_size=$(printf '%s' "$log_config" | jq -r '.["max-size"] // "not-set"' 2>/dev/null || echo "not-set")
    c_max_file=$(printf '%s' "$log_config" | jq -r '.["max-file"] // "not-set"' 2>/dev/null || echo "not-set")
    if [[ "$c_max_size" == "not-set" ]]; then
      add_finding "$resource_id" "container" "FAIL" "Container does not set log max-size (inherits daemon default; verify daemon config)"
    else
      add_finding "$resource_id" "container" "PASS" "Container log max-size is set to $c_max_size"
    fi
    if [[ "$c_max_file" == "not-set" ]]; then
      add_finding "$resource_id" "container" "FAIL" "Container does not set log max-file (inherits daemon default; verify daemon config)"
    else
      add_finding "$resource_id" "container" "PASS" "Container log max-file is set to $c_max_file"
    fi
  fi

  # ---- Check 3: Verify container is actually producing logs ----
  log_output=$(docker logs --tail 1 "$cid" 2>&1 || echo "")
  if [[ -z "$log_output" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container has no log output; verify the application is logging to stdout/stderr"
  else
    add_finding "$resource_id" "container" "PASS" "Container is producing log output"
  fi
done

printf '%s\n' "$findings"
