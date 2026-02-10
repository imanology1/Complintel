#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# check_daemon_config.sh
# Verify Docker daemon security configuration
# Frameworks: CIS-Docker-2.1, NIST-CM-6, SOC2-CC6.8
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
  add_finding "docker-cli" "daemon" "ERROR" "Docker CLI is not installed or not in PATH"
  printf '%s\n' "$findings"
  exit 0
fi

# Check if Docker daemon is running
if ! docker info &>/dev/null; then
  add_finding "docker-daemon" "daemon" "ERROR" "Docker daemon is not running or not accessible"
  printf '%s\n' "$findings"
  exit 0
fi

# ---- Check 1: Userland proxy disabled ----
userland_proxy=$(docker info --format '{{json .}}' 2>/dev/null | jq -r '.HttpProxy // empty' 2>/dev/null || true)
# Inspect daemon.json directly for the userland-proxy setting
daemon_json="/etc/docker/daemon.json"
if [[ -f "$daemon_json" ]]; then
  userland_proxy_setting=$(jq -r '.["userland-proxy"] // "not-set"' "$daemon_json" 2>/dev/null || echo "not-set")
  if [[ "$userland_proxy_setting" == "false" ]]; then
    add_finding "docker-daemon" "daemon-config" "PASS" "Userland proxy is disabled in daemon.json"
  elif [[ "$userland_proxy_setting" == "not-set" ]]; then
    add_finding "docker-daemon" "daemon-config" "FAIL" "Userland proxy setting is not configured in daemon.json (defaults to enabled)"
  else
    add_finding "docker-daemon" "daemon-config" "FAIL" "Userland proxy is enabled in daemon.json"
  fi
else
  add_finding "docker-daemon" "daemon-config" "FAIL" "Docker daemon.json configuration file not found at $daemon_json"
fi

# ---- Check 2: Live restore enabled ----
live_restore=$(docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null || echo "unknown")
if [[ "$live_restore" == "true" ]]; then
  add_finding "docker-daemon" "daemon-config" "PASS" "Live restore is enabled"
elif [[ "$live_restore" == "unknown" ]]; then
  add_finding "docker-daemon" "daemon-config" "ERROR" "Unable to determine live restore setting"
else
  add_finding "docker-daemon" "daemon-config" "FAIL" "Live restore is not enabled; containers will stop when daemon restarts"
fi

# ---- Check 3: Content trust / image signing ----
if [[ "${DOCKER_CONTENT_TRUST:-0}" == "1" ]]; then
  add_finding "docker-daemon" "daemon-config" "PASS" "Docker Content Trust (DOCKER_CONTENT_TRUST) is enabled"
else
  add_finding "docker-daemon" "daemon-config" "FAIL" "Docker Content Trust (DOCKER_CONTENT_TRUST) is not enabled"
fi

# ---- Check 4: icc (inter-container communication) ----
if [[ -f "$daemon_json" ]]; then
  icc_setting=$(jq -r '.["icc"] // "not-set"' "$daemon_json" 2>/dev/null || echo "not-set")
  if [[ "$icc_setting" == "false" ]]; then
    add_finding "docker-daemon" "daemon-config" "PASS" "Inter-container communication (icc) is disabled"
  elif [[ "$icc_setting" == "not-set" ]]; then
    add_finding "docker-daemon" "daemon-config" "FAIL" "Inter-container communication (icc) is not explicitly disabled (defaults to enabled)"
  else
    add_finding "docker-daemon" "daemon-config" "FAIL" "Inter-container communication (icc) is enabled"
  fi
fi

# ---- Check 5: Default ulimits configured ----
if [[ -f "$daemon_json" ]]; then
  default_ulimits=$(jq -r '.["default-ulimits"] // "not-set"' "$daemon_json" 2>/dev/null || echo "not-set")
  if [[ "$default_ulimits" != "not-set" && "$default_ulimits" != "null" ]]; then
    add_finding "docker-daemon" "daemon-config" "PASS" "Default ulimits are configured in daemon.json"
  else
    add_finding "docker-daemon" "daemon-config" "FAIL" "Default ulimits are not configured in daemon.json"
  fi
fi

# ---- Check 6: Storage driver ----
storage_driver=$(docker info --format '{{.Driver}}' 2>/dev/null || echo "unknown")
if [[ "$storage_driver" == "overlay2" ]]; then
  add_finding "docker-daemon" "daemon-config" "PASS" "Storage driver is overlay2 (recommended)"
elif [[ "$storage_driver" == "unknown" ]]; then
  add_finding "docker-daemon" "daemon-config" "ERROR" "Unable to determine storage driver"
else
  add_finding "docker-daemon" "daemon-config" "FAIL" "Storage driver is '$storage_driver'; overlay2 is recommended"
fi

# ---- Check 7: Logging driver at daemon level ----
logging_driver=$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || echo "unknown")
if [[ "$logging_driver" == "json-file" || "$logging_driver" == "journald" || "$logging_driver" == "syslog" || "$logging_driver" == "fluentd" || "$logging_driver" == "splunk" || "$logging_driver" == "gelf" ]]; then
  add_finding "docker-daemon" "daemon-config" "PASS" "Daemon logging driver is set to '$logging_driver'"
elif [[ "$logging_driver" == "none" ]]; then
  add_finding "docker-daemon" "daemon-config" "FAIL" "Daemon logging driver is set to 'none'; logs will not be captured"
elif [[ "$logging_driver" == "unknown" ]]; then
  add_finding "docker-daemon" "daemon-config" "ERROR" "Unable to determine daemon logging driver"
else
  add_finding "docker-daemon" "daemon-config" "PASS" "Daemon logging driver is set to '$logging_driver'"
fi

# ---- Check 8: Insecure registries ----
insecure_registries=$(docker info --format '{{json .RegistryConfig.InsecureRegistryCIDRs}}' 2>/dev/null || echo "[]")
insecure_count=$(printf '%s' "$insecure_registries" | jq 'length' 2>/dev/null || echo "0")
# Docker always includes 127.0.0.0/8 as insecure; only flag if more are present
if [[ "$insecure_count" -le 1 ]]; then
  add_finding "docker-daemon" "daemon-config" "PASS" "No additional insecure registries configured"
else
  add_finding "docker-daemon" "daemon-config" "FAIL" "Insecure registries detected: $insecure_registries"
fi

printf '%s\n' "$findings"
