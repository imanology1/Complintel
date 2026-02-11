#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# check_container_networking.sh
# Verify container network isolation and exposed ports
# Frameworks: CIS-Docker-5.7, NIST-SC-7, PCI-DSS-1.3, SOC2-CC6.6
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
  add_finding "docker-cli" "network" "ERROR" "Docker CLI is not installed or not in PATH"
  printf '%s\n' "$findings"
  exit 0
fi

# Check if Docker daemon is running
if ! docker info &>/dev/null; then
  add_finding "docker-daemon" "network" "ERROR" "Docker daemon is not running or not accessible"
  printf '%s\n' "$findings"
  exit 0
fi

# ---- Global check: default bridge network ----
default_bridge_containers=$(docker network inspect bridge --format '{{json .Containers}}' 2>/dev/null || echo "{}")
container_count=$(printf '%s' "$default_bridge_containers" | jq 'length' 2>/dev/null || echo "0")
if [[ "$container_count" -gt 0 ]]; then
  add_finding "bridge-network" "network" "FAIL" "$container_count container(s) attached to the default bridge network; use user-defined networks for isolation"
else
  add_finding "bridge-network" "network" "PASS" "No containers attached to the default bridge network"
fi

# Get list of running containers
container_ids=$(docker ps -q 2>/dev/null || true)

if [[ -z "$container_ids" ]]; then
  add_finding "no-containers" "network" "PASS" "No running containers found"
  printf '%s\n' "$findings"
  exit 0
fi

for cid in $container_ids; do
  container_name=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's|^/||' || echo "$cid")
  resource_id="${container_name}(${cid:0:12})"

  # ---- Check 1: Network mode ----
  network_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null || echo "unknown")
  if [[ "$network_mode" == "host" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container uses host network mode; no network isolation"
  elif [[ "$network_mode" == "default" || "$network_mode" == "bridge" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container uses the default bridge network; use a user-defined network"
  elif [[ "$network_mode" == "none" ]]; then
    add_finding "$resource_id" "container" "PASS" "Container has no network access (network mode: none)"
  else
    add_finding "$resource_id" "container" "PASS" "Container uses user-defined network: $network_mode"
  fi

  # ---- Check 2: Published ports ----
  port_bindings=$(docker inspect --format '{{json .HostConfig.PortBindings}}' "$cid" 2>/dev/null || echo "null")
  if [[ "$port_bindings" == "null" || "$port_bindings" == "{}" ]]; then
    add_finding "$resource_id" "container" "PASS" "Container has no published ports"
  else
    # Check for wildcard bindings (0.0.0.0)
    has_wildcard=false
    host_ports=$(printf '%s' "$port_bindings" | jq -r '.. | .HostIp? // empty' 2>/dev/null || true)
    # Also detect ports with empty HostIp (defaults to 0.0.0.0)
    all_bindings=$(printf '%s' "$port_bindings" | jq -c '[.[][]]' 2>/dev/null || echo "[]")
    binding_count=$(printf '%s' "$all_bindings" | jq 'length' 2>/dev/null || echo "0")

    for i in $(seq 0 $((binding_count - 1))); do
      host_ip=$(printf '%s' "$all_bindings" | jq -r ".[$i].HostIp" 2>/dev/null || echo "")
      host_port=$(printf '%s' "$all_bindings" | jq -r ".[$i].HostPort" 2>/dev/null || echo "")
      if [[ -z "$host_ip" || "$host_ip" == "0.0.0.0" || "$host_ip" == "::" ]]; then
        has_wildcard=true
        break
      fi
    done

    port_list=$(printf '%s' "$port_bindings" | jq -r 'keys[]' 2>/dev/null | tr '\n' ', ' | sed 's/,$//')

    if [[ "$has_wildcard" == "true" ]]; then
      add_finding "$resource_id" "container" "FAIL" "Container publishes ports on all interfaces (0.0.0.0): $port_list; bind to specific IPs"
    else
      add_finding "$resource_id" "container" "PASS" "Container publishes ports bound to specific interfaces: $port_list"
    fi

    # ---- Check 2b: Sensitive ports exposed ----
    sensitive_ports=("22" "23" "3389" "5432" "3306" "6379" "27017" "9200" "2379")
    for sp in "${sensitive_ports[@]}"; do
      if printf '%s' "$port_bindings" | jq -e "to_entries[] | select(.key | startswith(\"$sp/\"))" &>/dev/null; then
        add_finding "$resource_id" "container" "FAIL" "Container exposes sensitive port $sp to the host"
      fi
    done
  fi

  # ---- Check 3: Links (deprecated, insecure) ----
  links=$(docker inspect --format '{{json .HostConfig.Links}}' "$cid" 2>/dev/null || echo "null")
  if [[ "$links" != "null" && "$links" != "[]" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container uses legacy --link; migrate to user-defined networks"
  fi

  # ---- Check 4: IPC mode ----
  ipc_mode=$(docker inspect --format '{{.HostConfig.IpcMode}}' "$cid" 2>/dev/null || echo "")
  if [[ "$ipc_mode" == "host" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container shares host IPC namespace (IpcMode=host)"
  else
    add_finding "$resource_id" "container" "PASS" "Container does not share host IPC namespace"
  fi

  # ---- Check 5: UTS namespace ----
  uts_mode=$(docker inspect --format '{{.HostConfig.UTSMode}}' "$cid" 2>/dev/null || echo "")
  if [[ "$uts_mode" == "host" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container shares host UTS namespace (UTSMode=host)"
  else
    add_finding "$resource_id" "container" "PASS" "Container does not share host UTS namespace"
  fi
done

printf '%s\n' "$findings"
