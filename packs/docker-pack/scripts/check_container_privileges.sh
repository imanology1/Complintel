#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# check_container_privileges.sh
# Detect containers running with elevated privileges (--privileged, root user)
# Frameworks: CIS-Docker-5.1, NIST-AC-6, PCI-DSS-7.1, SOC2-CC6.3
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

  # ---- Check 1: Privileged mode ----
  privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null || echo "unknown")
  if [[ "$privileged" == "true" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container is running in privileged mode"
  elif [[ "$privileged" == "false" ]]; then
    add_finding "$resource_id" "container" "PASS" "Container is not running in privileged mode"
  else
    add_finding "$resource_id" "container" "ERROR" "Unable to determine privileged status"
  fi

  # ---- Check 2: Running as root user ----
  user=$(docker inspect --format '{{.Config.User}}' "$cid" 2>/dev/null || echo "")
  if [[ -z "$user" || "$user" == "root" || "$user" == "0" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container is running as root (user='${user:-unset}')"
  else
    add_finding "$resource_id" "container" "PASS" "Container is running as non-root user ('$user')"
  fi

  # ---- Check 3: Added capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.) ----
  cap_add=$(docker inspect --format '{{json .HostConfig.CapAdd}}' "$cid" 2>/dev/null || echo "null")
  if [[ "$cap_add" != "null" && "$cap_add" != "[]" ]]; then
    # Check for dangerous capabilities
    dangerous_caps=("SYS_ADMIN" "NET_ADMIN" "SYS_PTRACE" "SYS_RAWIO" "SYS_MODULE" "DAC_READ_SEARCH" "NET_RAW" "ALL")
    has_dangerous=false
    for cap in "${dangerous_caps[@]}"; do
      if printf '%s' "$cap_add" | jq -e "map(ascii_upcase) | index(\"$cap\")" &>/dev/null; then
        has_dangerous=true
        add_finding "$resource_id" "container" "FAIL" "Container has dangerous capability added: $cap"
      fi
    done
    if [[ "$has_dangerous" == "false" ]]; then
      add_finding "$resource_id" "container" "PASS" "Container has added capabilities but none are in the dangerous set: $cap_add"
    fi
  else
    add_finding "$resource_id" "container" "PASS" "Container has no additional capabilities added"
  fi

  # ---- Check 4: Dropped capabilities ----
  cap_drop=$(docker inspect --format '{{json .HostConfig.CapDrop}}' "$cid" 2>/dev/null || echo "null")
  if [[ "$cap_drop" == "null" || "$cap_drop" == "[]" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container does not drop any capabilities; consider dropping ALL and adding only required ones"
  else
    # Check if ALL is dropped
    if printf '%s' "$cap_drop" | jq -e 'map(ascii_upcase) | index("ALL")' &>/dev/null; then
      add_finding "$resource_id" "container" "PASS" "Container drops ALL capabilities (best practice)"
    else
      add_finding "$resource_id" "container" "PASS" "Container drops some capabilities: $cap_drop"
    fi
  fi

  # ---- Check 5: PID namespace sharing ----
  pid_mode=$(docker inspect --format '{{.HostConfig.PidMode}}' "$cid" 2>/dev/null || echo "")
  if [[ "$pid_mode" == "host" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container shares the host PID namespace (PidMode=host)"
  else
    add_finding "$resource_id" "container" "PASS" "Container does not share the host PID namespace"
  fi

  # ---- Check 6: No new privileges flag ----
  no_new_privs=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$cid" 2>/dev/null || echo "")
  if printf '%s' "$no_new_privs" | grep -q "no-new-privileges"; then
    add_finding "$resource_id" "container" "PASS" "Container has no-new-privileges security option set"
  else
    add_finding "$resource_id" "container" "FAIL" "Container does not have no-new-privileges security option set"
  fi

  # ---- Check 7: Read-only root filesystem ----
  readonly_rootfs=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$cid" 2>/dev/null || echo "unknown")
  if [[ "$readonly_rootfs" == "true" ]]; then
    add_finding "$resource_id" "container" "PASS" "Container root filesystem is read-only"
  elif [[ "$readonly_rootfs" == "false" ]]; then
    add_finding "$resource_id" "container" "FAIL" "Container root filesystem is writable; consider using --read-only"
  else
    add_finding "$resource_id" "container" "ERROR" "Unable to determine read-only root filesystem setting"
  fi
done

printf '%s\n' "$findings"
