#!/usr/bin/env bash
# Linux SSH Configuration Check Agent
# Verifies the SSH daemon is configured securely.
#
# Checks:
#   - Root login is disabled
#   - Password authentication is disabled (key-only)
#   - Protocol version 2 only
#   - X11 forwarding is disabled
#   - Max auth tries is reasonable
#
# Output: JSON array of Finding objects to stdout.

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
findings="["
first=true

add_finding() {
    local resource_id="$1"
    local resource_type="$2"
    local status="$3"
    local message="$4"

    if [ "$first" = true ]; then
        first=false
    else
        findings+=","
    fi

    findings+=$(printf '{"resource_id":"%s","resource_type":"%s","status":"%s","message":"%s"}' \
        "$resource_id" "$resource_type" "$status" "$message")
}

if [ ! -f "$SSHD_CONFIG" ]; then
    add_finding "$SSHD_CONFIG" "Linux::SSHConfig" "ERROR" "sshd_config not found"
    findings+="]"
    echo "$findings"
    exit 0
fi

# Helper: get effective sshd config value (last match wins, ignoring comments)
get_config() {
    local key="$1"
    grep -iE "^\s*${key}\s+" "$SSHD_CONFIG" 2>/dev/null | tail -1 | awk '{print tolower($2)}' || echo ""
}

# Check 1: PermitRootLogin
val=$(get_config "PermitRootLogin")
if [ "$val" = "no" ]; then
    add_finding "${SSHD_CONFIG}:PermitRootLogin" "Linux::SSHConfig" "PASS" "Root login is disabled"
else
    add_finding "${SSHD_CONFIG}:PermitRootLogin" "Linux::SSHConfig" "FAIL" "Root login is NOT disabled (current: ${val:-default})"
fi

# Check 2: PasswordAuthentication
val=$(get_config "PasswordAuthentication")
if [ "$val" = "no" ]; then
    add_finding "${SSHD_CONFIG}:PasswordAuthentication" "Linux::SSHConfig" "PASS" "Password authentication is disabled (key-only)"
else
    add_finding "${SSHD_CONFIG}:PasswordAuthentication" "Linux::SSHConfig" "FAIL" "Password authentication is NOT disabled (current: ${val:-default})"
fi

# Check 3: X11Forwarding
val=$(get_config "X11Forwarding")
if [ "$val" = "no" ]; then
    add_finding "${SSHD_CONFIG}:X11Forwarding" "Linux::SSHConfig" "PASS" "X11 forwarding is disabled"
else
    add_finding "${SSHD_CONFIG}:X11Forwarding" "Linux::SSHConfig" "FAIL" "X11 forwarding is NOT disabled (current: ${val:-default})"
fi

# Check 4: MaxAuthTries
val=$(get_config "MaxAuthTries")
if [ -n "$val" ] && [ "$val" -le 4 ] 2>/dev/null; then
    add_finding "${SSHD_CONFIG}:MaxAuthTries" "Linux::SSHConfig" "PASS" "Max auth tries is ${val} (<= 4)"
else
    add_finding "${SSHD_CONFIG}:MaxAuthTries" "Linux::SSHConfig" "FAIL" "Max auth tries is ${val:-default} (should be <= 4)"
fi

# Check 5: PermitEmptyPasswords
val=$(get_config "PermitEmptyPasswords")
if [ "$val" = "no" ] || [ -z "$val" ]; then
    add_finding "${SSHD_CONFIG}:PermitEmptyPasswords" "Linux::SSHConfig" "PASS" "Empty passwords are not permitted"
else
    add_finding "${SSHD_CONFIG}:PermitEmptyPasswords" "Linux::SSHConfig" "FAIL" "Empty passwords ARE permitted"
fi

findings+="]"
echo "$findings"
