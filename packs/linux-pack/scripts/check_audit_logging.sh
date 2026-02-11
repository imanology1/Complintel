#!/usr/bin/env bash
# Linux Audit Logging Check Agent
# Verifies that auditd is installed, running, and configured for key events.
#
# Checks:
#   - auditd package is installed
#   - auditd service is running and enabled
#   - Audit rules cover identity changes (passwd, shadow, group, gshadow, opasswd)
#   - Audit rules cover time changes (adjtimex, settimeofday, clock_settime)
#   - Audit rules cover user/group modifications (useradd, usermod, groupadd, groupmod)
#   - Audit rules cover network configuration changes
#   - Audit rules cover login/logout events (faillog, lastlog, tallylog)
#   - Audit rules cover privilege escalation (sudo, su)
#   - Audit log rotation and max_log_file configured
#   - Immutable audit rules (-e 2) are set
#
# Output: JSON array of Finding objects to stdout.

set -euo pipefail

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

# ---------------------------------------------------------------------------
# Check 1: auditd installed
# ---------------------------------------------------------------------------
auditd_installed=false
if command -v auditd &>/dev/null || command -v auditctl &>/dev/null; then
    auditd_installed=true
    add_finding "auditd:package" "Linux::AuditLogging" "PASS" "auditd is installed"
elif dpkg -l auditd &>/dev/null 2>&1 || rpm -q audit &>/dev/null 2>&1; then
    auditd_installed=true
    add_finding "auditd:package" "Linux::AuditLogging" "PASS" "auditd package is installed"
else
    add_finding "auditd:package" "Linux::AuditLogging" "FAIL" \
        "auditd is not installed"
fi

# ---------------------------------------------------------------------------
# Check 2: auditd service is running and enabled
# ---------------------------------------------------------------------------
if [ "$auditd_installed" = true ]; then
    if systemctl is-active auditd &>/dev/null 2>&1 || pgrep -x auditd &>/dev/null; then
        add_finding "auditd:service-running" "Linux::AuditLogging" "PASS" "auditd service is running"
    else
        add_finding "auditd:service-running" "Linux::AuditLogging" "FAIL" "auditd service is NOT running"
    fi

    if systemctl is-enabled auditd &>/dev/null 2>&1; then
        add_finding "auditd:service-enabled" "Linux::AuditLogging" "PASS" "auditd is enabled at boot"
    else
        add_finding "auditd:service-enabled" "Linux::AuditLogging" "FAIL" "auditd is NOT enabled at boot"
    fi
fi

# ---------------------------------------------------------------------------
# Gather all active audit rules
# ---------------------------------------------------------------------------
all_rules=""
if command -v auditctl &>/dev/null; then
    all_rules=$(auditctl -l 2>/dev/null || true)
fi
# Also gather from rules files
rules_files=""
if [ -d /etc/audit/rules.d ]; then
    rules_files=$(cat /etc/audit/rules.d/*.rules 2>/dev/null || true)
fi
if [ -f /etc/audit/audit.rules ]; then
    rules_files="${rules_files}
$(cat /etc/audit/audit.rules 2>/dev/null || true)"
fi
combined_rules="${all_rules}
${rules_files}"

# ---------------------------------------------------------------------------
# Check 3: Identity file changes
# ---------------------------------------------------------------------------
identity_files=("/etc/passwd" "/etc/shadow" "/etc/group" "/etc/gshadow" "/etc/security/opasswd")
identity_watched=0
identity_total=${#identity_files[@]}

for idfile in "${identity_files[@]}"; do
    if echo "$combined_rules" | grep -q "$idfile"; then
        identity_watched=$((identity_watched + 1))
    fi
done

if [ "$identity_watched" -eq "$identity_total" ]; then
    add_finding "auditd:identity-files" "Linux::AuditLogging" "PASS" \
        "All ${identity_total} identity files are monitored by audit rules"
elif [ "$identity_watched" -gt 0 ]; then
    add_finding "auditd:identity-files" "Linux::AuditLogging" "FAIL" \
        "Only ${identity_watched}/${identity_total} identity files are monitored"
else
    add_finding "auditd:identity-files" "Linux::AuditLogging" "FAIL" \
        "No identity files are monitored by audit rules"
fi

# ---------------------------------------------------------------------------
# Check 4: Time change events
# ---------------------------------------------------------------------------
time_keywords=("adjtimex" "settimeofday" "clock_settime" "/etc/localtime")
time_watched=0
for tkw in "${time_keywords[@]}"; do
    if echo "$combined_rules" | grep -q "$tkw"; then
        time_watched=$((time_watched + 1))
    fi
done

if [ "$time_watched" -ge 3 ]; then
    add_finding "auditd:time-change" "Linux::AuditLogging" "PASS" \
        "Time change events are audited (${time_watched}/${#time_keywords[@]} rules found)"
elif [ "$time_watched" -gt 0 ]; then
    add_finding "auditd:time-change" "Linux::AuditLogging" "FAIL" \
        "Partial time change auditing (${time_watched}/${#time_keywords[@]} rules found)"
else
    add_finding "auditd:time-change" "Linux::AuditLogging" "FAIL" \
        "No time change audit rules found"
fi

# ---------------------------------------------------------------------------
# Check 5: User/group modification commands
# ---------------------------------------------------------------------------
mod_commands=("useradd" "usermod" "userdel" "groupadd" "groupmod" "groupdel")
mod_watched=0
for mcmd in "${mod_commands[@]}"; do
    if echo "$combined_rules" | grep -q "$mcmd"; then
        mod_watched=$((mod_watched + 1))
    fi
done

if [ "$mod_watched" -ge 4 ]; then
    add_finding "auditd:user-group-mod" "Linux::AuditLogging" "PASS" \
        "User/group modification commands are audited (${mod_watched}/${#mod_commands[@]})"
elif [ "$mod_watched" -gt 0 ]; then
    add_finding "auditd:user-group-mod" "Linux::AuditLogging" "FAIL" \
        "Partial user/group modification auditing (${mod_watched}/${#mod_commands[@]})"
else
    add_finding "auditd:user-group-mod" "Linux::AuditLogging" "FAIL" \
        "No user/group modification audit rules found"
fi

# ---------------------------------------------------------------------------
# Check 6: Network configuration changes
# ---------------------------------------------------------------------------
net_keywords=("sethostname" "setdomainname" "/etc/issue" "/etc/hosts" "/etc/sysconfig/network")
net_watched=0
for nkw in "${net_keywords[@]}"; do
    if echo "$combined_rules" | grep -q "$nkw"; then
        net_watched=$((net_watched + 1))
    fi
done

if [ "$net_watched" -ge 3 ]; then
    add_finding "auditd:network-config" "Linux::AuditLogging" "PASS" \
        "Network configuration changes are audited (${net_watched}/${#net_keywords[@]} rules found)"
else
    add_finding "auditd:network-config" "Linux::AuditLogging" "FAIL" \
        "Insufficient network configuration audit rules (${net_watched}/${#net_keywords[@]})"
fi

# ---------------------------------------------------------------------------
# Check 7: Login/logout events
# ---------------------------------------------------------------------------
login_files=("/var/log/faillog" "/var/log/lastlog" "/var/log/tallylog" "/var/run/faillock")
login_watched=0
for lfile in "${login_files[@]}"; do
    if echo "$combined_rules" | grep -q "$lfile"; then
        login_watched=$((login_watched + 1))
    fi
done

if [ "$login_watched" -ge 2 ]; then
    add_finding "auditd:login-events" "Linux::AuditLogging" "PASS" \
        "Login/logout events are audited (${login_watched} log files monitored)"
else
    add_finding "auditd:login-events" "Linux::AuditLogging" "FAIL" \
        "Insufficient login/logout auditing (${login_watched} log files monitored)"
fi

# ---------------------------------------------------------------------------
# Check 8: Privilege escalation
# ---------------------------------------------------------------------------
priv_keywords=("/etc/sudoers" "/etc/sudoers.d" "execve")
priv_watched=0
for pkw in "${priv_keywords[@]}"; do
    if echo "$combined_rules" | grep -q "$pkw"; then
        priv_watched=$((priv_watched + 1))
    fi
done

if [ "$priv_watched" -ge 2 ]; then
    add_finding "auditd:privilege-escalation" "Linux::AuditLogging" "PASS" \
        "Privilege escalation events are audited (${priv_watched} rules found)"
else
    add_finding "auditd:privilege-escalation" "Linux::AuditLogging" "FAIL" \
        "Insufficient privilege escalation auditing (${priv_watched} rules found)"
fi

# ---------------------------------------------------------------------------
# Check 9: auditd.conf -- max_log_file and space_left_action
# ---------------------------------------------------------------------------
if [ -f /etc/audit/auditd.conf ]; then
    max_log_file=$(grep -iE "^\s*max_log_file\s*=" /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' || echo "")
    if [ -n "$max_log_file" ] && [ "$max_log_file" -ge 8 ] 2>/dev/null; then
        add_finding "auditd.conf:max_log_file" "Linux::AuditLogging" "PASS" \
            "max_log_file is set to ${max_log_file} MB"
    else
        add_finding "auditd.conf:max_log_file" "Linux::AuditLogging" "FAIL" \
            "max_log_file is ${max_log_file:-not set} (should be >= 8 MB)"
    fi

    space_left_action=$(grep -iE "^\s*space_left_action\s*=" /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | tr '[:upper:]' '[:lower:]' || echo "")
    if [ "$space_left_action" = "email" ] || [ "$space_left_action" = "exec" ] || [ "$space_left_action" = "syslog" ]; then
        add_finding "auditd.conf:space_left_action" "Linux::AuditLogging" "PASS" \
            "space_left_action is set to ${space_left_action}"
    else
        add_finding "auditd.conf:space_left_action" "Linux::AuditLogging" "FAIL" \
            "space_left_action is ${space_left_action:-not set} (should be email, exec, or syslog)"
    fi
else
    add_finding "auditd.conf" "Linux::AuditLogging" "ERROR" \
        "/etc/audit/auditd.conf not found"
fi

# ---------------------------------------------------------------------------
# Check 10: Immutable audit rules (-e 2)
# ---------------------------------------------------------------------------
if echo "$combined_rules" | grep -qE "^\s*-e\s+2"; then
    add_finding "auditd:immutable" "Linux::AuditLogging" "PASS" \
        "Audit rules are set to immutable (-e 2)"
else
    add_finding "auditd:immutable" "Linux::AuditLogging" "FAIL" \
        "Audit rules are NOT set to immutable (-e 2 not found)"
fi

findings+="]"
echo "$findings"
