#!/usr/bin/env bash
# Linux Cron Permissions Check Agent
# Verifies that cron job files and directories have proper permissions and ownership.
#
# Checks:
#   - /etc/crontab: owned by root:root, permissions 600 or more restrictive
#   - /etc/cron.hourly: owned by root:root, permissions 700 or more restrictive
#   - /etc/cron.daily: owned by root:root, permissions 700 or more restrictive
#   - /etc/cron.weekly: owned by root:root, permissions 700 or more restrictive
#   - /etc/cron.monthly: owned by root:root, permissions 700 or more restrictive
#   - /etc/cron.d: owned by root:root, permissions 700 or more restrictive
#   - /var/spool/cron: owned by root, restricted permissions
#   - /etc/cron.allow and /etc/cron.deny: proper access control
#   - /etc/at.allow and /etc/at.deny: proper access control
#   - Individual cron.d scripts ownership and permissions
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
# Helper: check file/directory ownership and permissions
# $1 = path
# $2 = expected max octal permission
# $3 = expected owner
# $4 = expected group
# $5 = type label for messages
# ---------------------------------------------------------------------------
check_path_security() {
    local path="$1"
    local expected_perm="$2"
    local expected_owner="$3"
    local expected_group="$4"
    local label="$5"

    if [ ! -e "$path" ]; then
        add_finding "${path}" "Linux::CronPermissions" "ERROR" \
            "${label} does not exist"
        return
    fi

    local actual_perm actual_owner actual_group
    actual_perm=$(stat -c '%a' "$path" 2>/dev/null || echo "")
    actual_owner=$(stat -c '%U' "$path" 2>/dev/null || echo "")
    actual_group=$(stat -c '%G' "$path" 2>/dev/null || echo "")

    # Check ownership
    local owner_ok=true
    if [ "$actual_owner" != "$expected_owner" ]; then
        owner_ok=false
    fi
    if [ "$actual_group" != "$expected_group" ]; then
        owner_ok=false
    fi

    if [ "$owner_ok" = true ]; then
        add_finding "${path}:ownership" "Linux::CronPermissions" "PASS" \
            "${label} ownership is ${actual_owner}:${actual_group}"
    else
        add_finding "${path}:ownership" "Linux::CronPermissions" "FAIL" \
            "${label} ownership is ${actual_owner}:${actual_group}, expected ${expected_owner}:${expected_group}"
    fi

    # Check permissions (actual must not be more permissive than expected)
    if [ -n "$actual_perm" ]; then
        local actual_int=$((8#$actual_perm))
        local expected_int=$((8#$expected_perm))
        local excess=$(( actual_int & ~expected_int ))

        if [ "$excess" -eq 0 ]; then
            add_finding "${path}:permissions" "Linux::CronPermissions" "PASS" \
                "${label} permissions are ${actual_perm} (maximum allowed: ${expected_perm})"
        else
            add_finding "${path}:permissions" "Linux::CronPermissions" "FAIL" \
                "${label} permissions are ${actual_perm}, more permissive than ${expected_perm}"
        fi
    else
        add_finding "${path}:permissions" "Linux::CronPermissions" "ERROR" \
            "Could not determine permissions for ${label}"
    fi
}

# ---------------------------------------------------------------------------
# Check 1: /etc/crontab
# ---------------------------------------------------------------------------
check_path_security "/etc/crontab" "600" "root" "root" "System crontab"

# ---------------------------------------------------------------------------
# Check 2-6: Cron directories
# ---------------------------------------------------------------------------
cron_dirs=("cron.hourly" "cron.daily" "cron.weekly" "cron.monthly" "cron.d")
for cdir in "${cron_dirs[@]}"; do
    check_path_security "/etc/${cdir}" "700" "root" "root" "/etc/${cdir} directory"
done

# ---------------------------------------------------------------------------
# Check 7: /var/spool/cron
# ---------------------------------------------------------------------------
if [ -d /var/spool/cron ]; then
    check_path_security "/var/spool/cron" "700" "root" "root" "User crontab spool"

    # Check individual user crontabs in spool
    if [ -d /var/spool/cron/crontabs ]; then
        check_path_security "/var/spool/cron/crontabs" "1730" "root" "crontab" "User crontab directory"
    fi
else
    add_finding "/var/spool/cron" "Linux::CronPermissions" "ERROR" \
        "Cron spool directory not found"
fi

# ---------------------------------------------------------------------------
# Check 8: /etc/cron.allow and /etc/cron.deny
# ---------------------------------------------------------------------------
if [ -f /etc/cron.allow ]; then
    # cron.allow exists -- only listed users can use cron
    allow_perm=$(stat -c '%a' /etc/cron.allow 2>/dev/null || echo "")
    allow_owner=$(stat -c '%U' /etc/cron.allow 2>/dev/null || echo "")

    if [ "$allow_owner" = "root" ]; then
        add_finding "/etc/cron.allow:ownership" "Linux::CronPermissions" "PASS" \
            "cron.allow is owned by root"
    else
        add_finding "/etc/cron.allow:ownership" "Linux::CronPermissions" "FAIL" \
            "cron.allow is owned by ${allow_owner}, should be root"
    fi

    if [ -n "$allow_perm" ]; then
        local_int=$((8#$allow_perm))
        max_int=$((8#640))
        excess=$(( local_int & ~max_int ))
        if [ "$excess" -eq 0 ]; then
            add_finding "/etc/cron.allow:permissions" "Linux::CronPermissions" "PASS" \
                "cron.allow permissions are ${allow_perm}"
        else
            add_finding "/etc/cron.allow:permissions" "Linux::CronPermissions" "FAIL" \
                "cron.allow permissions are ${allow_perm}, should be 640 or more restrictive"
        fi
    fi

    add_finding "/etc/cron.allow:exists" "Linux::CronPermissions" "PASS" \
        "cron.allow exists -- only explicitly listed users can use cron"
elif [ -f /etc/cron.deny ]; then
    add_finding "/etc/cron.allow:missing" "Linux::CronPermissions" "FAIL" \
        "cron.allow does not exist; cron.deny is used instead (less secure -- consider using cron.allow)"
else
    add_finding "/etc/cron.allow:missing" "Linux::CronPermissions" "FAIL" \
        "Neither cron.allow nor cron.deny exists -- all users may be able to create cron jobs"
fi

# ---------------------------------------------------------------------------
# Check 9: /etc/at.allow and /etc/at.deny
# ---------------------------------------------------------------------------
if command -v at &>/dev/null || [ -f /etc/at.allow ] || [ -f /etc/at.deny ]; then
    if [ -f /etc/at.allow ]; then
        at_owner=$(stat -c '%U' /etc/at.allow 2>/dev/null || echo "")
        if [ "$at_owner" = "root" ]; then
            add_finding "/etc/at.allow" "Linux::CronPermissions" "PASS" \
                "at.allow exists and is owned by root -- only listed users can use at"
        else
            add_finding "/etc/at.allow" "Linux::CronPermissions" "FAIL" \
                "at.allow is owned by ${at_owner}, should be root"
        fi
    elif [ -f /etc/at.deny ]; then
        add_finding "/etc/at.allow:missing" "Linux::CronPermissions" "FAIL" \
            "at.allow does not exist; at.deny is used instead (less secure)"
    else
        add_finding "/etc/at.allow:missing" "Linux::CronPermissions" "FAIL" \
            "Neither at.allow nor at.deny exists -- all users may be able to use at"
    fi
fi

# ---------------------------------------------------------------------------
# Check 10: Individual files in /etc/cron.d are owned by root
# ---------------------------------------------------------------------------
if [ -d /etc/cron.d ]; then
    bad_cron_d=0
    while IFS= read -r cronfile; do
        if [ -f "$cronfile" ]; then
            cf_owner=$(stat -c '%U' "$cronfile" 2>/dev/null || echo "")
            cf_perm=$(stat -c '%a' "$cronfile" 2>/dev/null || echo "")

            if [ "$cf_owner" != "root" ]; then
                bad_cron_d=$((bad_cron_d + 1))
                if [ "$bad_cron_d" -le 5 ]; then
                    add_finding "${cronfile}:ownership" "Linux::CronPermissions" "FAIL" \
                        "Cron file owned by ${cf_owner} instead of root"
                fi
            fi

            if [ -n "$cf_perm" ]; then
                cf_int=$((8#$cf_perm))
                max_int=$((8#644))
                excess=$(( cf_int & ~max_int ))
                if [ "$excess" -ne 0 ]; then
                    bad_cron_d=$((bad_cron_d + 1))
                    if [ "$bad_cron_d" -le 5 ]; then
                        add_finding "${cronfile}:permissions" "Linux::CronPermissions" "FAIL" \
                            "Cron file permissions ${cf_perm} are too permissive (max: 644)"
                    fi
                fi
            fi
        fi
    done < <(find /etc/cron.d -type f 2>/dev/null || true)

    if [ "$bad_cron_d" -eq 0 ]; then
        add_finding "/etc/cron.d:files" "Linux::CronPermissions" "PASS" \
            "All files in /etc/cron.d have proper ownership and permissions"
    elif [ "$bad_cron_d" -gt 5 ]; then
        add_finding "/etc/cron.d:files" "Linux::CronPermissions" "FAIL" \
            "${bad_cron_d} files in /etc/cron.d have improper ownership or permissions (showing first 5)"
    fi
fi

findings+="]"
echo "$findings"
