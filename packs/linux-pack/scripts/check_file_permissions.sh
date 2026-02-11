#!/usr/bin/env bash
# Linux Critical File Permissions Check Agent
# Verifies that critical system files have secure ownership and permissions.
#
# Checks:
#   - /etc/passwd  : should be 644, owned by root:root
#   - /etc/shadow  : should be 640 or 000, owned by root:root (or root:shadow)
#   - /etc/group   : should be 644, owned by root:root
#   - /etc/gshadow : should be 640 or 000, owned by root:root (or root:shadow)
#   - /etc/passwd-  : backup file permissions
#   - /etc/shadow-  : backup file permissions
#   - /etc/group-   : backup file permissions
#   - /etc/gshadow- : backup file permissions
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

# Convert octal permission to a human-comparable string
get_octal_perms() {
    stat -c '%a' "$1" 2>/dev/null || echo ""
}

get_owner() {
    stat -c '%U' "$1" 2>/dev/null || echo ""
}

get_group() {
    stat -c '%G' "$1" 2>/dev/null || echo ""
}

# Check a file's permissions and ownership against expected values
# $1 = file path
# $2 = expected max octal permission (e.g. 644)
# $3 = expected owner
# $4 = comma-separated allowed groups (e.g. "root,shadow")
check_file() {
    local file_path="$1"
    local expected_perm="$2"
    local expected_owner="$3"
    local allowed_groups="$4"

    if [ ! -e "$file_path" ]; then
        add_finding "$file_path" "Linux::FilePermissions" "ERROR" \
            "File does not exist"
        return
    fi

    local actual_perm
    actual_perm=$(get_octal_perms "$file_path")
    local actual_owner
    actual_owner=$(get_owner "$file_path")
    local actual_group
    actual_group=$(get_group "$file_path")

    # Check ownership
    if [ "$actual_owner" != "$expected_owner" ]; then
        add_finding "${file_path}:owner" "Linux::FilePermissions" "FAIL" \
            "Owner is ${actual_owner}, expected ${expected_owner}"
    else
        add_finding "${file_path}:owner" "Linux::FilePermissions" "PASS" \
            "Owner is correctly set to ${actual_owner}"
    fi

    # Check group ownership (match against comma-separated allowed list)
    local group_ok=false
    if echo ",$allowed_groups," | grep -q ",$actual_group,"; then
        group_ok=true
    fi

    if [ "$group_ok" = true ]; then
        add_finding "${file_path}:group" "Linux::FilePermissions" "PASS" \
            "Group is correctly set to ${actual_group}"
    else
        add_finding "${file_path}:group" "Linux::FilePermissions" "FAIL" \
            "Group is ${actual_group}, expected one of: ${allowed_groups}"
    fi

    # Check permissions -- actual must be <= expected (no extra bits)
    # Compare by checking that actual permissions do not grant more access
    if [ -n "$actual_perm" ]; then
        local actual_int=$((8#$actual_perm))
        local expected_int=$((8#$expected_perm))
        # If actual has bits set that expected does not, it is too permissive
        local excess=$(( actual_int & ~expected_int ))
        if [ "$excess" -eq 0 ]; then
            add_finding "${file_path}:permissions" "Linux::FilePermissions" "PASS" \
                "Permissions are ${actual_perm} (maximum allowed: ${expected_perm})"
        else
            add_finding "${file_path}:permissions" "Linux::FilePermissions" "FAIL" \
                "Permissions are ${actual_perm}, more permissive than allowed ${expected_perm}"
        fi
    else
        add_finding "${file_path}:permissions" "Linux::FilePermissions" "ERROR" \
            "Could not determine file permissions"
    fi
}

# -- Primary files --
check_file "/etc/passwd"   "644" "root" "root"
check_file "/etc/shadow"   "640" "root" "root,shadow"
check_file "/etc/group"    "644" "root" "root"
check_file "/etc/gshadow"  "640" "root" "root,shadow"

# -- Backup files (CIS 6.1.5 - 6.1.8) --
check_file "/etc/passwd-"  "600" "root" "root"
check_file "/etc/shadow-"  "600" "root" "root,shadow"
check_file "/etc/group-"   "600" "root" "root"
check_file "/etc/gshadow-" "600" "root" "root,shadow"

# -- World-writable check on /etc directory critical files --
world_writable_count=0
while IFS= read -r -d '' wfile; do
    world_writable_count=$((world_writable_count + 1))
    if [ "$world_writable_count" -le 10 ]; then
        add_finding "${wfile}" "Linux::FilePermissions" "FAIL" \
            "Critical config file is world-writable"
    fi
done < <(find /etc -maxdepth 1 -type f \( -name "*.conf" -o -name "passwd" -o -name "shadow" -o -name "group" -o -name "gshadow" -o -name "sudoers" \) -perm -0002 -print0 2>/dev/null || true)

if [ "$world_writable_count" -eq 0 ]; then
    add_finding "/etc:world-writable" "Linux::FilePermissions" "PASS" \
        "No critical config files in /etc are world-writable"
elif [ "$world_writable_count" -gt 10 ]; then
    add_finding "/etc:world-writable" "Linux::FilePermissions" "FAIL" \
        "Found ${world_writable_count} world-writable critical config files (showing first 10)"
fi

findings+="]"
echo "$findings"
