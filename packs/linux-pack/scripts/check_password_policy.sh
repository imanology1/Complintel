#!/usr/bin/env bash
# Linux Password Policy Check Agent
# Verifies system password policies for complexity and expiration.
#
# Parameters:
#   --min_length=N   Minimum required password length (default: 14)
#   --max_days=N     Maximum password age in days (default: 90)
#
# Output: JSON array of Finding objects to stdout.

set -euo pipefail

MIN_LENGTH=14
MAX_DAYS=90

for arg in "$@"; do
    case "$arg" in
        --min_length=*) MIN_LENGTH="${arg#*=}" ;;
        --max_days=*)   MAX_DAYS="${arg#*=}" ;;
    esac
done

findings="["
first=true

add_finding() {
    local resource_id="$1"
    local resource_type="$2"
    local status="$3"
    local message="$4"
    local details="${5:-}"

    if [ "$first" = true ]; then
        first=false
    else
        findings+=","
    fi

    if [ -n "$details" ]; then
        findings+=$(printf '{"resource_id":"%s","resource_type":"%s","status":"%s","message":"%s","details":"%s"}' \
            "$resource_id" "$resource_type" "$status" "$message" "$details")
    else
        findings+=$(printf '{"resource_id":"%s","resource_type":"%s","status":"%s","message":"%s"}' \
            "$resource_id" "$resource_type" "$status" "$message")
    fi
}

# Check 1: Minimum password length via login.defs
if [ -f /etc/login.defs ]; then
    current_min=$(grep -E "^PASS_MIN_LEN" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "0")
    current_min=${current_min:-0}

    if [ "$current_min" -ge "$MIN_LENGTH" ] 2>/dev/null; then
        add_finding "/etc/login.defs" "Linux::PasswordPolicy" "PASS" \
            "Minimum password length is ${current_min} (required: ${MIN_LENGTH})"
    else
        add_finding "/etc/login.defs" "Linux::PasswordPolicy" "FAIL" \
            "Minimum password length is ${current_min} (required: ${MIN_LENGTH})"
    fi
else
    add_finding "/etc/login.defs" "Linux::PasswordPolicy" "ERROR" \
        "/etc/login.defs not found"
fi

# Check 2: Maximum password age via login.defs
if [ -f /etc/login.defs ]; then
    current_max=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "99999")
    current_max=${current_max:-99999}

    if [ "$current_max" -le "$MAX_DAYS" ] 2>/dev/null; then
        add_finding "/etc/login.defs:PASS_MAX_DAYS" "Linux::PasswordPolicy" "PASS" \
            "Maximum password age is ${current_max} days (required: <= ${MAX_DAYS})"
    else
        add_finding "/etc/login.defs:PASS_MAX_DAYS" "Linux::PasswordPolicy" "FAIL" \
            "Maximum password age is ${current_max} days (required: <= ${MAX_DAYS})"
    fi
fi

# Check 3: PAM password quality module
if [ -f /etc/pam.d/common-password ]; then
    if grep -q "pam_pwquality" /etc/pam.d/common-password 2>/dev/null; then
        add_finding "/etc/pam.d/common-password" "Linux::PAM" "PASS" \
            "pam_pwquality module is enabled"
    else
        add_finding "/etc/pam.d/common-password" "Linux::PAM" "FAIL" \
            "pam_pwquality module is NOT enabled"
    fi
elif [ -f /etc/pam.d/system-auth ]; then
    if grep -q "pam_pwquality" /etc/pam.d/system-auth 2>/dev/null; then
        add_finding "/etc/pam.d/system-auth" "Linux::PAM" "PASS" \
            "pam_pwquality module is enabled"
    else
        add_finding "/etc/pam.d/system-auth" "Linux::PAM" "FAIL" \
            "pam_pwquality module is NOT enabled"
    fi
else
    add_finding "/etc/pam.d/common-password" "Linux::PAM" "ERROR" \
        "PAM password configuration file not found"
fi

findings+="]"
echo "$findings"
