#!/usr/bin/env bash
# Linux User Accounts Audit Check Agent
# Audits user accounts for security issues.
#
# Checks:
#   - Duplicate UID 0 accounts (only root should have UID 0)
#   - Accounts with empty passwords
#   - System accounts with login shells
#   - Duplicate UIDs across all accounts
#   - Duplicate GIDs across all groups
#   - Duplicate usernames and group names
#   - Accounts with no password expiration set
#   - Root account has a secure password hash
#   - Non-root accounts with UID < 1000 that have login shells
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

PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
GROUP_FILE="/etc/group"

# Verify critical files exist
for f in "$PASSWD_FILE" "$SHADOW_FILE" "$GROUP_FILE"; do
    if [ ! -f "$f" ]; then
        add_finding "$f" "Linux::UserAccounts" "ERROR" "File not found: ${f}"
    fi
done

# ---------------------------------------------------------------------------
# Check 1: Duplicate UID 0 accounts
# ---------------------------------------------------------------------------
if [ -f "$PASSWD_FILE" ]; then
    uid0_users=$(awk -F: '$3 == 0 {print $1}' "$PASSWD_FILE" 2>/dev/null)
    uid0_count=$(echo "$uid0_users" | grep -c . || echo "0")

    if [ "$uid0_count" -eq 1 ]; then
        add_finding "uid:0" "Linux::UserAccounts" "PASS" \
            "Only root has UID 0"
    elif [ "$uid0_count" -gt 1 ]; then
        uid0_list=$(echo "$uid0_users" | tr '\n' ', ' | sed 's/,$//')
        add_finding "uid:0" "Linux::UserAccounts" "FAIL" \
            "Multiple accounts have UID 0: ${uid0_list}"
    fi
fi

# ---------------------------------------------------------------------------
# Check 2: Accounts with empty passwords
# ---------------------------------------------------------------------------
if [ -f "$SHADOW_FILE" ]; then
    empty_pw_users=""
    empty_pw_count=0

    while IFS=: read -r username pw_hash rest; do
        # Empty password field means no password set
        if [ -z "$pw_hash" ] || [ "$pw_hash" = "" ]; then
            empty_pw_count=$((empty_pw_count + 1))
            if [ -n "$empty_pw_users" ]; then
                empty_pw_users="${empty_pw_users}, ${username}"
            else
                empty_pw_users="$username"
            fi
        fi
    done < "$SHADOW_FILE" 2>/dev/null || true

    if [ "$empty_pw_count" -eq 0 ]; then
        add_finding "accounts:empty-password" "Linux::UserAccounts" "PASS" \
            "No accounts have empty passwords"
    else
        add_finding "accounts:empty-password" "Linux::UserAccounts" "FAIL" \
            "${empty_pw_count} account(s) have empty passwords: ${empty_pw_users}"
    fi
fi

# ---------------------------------------------------------------------------
# Check 3: System accounts with login shells
# ---------------------------------------------------------------------------
if [ -f "$PASSWD_FILE" ]; then
    nologin_shells="/usr/sbin/nologin /sbin/nologin /bin/false /usr/bin/false"
    sys_with_shell=""
    sys_shell_count=0

    while IFS=: read -r username _ uid _ _ _ shell; do
        # System accounts: UID < 1000 and not root
        if [ "$uid" -lt 1000 ] 2>/dev/null && [ "$username" != "root" ]; then
            shell_ok=false
            for ns in $nologin_shells; do
                if [ "$shell" = "$ns" ] || [ -z "$shell" ]; then
                    shell_ok=true
                    break
                fi
            done
            if [ "$shell_ok" = false ]; then
                sys_shell_count=$((sys_shell_count + 1))
                if [ "$sys_shell_count" -le 10 ]; then
                    add_finding "user:${username}" "Linux::UserAccounts" "FAIL" \
                        "System account ${username} (UID ${uid}) has login shell: ${shell}"
                fi
            fi
        fi
    done < "$PASSWD_FILE" 2>/dev/null || true

    if [ "$sys_shell_count" -eq 0 ]; then
        add_finding "accounts:system-shells" "Linux::UserAccounts" "PASS" \
            "All system accounts have nologin/false shells"
    elif [ "$sys_shell_count" -gt 10 ]; then
        add_finding "accounts:system-shells" "Linux::UserAccounts" "FAIL" \
            "${sys_shell_count} system accounts have login shells (showing first 10)"
    fi
fi

# ---------------------------------------------------------------------------
# Check 4: Duplicate UIDs
# ---------------------------------------------------------------------------
if [ -f "$PASSWD_FILE" ]; then
    dup_uids=$(awk -F: '{print $3}' "$PASSWD_FILE" 2>/dev/null | sort | uniq -d)

    if [ -z "$dup_uids" ]; then
        add_finding "accounts:duplicate-uid" "Linux::UserAccounts" "PASS" \
            "No duplicate UIDs found"
    else
        while IFS= read -r dup_uid; do
            if [ -n "$dup_uid" ]; then
                dup_names=$(awk -F: -v uid="$dup_uid" '$3 == uid {print $1}' "$PASSWD_FILE" | tr '\n' ', ' | sed 's/,$//')
                add_finding "uid:${dup_uid}" "Linux::UserAccounts" "FAIL" \
                    "Duplicate UID ${dup_uid} shared by: ${dup_names}"
            fi
        done <<< "$dup_uids"
    fi
fi

# ---------------------------------------------------------------------------
# Check 5: Duplicate GIDs
# ---------------------------------------------------------------------------
if [ -f "$GROUP_FILE" ]; then
    dup_gids=$(awk -F: '{print $3}' "$GROUP_FILE" 2>/dev/null | sort | uniq -d)

    if [ -z "$dup_gids" ]; then
        add_finding "groups:duplicate-gid" "Linux::UserAccounts" "PASS" \
            "No duplicate GIDs found"
    else
        while IFS= read -r dup_gid; do
            if [ -n "$dup_gid" ]; then
                dup_groups=$(awk -F: -v gid="$dup_gid" '$3 == gid {print $1}' "$GROUP_FILE" | tr '\n' ', ' | sed 's/,$//')
                add_finding "gid:${dup_gid}" "Linux::UserAccounts" "FAIL" \
                    "Duplicate GID ${dup_gid} shared by: ${dup_groups}"
            fi
        done <<< "$dup_gids"
    fi
fi

# ---------------------------------------------------------------------------
# Check 6: Duplicate usernames
# ---------------------------------------------------------------------------
if [ -f "$PASSWD_FILE" ]; then
    dup_users=$(awk -F: '{print $1}' "$PASSWD_FILE" 2>/dev/null | sort | uniq -d)

    if [ -z "$dup_users" ]; then
        add_finding "accounts:duplicate-username" "Linux::UserAccounts" "PASS" \
            "No duplicate usernames found"
    else
        dup_list=$(echo "$dup_users" | tr '\n' ', ' | sed 's/,$//')
        add_finding "accounts:duplicate-username" "Linux::UserAccounts" "FAIL" \
            "Duplicate usernames found: ${dup_list}"
    fi
fi

# ---------------------------------------------------------------------------
# Check 7: Duplicate group names
# ---------------------------------------------------------------------------
if [ -f "$GROUP_FILE" ]; then
    dup_groups=$(awk -F: '{print $1}' "$GROUP_FILE" 2>/dev/null | sort | uniq -d)

    if [ -z "$dup_groups" ]; then
        add_finding "groups:duplicate-name" "Linux::UserAccounts" "PASS" \
            "No duplicate group names found"
    else
        dup_list=$(echo "$dup_groups" | tr '\n' ', ' | sed 's/,$//')
        add_finding "groups:duplicate-name" "Linux::UserAccounts" "FAIL" \
            "Duplicate group names found: ${dup_list}"
    fi
fi

# ---------------------------------------------------------------------------
# Check 8: Root password is set (not empty/locked unexpectedly)
# ---------------------------------------------------------------------------
if [ -f "$SHADOW_FILE" ]; then
    root_hash=$(awk -F: '$1 == "root" {print $2}' "$SHADOW_FILE" 2>/dev/null || echo "")

    if [ -z "$root_hash" ]; then
        add_finding "root:password" "Linux::UserAccounts" "FAIL" \
            "Root account has no password set"
    elif [ "$root_hash" = "!" ] || [ "$root_hash" = "*" ] || [ "$root_hash" = "!!" ]; then
        add_finding "root:password" "Linux::UserAccounts" "PASS" \
            "Root account is locked (password login disabled, use sudo)"
    elif echo "$root_hash" | grep -qE '^\$[0-9a-z]+\$'; then
        # Check hash algorithm strength
        hash_algo=$(echo "$root_hash" | cut -d'$' -f2)
        case "$hash_algo" in
            6) add_finding "root:password" "Linux::UserAccounts" "PASS" \
                   "Root password uses SHA-512 hashing" ;;
            y) add_finding "root:password" "Linux::UserAccounts" "PASS" \
                   "Root password uses yescrypt hashing" ;;
            5) add_finding "root:password" "Linux::UserAccounts" "PASS" \
                   "Root password uses SHA-256 hashing (consider upgrading to SHA-512)" ;;
            1) add_finding "root:password" "Linux::UserAccounts" "FAIL" \
                   "Root password uses weak MD5 hashing -- upgrade to SHA-512" ;;
            *) add_finding "root:password" "Linux::UserAccounts" "PASS" \
                   "Root password has a hash set (algorithm: ${hash_algo})" ;;
        esac
    else
        add_finding "root:password" "Linux::UserAccounts" "FAIL" \
            "Root password hash format not recognized -- investigate"
    fi
fi

# ---------------------------------------------------------------------------
# Check 9: Accounts with password aging disabled (PASS_MAX_DAYS very high)
# ---------------------------------------------------------------------------
if [ -f "$SHADOW_FILE" ]; then
    no_expire_count=0
    no_expire_users=""

    while IFS=: read -r username pw_hash _ _ max_days _ _ _ _; do
        # Skip locked/nologin accounts
        if [ "$pw_hash" = "!" ] || [ "$pw_hash" = "*" ] || [ "$pw_hash" = "!!" ]; then
            continue
        fi
        # Skip accounts without a real password
        if [ -z "$pw_hash" ]; then
            continue
        fi
        # Check max_days
        if [ -n "$max_days" ] && [ "$max_days" -gt 365 ] 2>/dev/null; then
            no_expire_count=$((no_expire_count + 1))
            if [ -n "$no_expire_users" ]; then
                no_expire_users="${no_expire_users}, ${username}"
            else
                no_expire_users="$username"
            fi
        elif [ -z "$max_days" ] || [ "$max_days" = "99999" ]; then
            no_expire_count=$((no_expire_count + 1))
            if [ -n "$no_expire_users" ]; then
                no_expire_users="${no_expire_users}, ${username}"
            else
                no_expire_users="$username"
            fi
        fi
    done < "$SHADOW_FILE" 2>/dev/null || true

    if [ "$no_expire_count" -eq 0 ]; then
        add_finding "accounts:password-aging" "Linux::UserAccounts" "PASS" \
            "All active accounts have password expiration configured"
    else
        add_finding "accounts:password-aging" "Linux::UserAccounts" "FAIL" \
            "${no_expire_count} account(s) have no password expiration: ${no_expire_users}"
    fi
fi

# ---------------------------------------------------------------------------
# Check 10: Ensure root is the only account with primary GID 0
# ---------------------------------------------------------------------------
if [ -f "$PASSWD_FILE" ]; then
    gid0_users=$(awk -F: '$4 == 0 && $1 != "root" {print $1}' "$PASSWD_FILE" 2>/dev/null)

    if [ -z "$gid0_users" ]; then
        add_finding "accounts:gid-zero" "Linux::UserAccounts" "PASS" \
            "Only root has primary GID 0"
    else
        gid0_list=$(echo "$gid0_users" | tr '\n' ', ' | sed 's/,$//')
        add_finding "accounts:gid-zero" "Linux::UserAccounts" "FAIL" \
            "Non-root accounts with primary GID 0: ${gid0_list}"
    fi
fi

findings+="]"
echo "$findings"
