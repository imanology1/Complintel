#!/usr/bin/env bash
# Linux Firewall Status Check Agent
# Verifies that a firewall is active with a default deny policy.
#
# Checks:
#   - UFW active and default deny
#   - iptables loaded with default DROP/REJECT on INPUT
#   - nftables active with base chains
#   - firewalld active (if present)
#   - IPv6 firewall rules present
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

firewall_found=false

# ---------------------------------------------------------------------------
# Check 1: UFW
# ---------------------------------------------------------------------------
if command -v ufw &>/dev/null; then
    ufw_status=$(ufw status 2>/dev/null || true)
    if echo "$ufw_status" | grep -qi "Status: active"; then
        firewall_found=true
        add_finding "ufw" "Linux::Firewall" "PASS" "UFW firewall is active"

        # Check default incoming policy
        ufw_default=$(ufw status verbose 2>/dev/null || true)
        if echo "$ufw_default" | grep -qi "Default:.*deny.*incoming\|Default:.*reject.*incoming"; then
            add_finding "ufw:default-incoming" "Linux::Firewall" "PASS" \
                "UFW default incoming policy is deny/reject"
        else
            add_finding "ufw:default-incoming" "Linux::Firewall" "FAIL" \
                "UFW default incoming policy is not deny/reject"
        fi

        # Check default outgoing policy
        if echo "$ufw_default" | grep -qi "Default:.*deny.*outgoing\|Default:.*reject.*outgoing\|Default:.*allow.*outgoing"; then
            # Outgoing allow is common but should be noted
            if echo "$ufw_default" | grep -qi "Default:.*allow.*outgoing"; then
                add_finding "ufw:default-outgoing" "Linux::Firewall" "PASS" \
                    "UFW default outgoing policy is allow (common configuration)"
            else
                add_finding "ufw:default-outgoing" "Linux::Firewall" "PASS" \
                    "UFW default outgoing policy is deny/reject"
            fi
        fi
    else
        add_finding "ufw" "Linux::Firewall" "FAIL" "UFW is installed but not active"
    fi
fi

# ---------------------------------------------------------------------------
# Check 2: iptables
# ---------------------------------------------------------------------------
if command -v iptables &>/dev/null; then
    ipt_rules=$(iptables -L -n 2>/dev/null || true)
    if [ -n "$ipt_rules" ]; then
        rule_count=$(iptables -L -n 2>/dev/null | grep -cE "^(ACCEPT|DROP|REJECT|LOG)" || echo "0")
        if [ "$rule_count" -gt 0 ]; then
            firewall_found=true
            add_finding "iptables" "Linux::Firewall" "PASS" \
                "iptables has ${rule_count} active rules"
        fi

        # Check INPUT chain default policy
        input_policy=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oE '\(policy [A-Z]+\)' | grep -oE '[A-Z]+' | tail -1 || echo "")
        if [ "$input_policy" = "DROP" ] || [ "$input_policy" = "REJECT" ]; then
            add_finding "iptables:INPUT-policy" "Linux::Firewall" "PASS" \
                "iptables INPUT chain default policy is ${input_policy}"
        elif [ -n "$input_policy" ]; then
            add_finding "iptables:INPUT-policy" "Linux::Firewall" "FAIL" \
                "iptables INPUT chain default policy is ${input_policy} (should be DROP or REJECT)"
        fi

        # Check FORWARD chain default policy
        fwd_policy=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -oE '\(policy [A-Z]+\)' | grep -oE '[A-Z]+' | tail -1 || echo "")
        if [ "$fwd_policy" = "DROP" ] || [ "$fwd_policy" = "REJECT" ]; then
            add_finding "iptables:FORWARD-policy" "Linux::Firewall" "PASS" \
                "iptables FORWARD chain default policy is ${fwd_policy}"
        elif [ -n "$fwd_policy" ]; then
            add_finding "iptables:FORWARD-policy" "Linux::Firewall" "FAIL" \
                "iptables FORWARD chain default policy is ${fwd_policy} (should be DROP or REJECT)"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Check 3: nftables
# ---------------------------------------------------------------------------
if command -v nft &>/dev/null; then
    nft_ruleset=$(nft list ruleset 2>/dev/null || true)
    if [ -n "$nft_ruleset" ] && echo "$nft_ruleset" | grep -q "chain"; then
        firewall_found=true
        chain_count=$(echo "$nft_ruleset" | grep -c "chain" || echo "0")
        add_finding "nftables" "Linux::Firewall" "PASS" \
            "nftables is active with ${chain_count} chain(s) defined"

        # Check for base chain with drop policy
        if echo "$nft_ruleset" | grep -qE "type filter.*policy drop"; then
            add_finding "nftables:default-policy" "Linux::Firewall" "PASS" \
                "nftables has filter chain(s) with drop policy"
        else
            add_finding "nftables:default-policy" "Linux::Firewall" "FAIL" \
                "nftables filter chains do not have a default drop policy"
        fi
    else
        if systemctl is-active nftables &>/dev/null 2>&1; then
            firewall_found=true
            add_finding "nftables" "Linux::Firewall" "FAIL" \
                "nftables service is active but no rules are loaded"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Check 4: firewalld
# ---------------------------------------------------------------------------
if command -v firewall-cmd &>/dev/null; then
    if firewall-cmd --state &>/dev/null 2>&1; then
        firewall_found=true
        default_zone=$(firewall-cmd --get-default-zone 2>/dev/null || echo "unknown")
        add_finding "firewalld" "Linux::Firewall" "PASS" \
            "firewalld is running with default zone: ${default_zone}"

        # Check if default zone target is DROP or REJECT
        zone_target=$(firewall-cmd --zone="$default_zone" --get-target 2>/dev/null || echo "")
        if [ "$zone_target" = "DROP" ] || [ "$zone_target" = "%%REJECT%%" ] || [ "$zone_target" = "REJECT" ]; then
            add_finding "firewalld:zone-target" "Linux::Firewall" "PASS" \
                "Default zone target is ${zone_target}"
        elif [ -n "$zone_target" ]; then
            add_finding "firewalld:zone-target" "Linux::Firewall" "FAIL" \
                "Default zone target is ${zone_target} (should be DROP or REJECT)"
        fi
    else
        add_finding "firewalld" "Linux::Firewall" "FAIL" "firewalld is installed but not running"
    fi
fi

# ---------------------------------------------------------------------------
# Check 5: IPv6 firewall rules
# ---------------------------------------------------------------------------
if command -v ip6tables &>/dev/null; then
    ip6_rule_count=$(ip6tables -L -n 2>/dev/null | grep -cE "^(ACCEPT|DROP|REJECT|LOG)" || echo "0")
    if [ "$ip6_rule_count" -gt 0 ]; then
        add_finding "ip6tables" "Linux::Firewall" "PASS" \
            "IPv6 firewall has ${ip6_rule_count} active rules"
    else
        # Only flag if IPv6 is enabled
        if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
            ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
            if [ "$ipv6_disabled" = "0" ]; then
                add_finding "ip6tables" "Linux::Firewall" "FAIL" \
                    "IPv6 is enabled but no ip6tables rules are configured"
            else
                add_finding "ip6tables" "Linux::Firewall" "PASS" \
                    "IPv6 is disabled at the kernel level"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Overall: No firewall found
# ---------------------------------------------------------------------------
if [ "$firewall_found" = false ]; then
    add_finding "firewall" "Linux::Firewall" "FAIL" \
        "No active firewall detected (checked ufw, iptables, nftables, firewalld)"
fi

findings+="]"
echo "$findings"
