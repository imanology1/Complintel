#!/usr/bin/env bash
# Linux Kernel Hardening Check Agent
# Verifies sysctl kernel hardening parameters are set to secure values.
#
# Checks:
#   - ASLR (kernel.randomize_va_space = 2)
#   - SYN cookies (net.ipv4.tcp_syncookies = 1)
#   - IP forwarding disabled (net.ipv4.ip_forward = 0)
#   - Source routing disabled
#   - ICMP redirect acceptance disabled
#   - Secure ICMP redirect acceptance disabled
#   - Log martian packets
#   - Reverse path filtering (net.ipv4.conf.all.rp_filter = 1)
#   - TCP RFC1337 (net.ipv4.tcp_rfc1337 = 1)
#   - Kernel pointer restriction (kernel.kptr_restrict >= 1)
#   - Dmesg restriction (kernel.dmesg_restrict = 1)
#   - Unprivileged BPF disabled (kernel.unprivileged_bpf_disabled = 1)
#   - Yama ptrace scope (kernel.yama.ptrace_scope >= 1)
#   - Core dump restrictions
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
# Helper: read a sysctl value
# ---------------------------------------------------------------------------
get_sysctl() {
    local key="$1"
    sysctl -n "$key" 2>/dev/null || echo ""
}

# ---------------------------------------------------------------------------
# Helper: check a sysctl value against expected
# $1 = sysctl key
# $2 = expected value
# $3 = human description
# $4 = comparison operator: "eq", "ge", "le" (default: eq)
# ---------------------------------------------------------------------------
check_sysctl() {
    local key="$1"
    local expected="$2"
    local description="$3"
    local op="${4:-eq}"

    local actual
    actual=$(get_sysctl "$key")

    if [ -z "$actual" ]; then
        add_finding "sysctl:${key}" "Linux::KernelHardening" "ERROR" \
            "${description} -- parameter ${key} not available"
        return
    fi

    local pass=false
    case "$op" in
        eq) [ "$actual" = "$expected" ] && pass=true ;;
        ge) [ "$actual" -ge "$expected" ] 2>/dev/null && pass=true ;;
        le) [ "$actual" -le "$expected" ] 2>/dev/null && pass=true ;;
    esac

    if [ "$pass" = true ]; then
        add_finding "sysctl:${key}" "Linux::KernelHardening" "PASS" \
            "${description} (${key} = ${actual})"
    else
        add_finding "sysctl:${key}" "Linux::KernelHardening" "FAIL" \
            "${description} -- ${key} is ${actual}, expected ${expected}"
    fi
}

# ---------------------------------------------------------------------------
# Check all interfaces for a given sysctl parameter
# $1 = sysctl suffix (e.g., "accept_redirects")
# $2 = expected value
# $3 = description prefix
# $4 = ipv4 or ipv6
# ---------------------------------------------------------------------------
check_net_iface_param() {
    local param="$1"
    local expected="$2"
    local desc_prefix="$3"
    local proto="${4:-ipv4}"

    for scope in "all" "default"; do
        local key="net.${proto}.conf.${scope}.${param}"
        check_sysctl "$key" "$expected" "${desc_prefix} (${scope})"
    done
}

# ===========================================================================
# ASLR
# ===========================================================================
check_sysctl "kernel.randomize_va_space" "2" "Full ASLR enabled" "ge"

# ===========================================================================
# Network: SYN cookies
# ===========================================================================
check_sysctl "net.ipv4.tcp_syncookies" "1" "TCP SYN cookies enabled"

# ===========================================================================
# Network: IP forwarding (should be disabled unless router)
# ===========================================================================
check_sysctl "net.ipv4.ip_forward" "0" "IPv4 forwarding disabled"

# IPv6 forwarding
val=$(get_sysctl "net.ipv6.conf.all.forwarding")
if [ -n "$val" ]; then
    check_sysctl "net.ipv6.conf.all.forwarding" "0" "IPv6 forwarding disabled"
fi

# ===========================================================================
# Network: Source routing disabled
# ===========================================================================
check_net_iface_param "accept_source_route" "0" "IPv4 source routing disabled" "ipv4"

# ===========================================================================
# Network: ICMP redirects disabled
# ===========================================================================
check_net_iface_param "accept_redirects" "0" "IPv4 ICMP redirect acceptance disabled" "ipv4"
check_net_iface_param "secure_redirects" "0" "IPv4 secure ICMP redirect acceptance disabled" "ipv4"
check_net_iface_param "send_redirects" "0" "IPv4 ICMP redirect sending disabled" "ipv4"

# IPv6 redirects
val=$(get_sysctl "net.ipv6.conf.all.accept_redirects")
if [ -n "$val" ]; then
    check_net_iface_param "accept_redirects" "0" "IPv6 ICMP redirect acceptance disabled" "ipv6"
fi

# ===========================================================================
# Network: Log martian packets
# ===========================================================================
check_net_iface_param "log_martians" "1" "Martian packet logging enabled" "ipv4"

# ===========================================================================
# Network: Reverse path filtering
# ===========================================================================
check_net_iface_param "rp_filter" "1" "Reverse path filtering enabled" "ipv4"

# ===========================================================================
# Network: TCP RFC1337
# ===========================================================================
check_sysctl "net.ipv4.tcp_rfc1337" "1" "TCP RFC1337 TIME-WAIT assassination protection"

# ===========================================================================
# Network: Bogus ICMP responses
# ===========================================================================
check_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1" "Bogus ICMP error response ignoring"

# ===========================================================================
# Kernel: pointer restriction
# ===========================================================================
check_sysctl "kernel.kptr_restrict" "1" "Kernel pointer address restriction" "ge"

# ===========================================================================
# Kernel: dmesg restriction
# ===========================================================================
check_sysctl "kernel.dmesg_restrict" "1" "Dmesg access restricted to privileged users"

# ===========================================================================
# Kernel: unprivileged BPF
# ===========================================================================
val=$(get_sysctl "kernel.unprivileged_bpf_disabled")
if [ -n "$val" ]; then
    check_sysctl "kernel.unprivileged_bpf_disabled" "1" "Unprivileged BPF disabled"
fi

# ===========================================================================
# Kernel: Yama ptrace scope
# ===========================================================================
val=$(get_sysctl "kernel.yama.ptrace_scope")
if [ -n "$val" ]; then
    check_sysctl "kernel.yama.ptrace_scope" "1" "Yama ptrace scope restricts debugging" "ge"
fi

# ===========================================================================
# Kernel: core dump restrictions
# ===========================================================================
check_sysctl "fs.suid_dumpable" "0" "SUID core dumps disabled"

# Also check /etc/security/limits.conf for core dump limit
if [ -f /etc/security/limits.conf ]; then
    if grep -qE "^\s*\*\s+hard\s+core\s+0" /etc/security/limits.conf 2>/dev/null; then
        add_finding "limits.conf:core-dump" "Linux::KernelHardening" "PASS" \
            "Core dumps restricted in /etc/security/limits.conf"
    else
        add_finding "limits.conf:core-dump" "Linux::KernelHardening" "FAIL" \
            "Core dumps not restricted in /etc/security/limits.conf (add: * hard core 0)"
    fi
else
    add_finding "limits.conf:core-dump" "Linux::KernelHardening" "ERROR" \
        "/etc/security/limits.conf not found"
fi

# ===========================================================================
# Kernel: ExecShield (older kernels) / NX bit
# ===========================================================================
# ExecShield is a legacy parameter; modern kernels use NX bit via CPU feature
if [ -f /proc/cpuinfo ]; then
    if grep -qi "nx" /proc/cpuinfo 2>/dev/null; then
        add_finding "cpu:nx-bit" "Linux::KernelHardening" "PASS" \
            "CPU NX (No-Execute) bit is supported and active"
    else
        add_finding "cpu:nx-bit" "Linux::KernelHardening" "FAIL" \
            "CPU NX (No-Execute) bit not detected"
    fi
fi

findings+="]"
echo "$findings"
