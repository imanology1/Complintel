#!/usr/bin/env bash
# Linux Unnecessary Services Check Agent
# Detects running services that should be disabled on hardened systems.
#
# Checks for:
#   - Legacy insecure services: telnet, rsh, rlogin, rexec, tftp
#   - Unencrypted file/print: ftp (vsftpd/proftpd), nfs, smb
#   - Unnecessary network: avahi-daemon, cups (if not needed), xinetd
#   - SNMP with default communities
#   - NIS (ypserv, ypbind)
#   - LDAP server (if not intentional)
#   - Talk, chargen, daytime, discard, echo services
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
# Helper: check if a service is active (systemd or process)
# ---------------------------------------------------------------------------
is_service_active() {
    local svc_name="$1"
    if systemctl is-active "$svc_name" &>/dev/null 2>&1; then
        return 0
    fi
    # Fallback: check for running process
    if pgrep -x "$svc_name" &>/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Helper: check if a service is enabled at boot
# ---------------------------------------------------------------------------
is_service_enabled() {
    local svc_name="$1"
    systemctl is-enabled "$svc_name" &>/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# Helper: check listening port
# ---------------------------------------------------------------------------
is_port_listening() {
    local port="$1"
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep -qE ":${port}\s" && return 0
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep -qE ":${port}\s" && return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Critical insecure services (MUST be disabled)
# ---------------------------------------------------------------------------
declare -A critical_services
critical_services=(
    ["telnet.socket"]="Telnet server (unencrypted remote access)"
    ["telnetd"]="Telnet daemon (unencrypted remote access)"
    ["rsh.socket"]="RSH server (unencrypted, no authentication)"
    ["rsh"]="RSH daemon (unencrypted, no authentication)"
    ["rlogin.socket"]="Rlogin server (unencrypted remote login)"
    ["rlogin"]="Rlogin daemon (unencrypted remote login)"
    ["rexec.socket"]="Rexec server (unencrypted remote execution)"
    ["rexec"]="Rexec daemon (unencrypted remote execution)"
    ["xinetd"]="xinetd super-server (legacy, often insecure)"
    ["ypserv"]="NIS server (insecure directory service)"
    ["ypbind"]="NIS client (insecure directory service)"
    ["tftpd"]="TFTP daemon (unauthenticated file transfer)"
    ["tftp.socket"]="TFTP socket (unauthenticated file transfer)"
)

critical_fail=0
for svc in "${!critical_services[@]}"; do
    desc="${critical_services[$svc]}"
    if is_service_active "$svc" || is_service_enabled "$svc"; then
        add_finding "service:${svc}" "Linux::UnnecessaryService" "FAIL" \
            "${desc} is active or enabled -- must be disabled"
        critical_fail=$((critical_fail + 1))
    fi
done

if [ "$critical_fail" -eq 0 ]; then
    add_finding "services:critical-insecure" "Linux::UnnecessaryService" "PASS" \
        "No critical insecure services (telnet, rsh, rlogin, rexec, NIS, tftp, xinetd) detected"
fi

# ---------------------------------------------------------------------------
# Legacy inetd/xinetd services by port
# ---------------------------------------------------------------------------
declare -A legacy_ports
legacy_ports=(
    ["7"]="echo"
    ["9"]="discard"
    ["13"]="daytime"
    ["17"]="qotd"
    ["19"]="chargen"
    ["37"]="time"
    ["512"]="rexec"
    ["513"]="rlogin"
    ["514"]="rsh"
)

legacy_fail=0
for port in "${!legacy_ports[@]}"; do
    svc_name="${legacy_ports[$port]}"
    if is_port_listening "$port"; then
        add_finding "port:${port}/${svc_name}" "Linux::UnnecessaryService" "FAIL" \
            "Legacy ${svc_name} service detected listening on port ${port}"
        legacy_fail=$((legacy_fail + 1))
    fi
done

if [ "$legacy_fail" -eq 0 ]; then
    add_finding "services:legacy-ports" "Linux::UnnecessaryService" "PASS" \
        "No legacy inetd services listening (echo, discard, daytime, chargen, etc.)"
fi

# ---------------------------------------------------------------------------
# Advisory services (might be needed, flag as informational)
# ---------------------------------------------------------------------------
declare -A advisory_services
advisory_services=(
    ["avahi-daemon"]="Avahi mDNS/DNS-SD daemon (auto-discovery, usually not needed on servers)"
    ["cups"]="CUPS printing service (usually not needed on servers)"
    ["vsftpd"]="FTP server (use SFTP instead)"
    ["proftpd"]="FTP server (use SFTP instead)"
    ["smbd"]="Samba file sharing"
    ["nmbd"]="Samba NetBIOS name service"
    ["snmpd"]="SNMP daemon (check community strings)"
    ["slapd"]="OpenLDAP server"
    ["named"]="BIND DNS server (verify if intentional)"
    ["dhcpd"]="DHCP server (verify if intentional)"
    ["squid"]="Squid proxy server (verify if intentional)"
    ["dovecot"]="IMAP/POP3 mail server (verify if intentional)"
    ["postfix"]="Postfix mail server (check if needed)"
    ["sendmail"]="Sendmail (legacy MTA, use postfix instead)"
)

advisory_found=0
for svc in "${!advisory_services[@]}"; do
    desc="${advisory_services[$svc]}"
    if is_service_active "$svc"; then
        add_finding "service:${svc}" "Linux::UnnecessaryService" "FAIL" \
            "${desc} -- review if this service is needed"
        advisory_found=$((advisory_found + 1))
    fi
done

if [ "$advisory_found" -eq 0 ]; then
    add_finding "services:advisory" "Linux::UnnecessaryService" "PASS" \
        "No commonly unnecessary advisory services detected"
fi

# ---------------------------------------------------------------------------
# SNMP community string check
# ---------------------------------------------------------------------------
if [ -f /etc/snmp/snmpd.conf ]; then
    if grep -qE "^\s*(rocommunity|rwcommunity)\s+(public|private)" /etc/snmp/snmpd.conf 2>/dev/null; then
        add_finding "snmpd:community-string" "Linux::UnnecessaryService" "FAIL" \
            "SNMP is using default community strings (public/private)"
    elif is_service_active "snmpd"; then
        add_finding "snmpd:community-string" "Linux::UnnecessaryService" "PASS" \
            "SNMP is running with non-default community strings"
    fi
fi

# ---------------------------------------------------------------------------
# Check for talk/ntalk
# ---------------------------------------------------------------------------
for talk_svc in "talk" "ntalk" "talk.socket" "ntalk.socket"; do
    if is_service_active "$talk_svc" || is_service_enabled "$talk_svc"; then
        add_finding "service:${talk_svc}" "Linux::UnnecessaryService" "FAIL" \
            "Talk service is active or enabled -- should be disabled"
    fi
done

findings+="]"
echo "$findings"
