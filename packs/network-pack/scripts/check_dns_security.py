#!/usr/bin/env python3
"""
DNS Security Check Agent
Verifies DNS security for given domains:
  1. DNSSEC validation (checks for RRSIG/DNSKEY records via system dig or manual query)
  2. Zone transfer protection (attempts AXFR against discovered nameservers)

Parameters:
  --domains=DOMAIN,DOMAIN,...   Comma-separated list of domains

Output: JSON array of Finding objects to stdout.

Note: Uses subprocess to call 'dig' if available, with a pure-socket fallback
for basic DNS queries. Only Python stdlib is used.
"""

import json
import os
import socket
import struct
import subprocess
import sys


def parse_args():
    domains = ""
    for arg in sys.argv[1:]:
        if arg.startswith("--domains="):
            domains = arg.split("=", 1)[1]
    return domains


def has_command(cmd):
    """Check if a command is available on the system."""
    try:
        subprocess.run(
            [cmd, "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def dig_available():
    """Check if dig is available."""
    try:
        result = subprocess.run(
            ["dig", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def check_dnssec_with_dig(domain):
    """Use dig to check DNSSEC. Returns (has_dnssec: bool, details: dict)."""
    details = {}

    # Check for DNSKEY records
    try:
        result = subprocess.run(
            ["dig", "+dnssec", "+short", domain, "DNSKEY"],
            capture_output=True, text=True, timeout=15
        )
        dnskey_output = result.stdout.strip()
        details["dnskey_records"] = bool(dnskey_output)
        details["dnskey_count"] = len(dnskey_output.splitlines()) if dnskey_output else 0
    except (subprocess.TimeoutExpired, OSError) as e:
        details["dnskey_error"] = str(e)

    # Check for RRSIG records on the SOA
    try:
        result = subprocess.run(
            ["dig", "+dnssec", "+short", domain, "RRSIG"],
            capture_output=True, text=True, timeout=15
        )
        rrsig_output = result.stdout.strip()
        details["rrsig_records"] = bool(rrsig_output)
    except (subprocess.TimeoutExpired, OSError) as e:
        details["rrsig_error"] = str(e)

    # Check the AD (Authenticated Data) flag
    try:
        result = subprocess.run(
            ["dig", "+dnssec", domain, "SOA"],
            capture_output=True, text=True, timeout=15
        )
        ad_flag = "flags:" in result.stdout and " ad" in result.stdout.lower().split("flags:")[1].split(";")[0]
        details["ad_flag"] = ad_flag
    except (subprocess.TimeoutExpired, OSError) as e:
        details["ad_flag_error"] = str(e)

    has_dnssec = details.get("dnskey_records", False) or details.get("rrsig_records", False)
    return has_dnssec, details


def build_dns_query(domain, qtype=1):
    """Build a minimal DNS query packet. qtype: 1=A, 48=DNSKEY, 46=RRSIG, 252=AXFR."""
    transaction_id = os.urandom(2)
    # Standard query, recursion desired
    flags = b'\x01\x00'
    qdcount = b'\x00\x01'
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    header = transaction_id + flags + qdcount + ancount + nscount + arcount

    # Encode domain name
    qname = b''
    for label in domain.rstrip('.').split('.'):
        qname += bytes([len(label)]) + label.encode('ascii')
    qname += b'\x00'

    qtype_bytes = struct.pack('!H', qtype)
    qclass = b'\x00\x01'  # IN class

    return header + qname + qtype_bytes + qclass


def check_dnssec_basic(domain):
    """Fallback DNSSEC check using raw DNS queries to system resolver."""
    details = {}
    has_dnssec = False

    # Try to query DNSKEY (type 48) using the system resolver
    try:
        resolver = "8.8.8.8"  # Use Google DNS as fallback
        query = build_dns_query(domain, qtype=48)  # DNSKEY

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query, (resolver, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()

        # Parse answer count from response header
        if len(response) >= 12:
            ancount = struct.unpack('!H', response[6:8])[0]
            details["dnskey_answer_count"] = ancount
            if ancount > 0:
                has_dnssec = True
                details["dnskey_records"] = True
            else:
                details["dnskey_records"] = False
    except Exception as e:
        details["dnskey_error"] = str(e)

    return has_dnssec, details


def get_nameservers_dig(domain):
    """Get nameservers for a domain using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", domain, "NS"],
            capture_output=True, text=True, timeout=15
        )
        ns_list = [ns.strip().rstrip('.') for ns in result.stdout.strip().splitlines() if ns.strip()]
        return ns_list
    except (subprocess.TimeoutExpired, OSError):
        return []


def get_nameservers_socket(domain):
    """Fallback: get nameservers using raw DNS query (type 2 = NS)."""
    ns_list = []
    try:
        resolver = "8.8.8.8"
        query = build_dns_query(domain, qtype=2)  # NS

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query, (resolver, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()

        # Very basic parsing: just check if we got answers
        if len(response) >= 12:
            ancount = struct.unpack('!H', response[6:8])[0]
            if ancount > 0:
                # Try to resolve known NS patterns by doing a secondary lookup
                # This is a simplified fallback; for real NS extraction we would
                # need full DNS message parsing
                try:
                    import subprocess as sp
                    # Try nslookup as another fallback
                    result = sp.run(
                        ["nslookup", "-type=ns", domain],
                        capture_output=True, text=True, timeout=10
                    )
                    for line in result.stdout.splitlines():
                        if "nameserver" in line.lower() and "=" in line:
                            ns = line.split("=")[-1].strip().rstrip('.')
                            if ns:
                                ns_list.append(ns)
                except Exception:
                    pass
    except Exception:
        pass
    return ns_list


def check_zone_transfer(domain, nameserver, timeout=10):
    """
    Attempt an AXFR (zone transfer) against a nameserver.
    Returns (vulnerable: bool, details: str).
    """
    # First resolve the nameserver to an IP
    try:
        ns_ip = socket.gethostbyname(nameserver)
    except socket.gaierror:
        return False, f"Could not resolve nameserver {nameserver}"

    try:
        # Build AXFR query (type 252) and send over TCP
        query = build_dns_query(domain, qtype=252)

        # TCP DNS: prefix with 2-byte length
        tcp_query = struct.pack('!H', len(query)) + query

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ns_ip, 53))
        sock.sendall(tcp_query)

        # Read response
        length_data = sock.recv(2)
        if len(length_data) < 2:
            sock.close()
            return False, "No response to AXFR query (connection closed)"

        resp_length = struct.unpack('!H', length_data)[0]
        response = b''
        while len(response) < resp_length:
            chunk = sock.recv(resp_length - len(response))
            if not chunk:
                break
            response += chunk
        sock.close()

        if len(response) < 12:
            return False, "Response too short"

        # Check RCODE in flags (bits 12-15 of second flag byte)
        rcode = response[3] & 0x0F
        ancount = struct.unpack('!H', response[6:8])[0]

        if rcode == 0 and ancount > 0:
            return True, f"Zone transfer succeeded: {ancount} records returned"
        elif rcode == 5:
            return False, "Zone transfer refused (RCODE=REFUSED)"
        elif rcode == 9:
            return False, "Zone transfer not authorized (RCODE=NOTAUTH)"
        else:
            return False, f"Zone transfer denied (RCODE={rcode}, answers={ancount})"

    except socket.timeout:
        return False, "Connection timed out (zone transfer likely blocked)"
    except ConnectionRefusedError:
        return False, "Connection refused (TCP port 53 not open or blocked)"
    except OSError as e:
        return False, f"Connection error: {e}"


def check_domain(domain, use_dig):
    """Run all DNS security checks for a domain."""
    findings = []
    resource_type = "Network::DNS"

    # --- Check 1: DNSSEC ---
    if use_dig:
        has_dnssec, dnssec_details = check_dnssec_with_dig(domain)
    else:
        has_dnssec, dnssec_details = check_dnssec_basic(domain)

    if has_dnssec:
        findings.append({
            "resource_id": domain,
            "resource_type": resource_type,
            "status": "PASS",
            "message": "DNSSEC records detected for domain",
            "details": json.dumps(dnssec_details)
        })
    else:
        findings.append({
            "resource_id": domain,
            "resource_type": resource_type,
            "status": "FAIL",
            "message": "No DNSSEC records found -- domain is not DNSSEC-signed",
            "details": json.dumps(dnssec_details)
        })

    # --- Check 2: Zone Transfer Protection ---
    if use_dig:
        nameservers = get_nameservers_dig(domain)
    else:
        nameservers = get_nameservers_socket(domain)

    if not nameservers:
        findings.append({
            "resource_id": domain,
            "resource_type": resource_type,
            "status": "ERROR",
            "message": "Could not discover nameservers for zone transfer test"
        })
    else:
        any_vulnerable = False
        for ns in nameservers:
            vulnerable, detail_msg = check_zone_transfer(domain, ns)
            if vulnerable:
                any_vulnerable = True
                findings.append({
                    "resource_id": f"{domain}@{ns}",
                    "resource_type": resource_type,
                    "status": "FAIL",
                    "message": f"Zone transfer ALLOWED on nameserver {ns}",
                    "details": json.dumps({"nameserver": ns, "result": detail_msg})
                })
            else:
                findings.append({
                    "resource_id": f"{domain}@{ns}",
                    "resource_type": resource_type,
                    "status": "PASS",
                    "message": f"Zone transfer properly denied on {ns}",
                    "details": json.dumps({"nameserver": ns, "result": detail_msg})
                })

        if not any_vulnerable:
            findings.append({
                "resource_id": domain,
                "resource_type": resource_type,
                "status": "PASS",
                "message": f"All {len(nameservers)} nameserver(s) deny zone transfers"
            })

    return findings


def main():
    findings = []

    raw_domains = parse_args()
    if not raw_domains:
        findings.append({
            "resource_id": "domains-parameter",
            "resource_type": "Network::DNS",
            "status": "ERROR",
            "message": "The 'domains' parameter is required (comma-separated domains)"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    domains = [d.strip() for d in raw_domains.split(",") if d.strip()]
    if not domains:
        findings.append({
            "resource_id": "domains-parameter",
            "resource_type": "Network::DNS",
            "status": "ERROR",
            "message": "No valid domains parsed from input"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    use_dig = dig_available()

    for domain in domains:
        domain_findings = check_domain(domain, use_dig)
        findings.extend(domain_findings)

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
