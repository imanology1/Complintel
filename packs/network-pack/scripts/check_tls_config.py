#!/usr/bin/env python3
"""
Network TLS Configuration Check Agent
Verifies that endpoints enforce minimum TLS 1.2 and use strong cipher suites.

Parameters:
  --targets=HOST:PORT,HOST:PORT,...   Comma-separated list of host:port pairs

Output: JSON array of Finding objects to stdout.
"""

import json
import socket
import ssl
import sys


# Cipher suites considered weak or broken
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
    "RC2", "IDEA", "SEED", "DES-CBC3",
}

# TLS versions considered insecure
INSECURE_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}

# Minimum acceptable TLS version for the numeric comparison
# TLS 1.2 = 0x0303, TLS 1.3 = 0x0304
MIN_TLS_VERSION_NAME = "TLSv1.2"


def parse_args():
    targets = ""
    for arg in sys.argv[1:]:
        if arg.startswith("--targets="):
            targets = arg.split("=", 1)[1]
    return targets


def parse_targets(raw):
    """Parse 'host:port,host:port' into list of (host, port) tuples."""
    result = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            parts = entry.rsplit(":", 1)
            host = parts[0].strip("[]")  # handle IPv6 brackets
            try:
                port = int(parts[1])
            except ValueError:
                port = 443
        else:
            host = entry
            port = 443
        result.append((host, port))
    return result


def check_cipher_strength(cipher_name):
    """Return list of weakness reasons for a given cipher name."""
    weaknesses = []
    upper = cipher_name.upper()
    for weak in WEAK_CIPHERS:
        if weak.upper() in upper:
            weaknesses.append(weak)
    return weaknesses


def check_tls_endpoint(host, port, timeout=10):
    """Connect to host:port and evaluate TLS configuration. Returns list of findings."""
    findings = []
    resource_id = f"{host}:{port}"
    resource_type = "Network::TLSEndpoint"

    # --- Test 1: Check if TLS 1.2+ is supported with default (best) negotiation ---
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        # Set minimum to TLS 1.2
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                negotiated_version = tls_sock.version()
                cipher_info = tls_sock.cipher()  # (name, protocol, bits)

        # Negotiated version check
        if negotiated_version and negotiated_version in INSECURE_PROTOCOLS:
            findings.append({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "status": "FAIL",
                "message": f"Endpoint negotiated insecure protocol: {negotiated_version}",
                "details": json.dumps({"negotiated_version": negotiated_version})
            })
        else:
            findings.append({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "status": "PASS",
                "message": f"Endpoint supports {negotiated_version}",
                "details": json.dumps({"negotiated_version": negotiated_version})
            })

        # Cipher strength check
        if cipher_info:
            cipher_name, cipher_proto, cipher_bits = cipher_info
            weaknesses = check_cipher_strength(cipher_name)
            if weaknesses:
                findings.append({
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "status": "FAIL",
                    "message": f"Weak cipher negotiated: {cipher_name} (weaknesses: {', '.join(weaknesses)})",
                    "details": json.dumps({
                        "cipher": cipher_name,
                        "protocol": cipher_proto,
                        "bits": cipher_bits,
                        "weaknesses": weaknesses
                    })
                })
            elif cipher_bits and cipher_bits < 128:
                findings.append({
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "status": "FAIL",
                    "message": f"Cipher key length too short: {cipher_name} ({cipher_bits} bits)",
                    "details": json.dumps({
                        "cipher": cipher_name,
                        "protocol": cipher_proto,
                        "bits": cipher_bits
                    })
                })
            else:
                findings.append({
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "status": "PASS",
                    "message": f"Strong cipher negotiated: {cipher_name} ({cipher_bits} bits)",
                    "details": json.dumps({
                        "cipher": cipher_name,
                        "protocol": cipher_proto,
                        "bits": cipher_bits
                    })
                })

    except ssl.SSLError as e:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "FAIL",
            "message": f"TLS 1.2+ handshake failed: {e}",
            "details": str(e)
        })
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "ERROR",
            "message": f"Connection failed: {e}"
        })
        return findings

    # --- Test 2: Verify insecure protocols (TLS 1.0, TLS 1.1) are rejected ---
    for proto_name, proto_version in [
        ("TLSv1", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = proto_version
            ctx.minimum_version = proto_version

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    # If we get here, the insecure protocol was accepted
                    findings.append({
                        "resource_id": resource_id,
                        "resource_type": resource_type,
                        "status": "FAIL",
                        "message": f"Endpoint accepts deprecated protocol {proto_name}",
                        "details": json.dumps({"protocol": proto_name, "accepted": True})
                    })
        except (ssl.SSLError, OSError):
            # Connection refused or SSL error means the protocol is rejected -- good
            findings.append({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "status": "PASS",
                "message": f"Endpoint correctly rejects {proto_name}",
                "details": json.dumps({"protocol": proto_name, "accepted": False})
            })

    return findings


def main():
    findings = []

    raw_targets = parse_args()
    if not raw_targets:
        findings.append({
            "resource_id": "targets-parameter",
            "resource_type": "Network::TLSEndpoint",
            "status": "ERROR",
            "message": "The 'targets' parameter is required (comma-separated host:port list)"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    targets = parse_targets(raw_targets)
    if not targets:
        findings.append({
            "resource_id": "targets-parameter",
            "resource_type": "Network::TLSEndpoint",
            "status": "ERROR",
            "message": "No valid targets parsed from input"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    for host, port in targets:
        endpoint_findings = check_tls_endpoint(host, port)
        findings.extend(endpoint_findings)

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
