#!/usr/bin/env python3
"""
TLS Certificate Expiry Check Agent
Connects to endpoints and checks certificate validity and expiration dates.

Parameters:
  --targets=HOST:PORT,HOST:PORT,...  Comma-separated host:port list
  --warn_days=30                     Days before expiry to trigger a warning (default: 30)

Output: JSON array of Finding objects to stdout.
"""

import datetime
import json
import socket
import ssl
import sys


def parse_args():
    targets = ""
    warn_days = "30"
    for arg in sys.argv[1:]:
        if arg.startswith("--targets="):
            targets = arg.split("=", 1)[1]
        elif arg.startswith("--warn_days="):
            warn_days = arg.split("=", 1)[1]
    try:
        warn_days = int(warn_days)
    except ValueError:
        warn_days = 30
    return targets, warn_days


def parse_targets(raw):
    """Parse 'host:port,host:port' into list of (host, port) tuples."""
    result = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            parts = entry.rsplit(":", 1)
            host = parts[0].strip("[]")
            try:
                port = int(parts[1])
            except ValueError:
                port = 443
        else:
            host = entry
            port = 443
        result.append((host, port))
    return result


def parse_cert_date(date_str):
    """Parse the date string from ssl.getpeercert() into a datetime object."""
    # OpenSSL format: 'Mon DD HH:MM:SS YYYY GMT'
    # e.g. 'Jan  5 09:30:00 2025 GMT'
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b  %d %H:%M:%S %Y %Z",
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    # Fallback: try generic parsing
    raise ValueError(f"Cannot parse certificate date: {date_str}")


def get_certificate_info(host, port, timeout=10):
    """Connect to host:port and retrieve the TLS certificate details."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # We need the cert but want to connect even if CA is not in our trust store
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            # getpeercert(binary_form=True) always works; getpeercert() needs CERT_REQUIRED
            cert_bin = tls_sock.getpeercert(binary_form=True)

    # Now decode the certificate using a verifying context to get the dict form
    # We use load_der_x509_certificate equivalent via ssl
    cert_dict = ssl.DER_cert_to_PEM_cert(cert_bin)

    # Re-connect with verification disabled but get the parsed cert
    # by temporarily setting verify_mode
    context2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context2.check_hostname = False
    context2.verify_mode = ssl.CERT_NONE

    # Use the _ssl module trick: wrap and get binary, then decode
    # Actually, the simplest reliable way is to reconnect with CERT_NONE
    # and use getpeercert with binary_form=False by loading the cert into a temp context
    # Let's use a different approach: connect once more with CERT_OPTIONAL
    context3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context3.check_hostname = False
    context3.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context3.wrap_socket(sock, server_hostname=host) as tls_sock:
            # With CERT_NONE, getpeercert() returns empty dict
            # We need to parse from the binary cert
            pass

    # Parse the binary cert using ssl helper
    return parse_cert_from_binary(cert_bin, host)


def parse_cert_from_binary(cert_bin, host):
    """Extract certificate information from DER-encoded binary certificate."""
    # Use a memory-based approach: load cert into a context to decode
    pem = ssl.DER_cert_to_PEM_cert(cert_bin)

    # We can get the parsed cert by creating a temporary connection to ourselves
    # or by using the ssl module's internal parsing.
    # Since we want stdlib only, let's do a direct ASN.1 parse for the dates.
    info = {
        "subject": "",
        "issuer": "",
        "not_before": None,
        "not_after": None,
        "san": [],
        "serial": "",
    }

    # Parse dates from DER using basic ASN.1 extraction
    not_before, not_after = extract_validity_from_der(cert_bin)
    info["not_before"] = not_before
    info["not_after"] = not_after

    # Extract subject CN from DER (simplified)
    info["subject"] = extract_cn_from_der(cert_bin, host)

    return info


def extract_validity_from_der(der_bytes):
    """
    Extract notBefore and notAfter from a DER-encoded X.509 certificate.
    This does basic ASN.1 parsing to find the validity sequence.
    """
    not_before = None
    not_after = None

    # Find UTCTime (tag 0x17) or GeneralizedTime (tag 0x18) patterns
    # In a typical X.509 cert, there are exactly 2 time fields in the Validity sequence
    times = []
    i = 0
    while i < len(der_bytes) - 2:
        tag = der_bytes[i]
        if tag in (0x17, 0x18):  # UTCTime or GeneralizedTime
            length = der_bytes[i + 1]
            if length < 128 and i + 2 + length <= len(der_bytes):
                time_str = der_bytes[i + 2:i + 2 + length].decode('ascii', errors='ignore')
                parsed = parse_asn1_time(tag, time_str)
                if parsed:
                    times.append(parsed)
                if len(times) >= 2:
                    break
            i += 2 + length
        else:
            i += 1

    if len(times) >= 2:
        not_before = times[0]
        not_after = times[1]
    elif len(times) == 1:
        not_after = times[0]

    return not_before, not_after


def parse_asn1_time(tag, time_str):
    """Parse ASN.1 UTCTime or GeneralizedTime string to datetime."""
    try:
        time_str = time_str.rstrip('Z').rstrip('\x00')
        if tag == 0x17:  # UTCTime: YYMMDDHHMMSSZ
            if len(time_str) >= 12:
                year = int(time_str[0:2])
                year += 2000 if year < 50 else 1900
                return datetime.datetime(
                    year, int(time_str[2:4]), int(time_str[4:6]),
                    int(time_str[6:8]), int(time_str[8:10]), int(time_str[10:12])
                )
        elif tag == 0x18:  # GeneralizedTime: YYYYMMDDHHMMSSZ
            if len(time_str) >= 14:
                return datetime.datetime(
                    int(time_str[0:4]), int(time_str[4:6]), int(time_str[6:8]),
                    int(time_str[8:10]), int(time_str[10:12]), int(time_str[12:14])
                )
    except (ValueError, IndexError):
        pass
    return None


def extract_cn_from_der(der_bytes, fallback_host):
    """Try to extract the Common Name from a DER certificate. Returns fallback on failure."""
    # Look for the OID for commonName: 2.5.4.3 => 55 04 03
    oid_cn = bytes([0x55, 0x04, 0x03])
    idx = der_bytes.find(oid_cn)
    if idx == -1:
        return fallback_host

    # After the OID, there should be a string tag (UTF8String=0x0C, PrintableString=0x13, etc.)
    search_start = idx + len(oid_cn)
    if search_start + 2 >= len(der_bytes):
        return fallback_host

    tag = der_bytes[search_start]
    length = der_bytes[search_start + 1]
    if tag in (0x0C, 0x13, 0x16) and length < 128:
        cn_start = search_start + 2
        cn_end = cn_start + length
        if cn_end <= len(der_bytes):
            return der_bytes[cn_start:cn_end].decode('utf-8', errors='replace')

    return fallback_host


def check_certificate(host, port, warn_days, timeout=10):
    """Check certificate expiry for a single endpoint."""
    findings = []
    resource_id = f"{host}:{port}"
    resource_type = "Network::TLSCertificate"
    now = datetime.datetime.utcnow()

    try:
        cert_info = get_certificate_info(host, port, timeout)
    except ssl.SSLError as e:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "ERROR",
            "message": f"TLS handshake failed: {e}"
        })
        return findings
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "ERROR",
            "message": f"Connection failed: {e}"
        })
        return findings
    except Exception as e:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "ERROR",
            "message": f"Certificate parsing error: {e}"
        })
        return findings

    not_before = cert_info.get("not_before")
    not_after = cert_info.get("not_after")
    subject = cert_info.get("subject", resource_id)

    if not not_after:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "ERROR",
            "message": "Could not determine certificate expiration date",
            "details": json.dumps({"subject": subject})
        })
        return findings

    days_remaining = (not_after - now).days

    cert_details = {
        "subject": subject,
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "warn_threshold_days": warn_days
    }

    # Check if certificate has not yet become valid
    if not_before and now < not_before:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "FAIL",
            "message": f"Certificate is not yet valid (starts {not_before.strftime('%Y-%m-%d')})",
            "details": json.dumps(cert_details)
        })

    # Check expiration
    if days_remaining < 0:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "FAIL",
            "message": f"Certificate EXPIRED {abs(days_remaining)} day(s) ago on {not_after.strftime('%Y-%m-%d')}",
            "details": json.dumps(cert_details)
        })
    elif days_remaining <= warn_days:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "FAIL",
            "message": f"Certificate expires in {days_remaining} day(s) on {not_after.strftime('%Y-%m-%d')} (within {warn_days}-day warning threshold)",
            "details": json.dumps(cert_details)
        })
    else:
        findings.append({
            "resource_id": resource_id,
            "resource_type": resource_type,
            "status": "PASS",
            "message": f"Certificate valid for {days_remaining} more day(s) (expires {not_after.strftime('%Y-%m-%d')})",
            "details": json.dumps(cert_details)
        })

    # Check certificate lifetime (warn if > 398 days per CA/B Forum)
    if not_before and not_after:
        lifetime_days = (not_after - not_before).days
        if lifetime_days > 398:
            findings.append({
                "resource_id": resource_id,
                "resource_type": resource_type,
                "status": "FAIL",
                "message": f"Certificate lifetime ({lifetime_days} days) exceeds CA/Browser Forum maximum of 398 days",
                "details": json.dumps({
                    "subject": subject,
                    "lifetime_days": lifetime_days,
                    "max_recommended": 398
                })
            })

    return findings


def main():
    findings = []

    raw_targets, warn_days = parse_args()

    if not raw_targets:
        findings.append({
            "resource_id": "targets-parameter",
            "resource_type": "Network::TLSCertificate",
            "status": "ERROR",
            "message": "The 'targets' parameter is required (comma-separated host:port)"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    targets = parse_targets(raw_targets)
    if not targets:
        findings.append({
            "resource_id": "targets-parameter",
            "resource_type": "Network::TLSCertificate",
            "status": "ERROR",
            "message": "No valid targets parsed from input"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    for host, port in targets:
        cert_findings = check_certificate(host, port, warn_days)
        findings.extend(cert_findings)

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
