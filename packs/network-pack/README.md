# Network Security Agent Pack

Network-layer compliance checks for TLS configuration, open ports, DNS security, HTTP security headers, and certificate lifecycle management.

## Checks

| ID | Description | Severity | Frameworks |
|----|-------------|----------|------------|
| `tls-config` | Verify TLS configuration on endpoints (minimum TLS 1.2, strong ciphers) | Critical | SOC2-CC6.1, NIST-SC-8, PCI-DSS-4.1, CIS-AWS-2.4 |
| `open-ports` | Scan for unexpected open ports on target hosts | High | SOC2-CC6.6, NIST-CM-7, PCI-DSS-1.1, CIS-Linux-3.5 |
| `dns-security` | Verify DNS security (DNSSEC support, no zone transfer leaks) | Medium | SOC2-CC6.6, NIST-SC-20 |
| `http-headers` | Check HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) | High | SOC2-CC6.1, NIST-SI-10, PCI-DSS-6.5, CIS-AWS-2.5 |
| `certificate-expiry` | Check TLS certificate expiration dates | Critical | SOC2-CC6.1, NIST-SC-17, PCI-DSS-4.1 |

## Prerequisites

- Python 3.6+
- No external dependencies -- all scripts use only the Python standard library

## Parameters

### tls-config

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `targets` | Yes | -- | Comma-separated `host:port` list (e.g., `example.com:443,api.example.com:8443`) |

### open-ports

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `targets` | Yes | -- | Comma-separated hostnames or IPs |
| `allowed_ports` | No | `22,80,443` | Comma-separated list of ports considered acceptable |

### dns-security

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `domains` | Yes | -- | Comma-separated domain names |

### http-headers

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `targets` | Yes | -- | Comma-separated URLs (e.g., `https://example.com,https://api.example.com`) |

### certificate-expiry

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `targets` | Yes | -- | Comma-separated `host:port` list |
| `warn_days` | No | `30` | Number of days before expiry to flag as a warning |

## Usage Examples

```bash
# Check TLS configuration
python3 scripts/check_tls_config.py --targets=example.com:443,api.example.com:443

# Scan for unexpected open ports
python3 scripts/check_open_ports.py --targets=192.168.1.1,10.0.0.1 --allowed_ports=22,80,443

# Verify DNS security
python3 scripts/check_dns_security.py --domains=example.com,example.org

# Check HTTP security headers
python3 scripts/check_http_headers.py --targets=https://example.com,https://api.example.com

# Check certificate expiry (warn if < 60 days)
python3 scripts/check_cert_expiry.py --targets=example.com:443 --warn_days=60
```

## Example Findings

```json
[
  {
    "resource_id": "example.com:443",
    "resource_type": "Network::TLSEndpoint",
    "status": "PASS",
    "message": "Endpoint supports TLSv1.3"
  },
  {
    "resource_id": "example.com:443",
    "resource_type": "Network::TLSCertificate",
    "status": "FAIL",
    "message": "Certificate expires in 12 day(s) on 2025-06-15 (within 30-day warning threshold)"
  },
  {
    "resource_id": "10.0.0.1:3306",
    "resource_type": "Network::Host",
    "status": "FAIL",
    "message": "Unexpected open port: 3306/MySQL"
  }
]
```

## What Each Check Does

### tls-config
- Connects to each target and negotiates TLS, verifying the highest supported version
- Checks that the negotiated cipher suite uses strong algorithms (no RC4, DES, 3DES, NULL, EXPORT, or MD5)
- Verifies that key length is at least 128 bits
- Actively probes to confirm that TLS 1.0 and TLS 1.1 are rejected by the server

### open-ports
- Performs a TCP connect scan against 55+ common service ports on each target host
- Compares discovered open ports against the allowed list
- Uses concurrent connections for fast scanning without external tools
- Reports each unexpected open port with its associated service name

### dns-security
- Queries for DNSKEY and RRSIG records to determine whether the domain is DNSSEC-signed
- Discovers authoritative nameservers and attempts AXFR (zone transfer) against each one
- Uses `dig` when available, falls back to raw DNS socket queries otherwise

### http-headers
- Fetches each target URL and inspects the response headers
- Checks for required headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Validates header values (e.g., HSTS max-age >= 1 year, X-Frame-Options is DENY or SAMEORIGIN)
- Flags information-leaking headers: Server, X-Powered-By, X-AspNet-Version

### certificate-expiry
- Retrieves the TLS certificate from each endpoint
- Parses the notBefore/notAfter validity dates from the DER-encoded certificate
- Flags certificates that are expired, expiring within the warning threshold, or not yet valid
- Warns if certificate lifetime exceeds the CA/Browser Forum 398-day maximum
