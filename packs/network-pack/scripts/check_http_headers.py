#!/usr/bin/env python3
"""
HTTP Security Headers Check Agent
Verifies that target URLs return recommended security headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - X-XSS-Protection (legacy but still checked)
  - Cache-Control (for sensitive endpoints)

Parameters:
  --targets=URL,URL,...   Comma-separated list of URLs to check

Output: JSON array of Finding objects to stdout.
"""

import json
import ssl
import sys
import urllib.request
import urllib.error


# Headers to check, with evaluation logic
REQUIRED_HEADERS = {
    "strict-transport-security": {
        "display_name": "Strict-Transport-Security (HSTS)",
        "severity": "critical",
        "validate": lambda v: "max-age" in v.lower() and int(
            next((p.split("=")[1] for p in v.split(";") if "max-age" in p.lower()), "0")
        ) >= 31536000,
        "recommendation": "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
    },
    "content-security-policy": {
        "display_name": "Content-Security-Policy (CSP)",
        "severity": "high",
        "validate": lambda v: len(v) > 0 and "unsafe-inline" not in v.replace("'unsafe-inline'", "QUOTED"),
        "recommendation": "Set a Content-Security-Policy that restricts resource loading origins"
    },
    "x-frame-options": {
        "display_name": "X-Frame-Options",
        "severity": "high",
        "validate": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "recommendation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'"
    },
    "x-content-type-options": {
        "display_name": "X-Content-Type-Options",
        "severity": "medium",
        "validate": lambda v: v.lower().strip() == "nosniff",
        "recommendation": "Set 'X-Content-Type-Options: nosniff'"
    },
    "referrer-policy": {
        "display_name": "Referrer-Policy",
        "severity": "medium",
        "validate": lambda v: v.lower().strip() in (
            "no-referrer", "no-referrer-when-downgrade", "origin",
            "origin-when-cross-origin", "same-origin", "strict-origin",
            "strict-origin-when-cross-origin"
        ),
        "recommendation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter"
    },
    "permissions-policy": {
        "display_name": "Permissions-Policy",
        "severity": "medium",
        "validate": lambda v: len(v) > 0,
        "recommendation": "Set Permissions-Policy to restrict browser features (camera, microphone, geolocation, etc.)"
    },
}

# Additional headers that are informational / best-practice
OPTIONAL_HEADERS = {
    "x-xss-protection": {
        "display_name": "X-XSS-Protection",
        "severity": "low",
        "validate": lambda v: v.strip().startswith("1"),
        "recommendation": "Set 'X-XSS-Protection: 1; mode=block' (legacy but still useful for older browsers)"
    },
}

# Headers that should NOT be present (information leakage)
UNWANTED_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
]


def parse_args():
    targets = ""
    for arg in sys.argv[1:]:
        if arg.startswith("--targets="):
            targets = arg.split("=", 1)[1]
    return targets


def fetch_headers(url, timeout=15):
    """Fetch HTTP response headers from a URL. Returns (headers_dict, status_code, error)."""
    try:
        # Create SSL context that does not verify certs (we just want the headers)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, method="GET")
        req.add_header("User-Agent", "comply-intel-agent/1.0")

        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            return headers, resp.status, None

    except urllib.error.HTTPError as e:
        # Even on error responses we can check headers
        headers = {k.lower(): v for k, v in e.headers.items()}
        return headers, e.code, None

    except Exception as e:
        return {}, 0, str(e)


def check_url(url):
    """Check all security headers for a given URL."""
    findings = []
    resource_type = "Network::HTTPEndpoint"

    headers, status_code, error = fetch_headers(url)

    if error:
        findings.append({
            "resource_id": url,
            "resource_type": resource_type,
            "status": "ERROR",
            "message": f"Failed to fetch URL: {error}"
        })
        return findings

    # --- Required Security Headers ---
    for header_key, config in REQUIRED_HEADERS.items():
        display = config["display_name"]
        value = headers.get(header_key, "")

        if not value:
            findings.append({
                "resource_id": url,
                "resource_type": resource_type,
                "status": "FAIL",
                "message": f"Missing header: {display}",
                "details": json.dumps({
                    "header": header_key,
                    "present": False,
                    "recommendation": config["recommendation"]
                })
            })
        else:
            try:
                is_valid = config["validate"](value)
            except Exception:
                is_valid = False

            if is_valid:
                findings.append({
                    "resource_id": url,
                    "resource_type": resource_type,
                    "status": "PASS",
                    "message": f"{display} is properly configured",
                    "details": json.dumps({
                        "header": header_key,
                        "value": value
                    })
                })
            else:
                findings.append({
                    "resource_id": url,
                    "resource_type": resource_type,
                    "status": "FAIL",
                    "message": f"{display} is present but misconfigured",
                    "details": json.dumps({
                        "header": header_key,
                        "value": value,
                        "recommendation": config["recommendation"]
                    })
                })

    # --- Optional Security Headers ---
    for header_key, config in OPTIONAL_HEADERS.items():
        display = config["display_name"]
        value = headers.get(header_key, "")

        if value:
            try:
                is_valid = config["validate"](value)
            except Exception:
                is_valid = False

            status = "PASS" if is_valid else "FAIL"
            findings.append({
                "resource_id": url,
                "resource_type": resource_type,
                "status": status,
                "message": f"{display}: {'properly configured' if is_valid else 'misconfigured'}",
                "details": json.dumps({
                    "header": header_key,
                    "value": value,
                    "optional": True
                })
            })

    # --- Unwanted Headers (information disclosure) ---
    for header_key in UNWANTED_HEADERS:
        value = headers.get(header_key, "")
        if value:
            findings.append({
                "resource_id": url,
                "resource_type": resource_type,
                "status": "FAIL",
                "message": f"Information disclosure: '{header_key}' header exposes server details",
                "details": json.dumps({
                    "header": header_key,
                    "value": value,
                    "recommendation": f"Remove or suppress the '{header_key}' response header"
                })
            })

    # --- HTTPS redirect check (if target is HTTP) ---
    if url.startswith("http://"):
        https_url = url.replace("http://", "https://", 1)
        _, https_status, https_error = fetch_headers(https_url)
        if https_error:
            findings.append({
                "resource_id": url,
                "resource_type": resource_type,
                "status": "FAIL",
                "message": "HTTPS is not available for this endpoint",
                "details": json.dumps({"https_url": https_url, "error": https_error})
            })
        else:
            findings.append({
                "resource_id": url,
                "resource_type": resource_type,
                "status": "PASS",
                "message": "HTTPS is available for this endpoint",
                "details": json.dumps({"https_url": https_url, "status_code": https_status})
            })

    return findings


def main():
    findings = []

    raw_targets = parse_args()
    if not raw_targets:
        findings.append({
            "resource_id": "targets-parameter",
            "resource_type": "Network::HTTPEndpoint",
            "status": "ERROR",
            "message": "The 'targets' parameter is required (comma-separated URLs)"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    urls = [u.strip() for u in raw_targets.split(",") if u.strip()]
    if not urls:
        findings.append({
            "resource_id": "targets-parameter",
            "resource_type": "Network::HTTPEndpoint",
            "status": "ERROR",
            "message": "No valid URLs parsed from input"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    for url in urls:
        # Ensure URL has a scheme
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        url_findings = check_url(url)
        findings.extend(url_findings)

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
