#!/usr/bin/env python3
"""
Network Open Ports Check Agent
Scans target hosts for unexpected open ports using Python stdlib sockets.

Parameters:
  --targets=HOST,HOST,...         Comma-separated list of hosts
  --allowed_ports=22,80,443      Comma-separated list of allowed ports (default: 22,80,443)

Output: JSON array of Finding objects to stdout.
"""

import json
import socket
import sys
import concurrent.futures


# Common ports to scan -- covers well-known service ports
SCAN_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 162,
    389, 443, 445, 465, 514, 587, 636, 993, 995, 1080, 1433, 1434,
    1521, 2049, 2181, 3306, 3389, 4443, 5432, 5672, 5900, 5984,
    6379, 6443, 7001, 8000, 8080, 8443, 8888, 9090, 9200, 9300,
    9418, 11211, 15672, 27017, 27018, 28017, 50070, 50075,
]

# Map of common ports to their typical service names
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-Browser",
    1521: "Oracle-DB", 2049: "NFS", 2181: "ZooKeeper",
    3306: "MySQL", 3389: "RDP", 4443: "HTTPS-Alt",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC",
    5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes-API",
    7001: "WebLogic", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "HTTP-Alt",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    9418: "Git", 11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    27017: "MongoDB", 27018: "MongoDB", 28017: "MongoDB-HTTP",
    50070: "HDFS-NameNode", 50075: "HDFS-DataNode",
}


def parse_args():
    targets = ""
    allowed_ports = "22,80,443"
    for arg in sys.argv[1:]:
        if arg.startswith("--targets="):
            targets = arg.split("=", 1)[1]
        elif arg.startswith("--allowed_ports="):
            allowed_ports = arg.split("=", 1)[1]
    return targets, allowed_ports


def parse_ports(raw):
    """Parse comma-separated port numbers."""
    ports = set()
    for p in raw.split(","):
        p = p.strip()
        if p.isdigit():
            ports.add(int(p))
    return ports


def scan_port(host, port, timeout=2):
    """Attempt a TCP connection to host:port. Returns True if open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_host(host, allowed_ports, timeout=2):
    """Scan a host for open ports and evaluate against the allowed list."""
    findings = []
    resource_type = "Network::Host"
    open_ports = []

    # Resolve hostname first to verify it is reachable
    try:
        socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        findings.append({
            "resource_id": host,
            "resource_type": resource_type,
            "status": "ERROR",
            "message": f"Cannot resolve hostname: {e}"
        })
        return findings

    # Scan ports concurrently for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port
            for port in SCAN_PORTS
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    open_ports.sort()

    if not open_ports:
        findings.append({
            "resource_id": host,
            "resource_type": resource_type,
            "status": "PASS",
            "message": "No open ports detected among scanned common ports",
            "details": json.dumps({"scanned_count": len(SCAN_PORTS)})
        })
        return findings

    # Evaluate each open port
    unexpected_ports = []
    for port in open_ports:
        service = PORT_SERVICES.get(port, "unknown")
        if port in allowed_ports:
            findings.append({
                "resource_id": f"{host}:{port}",
                "resource_type": resource_type,
                "status": "PASS",
                "message": f"Port {port}/{service} is open and in the allowed list",
                "details": json.dumps({"port": port, "service": service, "allowed": True})
            })
        else:
            unexpected_ports.append(port)
            findings.append({
                "resource_id": f"{host}:{port}",
                "resource_type": resource_type,
                "status": "FAIL",
                "message": f"Unexpected open port: {port}/{service}",
                "details": json.dumps({"port": port, "service": service, "allowed": False})
            })

    # Summary finding
    if unexpected_ports:
        findings.append({
            "resource_id": host,
            "resource_type": resource_type,
            "status": "FAIL",
            "message": f"{len(unexpected_ports)} unexpected open port(s) found: {', '.join(str(p) for p in unexpected_ports)}",
            "details": json.dumps({
                "open_ports": open_ports,
                "unexpected_ports": unexpected_ports,
                "allowed_ports": sorted(allowed_ports)
            })
        })
    else:
        findings.append({
            "resource_id": host,
            "resource_type": resource_type,
            "status": "PASS",
            "message": f"All {len(open_ports)} open port(s) are in the allowed list",
            "details": json.dumps({
                "open_ports": open_ports,
                "allowed_ports": sorted(allowed_ports)
            })
        })

    return findings


def main():
    findings = []

    raw_targets, raw_allowed = parse_args()

    if not raw_targets:
        findings.append({
            "resource_id": "targets-parameter",
            "resource_type": "Network::Host",
            "status": "ERROR",
            "message": "The 'targets' parameter is required (comma-separated hosts)"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    allowed_ports = parse_ports(raw_allowed)
    hosts = [h.strip() for h in raw_targets.split(",") if h.strip()]

    if not hosts:
        findings.append({
            "resource_id": "targets-parameter",
            "resource_type": "Network::Host",
            "status": "ERROR",
            "message": "No valid hosts parsed from input"
        })
        json.dump(findings, sys.stdout, indent=2)
        return

    for host in hosts:
        host_findings = scan_host(host, allowed_ports)
        findings.extend(host_findings)

    json.dump(findings, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
