# Docker Security Agent Pack

A comprehensive Docker/container security compliance pack for Comply-Intel. This pack audits running Docker environments against industry security benchmarks including CIS Docker Benchmark, NIST, PCI-DSS, and SOC 2.

## Overview

This pack contains 6 automated security checks that inspect the Docker daemon configuration, running containers, images, networking, logging, and resource limits. Each check outputs a JSON array of findings with PASS, FAIL, or ERROR status.

## Checks

| ID | Description | Severity | Frameworks |
|----|-------------|----------|------------|
| `docker-daemon-config` | Verify Docker daemon security configuration | Critical | CIS-Docker-2.1, NIST-CM-6, SOC2-CC6.8 |
| `container-privileges` | Detect containers running with elevated privileges | Critical | CIS-Docker-5.1, NIST-AC-6, PCI-DSS-7.1, SOC2-CC6.3 |
| `image-vulnerabilities` | Check images for known vulnerabilities | High | CIS-Docker-4.1, NIST-SI-2, PCI-DSS-6.2, SOC2-CC7.1 |
| `container-networking` | Verify network isolation and exposed ports | High | CIS-Docker-5.7, NIST-SC-7, PCI-DSS-1.3, SOC2-CC6.6 |
| `docker-logging` | Verify container logging driver configuration | Medium | CIS-Docker-2.12, NIST-AU-2, PCI-DSS-10.2, SOC2-CC7.2 |
| `docker-resource-limits` | Verify CPU and memory limits are set | Medium | CIS-Docker-5.10, NIST-SC-6, SOC2-A1.2 |

## Prerequisites

- Docker CLI installed and accessible in `PATH`
- Docker daemon running and accessible (user must have permissions)
- `jq` installed for JSON processing
- Optional: `trivy`, `grype`, or `docker scout` for vulnerability scanning (used by `image-vulnerabilities` check)

## Directory Structure

```
docker-pack/
  pack.yaml                         # Pack manifest with check definitions
  README.md                         # This file
  scripts/
    check_daemon_config.sh          # Daemon configuration audit
    check_container_privileges.sh   # Privilege escalation detection
    check_image_vulnerabilities.sh  # Image vulnerability scanning
    check_container_networking.sh   # Network isolation verification
    check_docker_logging.sh         # Logging configuration audit
    check_resource_limits.sh        # Resource limits verification
```

## Output Format

Each script outputs a JSON array of finding objects to stdout:

```json
[
  {
    "resource_id": "my-container(a1b2c3d4e5f6)",
    "resource_type": "container",
    "status": "FAIL",
    "message": "Container is running in privileged mode"
  }
]
```

### Fields

| Field | Description |
|-------|-------------|
| `resource_id` | Identifier for the resource being checked (container name, daemon, network, etc.) |
| `resource_type` | Type of resource: `container`, `daemon`, `daemon-config`, `image`, `network`, `logging` |
| `status` | `PASS` (compliant), `FAIL` (non-compliant), or `ERROR` (check could not complete) |
| `message` | Human-readable description of the finding |

## Check Details

### docker-daemon-config (Critical)

Audits the Docker daemon configuration file (`/etc/docker/daemon.json`) and runtime settings:

- Userland proxy disabled
- Live restore enabled
- Docker Content Trust enabled
- Inter-container communication (icc) disabled
- Default ulimits configured
- Storage driver is overlay2
- Logging driver configured
- Insecure registries not configured

### container-privileges (Critical)

Inspects each running container for privilege escalation risks:

- Privileged mode (`--privileged`)
- Running as root user
- Dangerous added capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, etc.)
- Capabilities not being dropped
- Host PID namespace sharing
- `no-new-privileges` security option
- Read-only root filesystem

### image-vulnerabilities (High)

Checks container images for vulnerability and provenance concerns:

- Use of `latest` or untagged images
- Image age (flags images older than 30/90 days)
- Image digest pinning for provenance verification
- Vulnerability scanning via trivy, grype, or docker scout (if available)
- HEALTHCHECK instruction defined

### container-networking (High)

Verifies container network isolation and port exposure:

- Containers on the default bridge network
- Host network mode usage
- Ports published on all interfaces (0.0.0.0)
- Sensitive ports exposed (SSH, databases, etc.)
- Legacy `--link` usage
- Host IPC namespace sharing
- Host UTS namespace sharing

### docker-logging (Medium)

Verifies logging is properly configured at both daemon and container levels:

- Daemon default logging driver
- Log rotation settings (max-size, max-file)
- Per-container logging driver
- Per-container log rotation options
- Container actually producing log output

### docker-resource-limits (Medium)

Verifies containers have resource constraints to prevent denial of service:

- Memory hard limit
- Memory reservation (soft limit)
- CPU limit (NanoCPUs, CpuQuota/CpuPeriod, or CpusetCpus)
- CPU shares (relative weight)
- PIDs limit (fork bomb protection)
- Restart policy configuration
- OOM killer settings

## Usage

Run an individual check directly:

```bash
bash scripts/check_daemon_config.sh
```

Or use the Comply-Intel agent runner to execute all checks defined in `pack.yaml`.

## Error Handling

All scripts handle the following edge cases gracefully:

- Docker CLI not installed: returns an ERROR finding and exits cleanly
- Docker daemon not running: returns an ERROR finding and exits cleanly
- No running containers: returns a PASS finding indicating no containers to audit
- Individual container inspection failures: caught and reported as ERROR findings

Scripts use `set -euo pipefail` for strict error handling and will not produce partial or malformed output.
