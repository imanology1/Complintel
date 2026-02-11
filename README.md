# Comply-Intel — GRC Agent Factory

A pluggable Governance, Risk, and Compliance (GRC) automation platform with an integrated **virtual security team**. Define compliance checks as simple scripts, organize them into agent packs, and let the core engine handle scheduling, execution, risk assessment, and compliance reporting across SOC 2, NIST 800-53, PCI-DSS, and CIS Benchmarks.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Core Engine (Go)                          │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │  Config   │ │ Discovery│ │  Scheduler  │ │ Execution   │ │
│  │  Loader   │ │  Loader  │ │ (cron/once) │ │ Engine      │ │
│  └──────────┘ └──────────┘ └─────────────┘ └──────┬──────┘ │
│                                                    │        │
│  ┌─────────────────────────────────────────────────┴──────┐ │
│  │              Security Team Aggregation Layer            │ │
│  │  ┌──────────────┐ ┌────────────┐ ┌──────────────────┐ │ │
│  │  │ Risk         │ │ Compliance │ │ Remediation      │ │ │
│  │  │ Assessment   │ │ Mapper     │ │ Prioritizer      │ │ │
│  │  │ Agent        │ │ (SOC2,NIST │ │                  │ │ │
│  │  │              │ │  PCI,CIS)  │ │                  │ │ │
│  │  └──────────────┘ └────────────┘ └──────────────────┘ │ │
│  └────────────────────────────────────────────────────────┘ │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │ Results Writer    │  │ Team Report      │                 │
│  │ (JSON/CSV/table)  │  │ Renderer         │                 │
│  └──────────────────┘  └──────────────────┘                 │
└────────────────┬────────────────────────────────────────────┘
                 │ executes
    ┌────────┬───┼────┬──────────┐
    ▼        ▼   ▼    ▼          ▼
┌───────┐┌───────┐┌────────┐┌────────┐┌────────┐
│  AWS  ││ Linux ││ GitHub ││Network ││ Docker │
│(17chk)││(10chk)││ (6chk) ││ (5chk) ││ (6chk) │
└───────┘└───────┘└────────┘└────────┘└────────┘
```

## Quick Start

### 1. Build

```bash
go build -o comply-intel ./cmd/comply-intel
chmod +x packs/*/scripts/*
```

### 2. Configure

Edit `config.yaml` — uncomment the checks you need and set credentials.

### 3. Run a scan

```bash
# Basic scan (findings only)
./comply-intel --config config.yaml

# Full security team report (risk + compliance + remediation)
./comply-intel --config config.yaml --report

# JSON report for programmatic consumption
./comply-intel --config config.yaml --report-json

# Single framework report
./comply-intel --config config.yaml --report --framework SOC2
./comply-intel --config config.yaml --report --framework PCI-DSS
```

## The Virtual Security Team

When you run with `--report`, Comply-Intel activates its **aggregation layer** — a virtual security team that analyzes raw findings and produces executive-level output:

### Risk Assessment Agent
- Calculates an overall compliance score (weighted by severity)
- Classifies risk level: CRITICAL / HIGH / MEDIUM / LOW
- Produces category-by-category score breakdown with visual bars
- Ranks the top 10 risks by severity

### Compliance Mapper Agents
Four framework-specific agents map your findings to real controls:

| Agent | Framework | Controls Mapped |
|-------|-----------|-----------------|
| **SOC 2 Agent** | SOC 2 Type II Trust Service Criteria | CC1-CC8, A1, C1 |
| **NIST Agent** | NIST SP 800-53 Rev 5 | AC, AU, CM, CP, IA, SA, SC, SI families |
| **PCI-DSS Agent** | PCI DSS v4.0 | Requirements 1-12 |
| **CIS Agent** | CIS Benchmarks (AWS, Linux, Docker, GitHub) | 30+ controls |

Each agent produces:
- Pass/fail/not-tested counts per control
- Overall compliance percentage
- Gap analysis identifying exactly which controls are failing

### Remediation Prioritizer
- Generates a prioritized remediation plan sorted by severity
- Maps each action to affected frameworks
- Provides impact statements with SLA guidance (24h / 7d / 30d / 90d)

## Agent Packs (44 checks total)

### AWS Pack (17 checks)

| ID | Description | Severity |
|----|-------------|----------|
| `s3-encryption` | S3 bucket default encryption | High |
| `s3-public-access` | S3 public access block | Critical |
| `s3-versioning` | S3 versioning for data recovery | Medium |
| `s3-logging` | S3 server access logging | Medium |
| `iam-password-policy` | IAM password policy requirements | High |
| `iam-mfa-enabled` | MFA on all console users | Critical |
| `iam-root-mfa` | Root account MFA | Critical |
| `iam-unused-credentials` | Stale credentials (>90 days) | Medium |
| `iam-access-key-rotation` | Access key rotation (>90 days) | High |
| `cloudtrail-enabled` | CloudTrail multi-region logging | Critical |
| `cloudtrail-log-validation` | CloudTrail log file integrity | High |
| `sg-unrestricted-ssh` | Security groups open SSH (0.0.0.0/0:22) | Critical |
| `sg-unrestricted-rdp` | Security groups open RDP (0.0.0.0/0:3389) | Critical |
| `ebs-encryption` | EBS volume encryption | High |
| `rds-encryption` | RDS encryption at rest | High |
| `rds-public-access` | RDS public accessibility | Critical |
| `rds-backup-enabled` | RDS automated backups | Medium |

### Linux Pack (10 checks)

| ID | Description | Severity |
|----|-------------|----------|
| `password-policy` | Password length, expiration, PAM modules | High |
| `ssh-config` | SSH daemon hardening | Critical |
| `file-permissions` | Critical file permissions (/etc/passwd, shadow) | High |
| `firewall-status` | Firewall active with default-deny | Critical |
| `audit-logging` | auditd installation and rule configuration | High |
| `unnecessary-services` | Detect telnet, rsh, rlogin, etc. | Medium |
| `kernel-hardening` | sysctl parameters (ASLR, SYN cookies, etc.) | High |
| `filesystem-encryption` | LUKS / encrypted filesystem detection | High |
| `user-accounts` | UID 0 duplicates, empty passwords, shell access | Critical |
| `cron-permissions` | Cron file ownership and permissions | Medium |

### GitHub Pack (6 checks)

| ID | Description | Severity |
|----|-------------|----------|
| `branch-protection` | Default branch protection rules | High |
| `secret-scanning` | Secret scanning enabled | Critical |
| `dependabot-alerts` | Unresolved vulnerability alerts | High |
| `org-2fa` | Organization 2FA enforcement | Critical |
| `repo-visibility` | Unintended public repositories | Critical |
| `actions-security` | GitHub Actions permissions | High |

### Network Pack (5 checks)

| ID | Description | Severity |
|----|-------------|----------|
| `tls-config` | TLS 1.2+ with strong ciphers | Critical |
| `open-ports` | Unexpected open ports | High |
| `dns-security` | DNSSEC and zone transfer security | Medium |
| `http-headers` | HTTP security headers (HSTS, CSP, etc.) | High |
| `certificate-expiry` | TLS certificate expiration | Critical |

### Docker Pack (6 checks)

| ID | Description | Severity |
|----|-------------|----------|
| `docker-daemon-config` | Docker daemon security configuration | Critical |
| `container-privileges` | Privileged containers / root user | Critical |
| `image-vulnerabilities` | Outdated images with known CVEs | High |
| `container-networking` | Network isolation and port exposure | High |
| `docker-logging` | Container logging driver | Medium |
| `docker-resource-limits` | CPU and memory limits | Medium |

## Output Formats

| Format | Flag | Description |
|--------|------|-------------|
| Table | *(default)* | Human-readable findings table |
| JSON | `--report-json` | Full structured report for APIs/dashboards |
| CSV | `output.format: csv` | Spreadsheet-compatible findings export |
| Team Report | `--report` | Full security team assessment to terminal |

## Scheduling

| Value | Behavior |
|-------|----------|
| `once` | Single scan, then exit |
| `every 5m` | Run every 5 minutes |
| `every 1h` | Run every hour |
| `0 2 * * *` | Cron: daily at 2:00 AM |

## Creating Your Own Pack

1. Create `packs/my-pack/` with a `pack.yaml` manifest and `scripts/` directory
2. Define checks in `pack.yaml` with framework tags:

```yaml
name: my-pack
version: "1.0.0"
description: "My custom compliance checks"
checks:
  - id: my-check
    description: "What this check does"
    script: my_check.sh
    severity: high
    frameworks:
      - SOC2-CC6.1     # Maps to SOC 2 Logical Access control
      - NIST-SC-28     # Maps to NIST Protection of Info at Rest
      - PCI-DSS-3.4    # Maps to PCI Encryption at Rest
      - CIS-AWS-2.1.1  # Maps to CIS AWS S3 Encryption
```

3. Script outputs JSON array to stdout:
```json
[{"resource_id": "x", "resource_type": "T", "status": "PASS", "message": "OK"}]
```

4. Reference in `config.yaml` and run. The aggregation engine automatically maps your framework tags to compliance reports.

## Project Structure

```
comply-intel/
├── cmd/comply-intel/main.go       # CLI entry point
├── internal/
│   ├── config/                    # Config loader & validation
│   ├── discovery/                 # Pack discovery & manifest validation
│   ├── executor/                  # Concurrent execution with timeouts
│   ├── results/                   # Output formatting (JSON/CSV/table)
│   ├── scheduler/                 # Cron & interval scheduling
│   └── aggregator/                # Security team aggregation layer
│       ├── frameworks.go          # SOC2, NIST, PCI-DSS, CIS definitions
│       ├── risk.go                # Risk assessment & remediation engine
│       ├── compliance.go          # Framework compliance mapping
│       └── report.go              # Team report renderer
├── packs/
│   ├── aws-pack/                  # 17 AWS checks (Python/boto3)
│   ├── linux-pack/                # 10 Linux checks (Bash)
│   ├── github-pack/               # 6 GitHub checks (Python/stdlib)
│   ├── network-pack/              # 5 Network checks (Python/stdlib)
│   └── docker-pack/               # 6 Docker checks (Bash)
├── config.yaml                    # User configuration
└── go.mod
```

## Security Notes

- Credentials are passed to scripts via **environment variables**, never command-line arguments
- Agent scripts run with configurable **timeouts** to prevent hangs
- Scripts that produce `stderr` output are treated as failures
- Each script is **stateless** — no data persists between runs
- The engine validates all pack manifests before execution
