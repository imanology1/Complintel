# Comply-Intel — GRC Agent Factory

A pluggable **Governance, Risk, and Compliance (GRC) automation platform** with an integrated virtual security team. Comply-Intel lets you define compliance checks as simple scripts, organize them into agent packs, and automates the three pillars of GRC work: **Assess, Monitor, and Report**.

The platform ships with **44 production-ready checks** across 5 agent packs and a built-in **aggregation engine** that maps raw findings to real compliance framework controls (SOC 2, NIST 800-53, PCI-DSS, CIS Benchmarks), calculates risk scores, and generates prioritized remediation plans.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Configuration Reference](#configuration-reference)
- [The Virtual Security Team](#the-virtual-security-team)
- [Agent Packs](#agent-packs-44-checks)
  - [AWS Pack (17 checks)](#aws-pack-17-checks)
  - [Linux Pack (10 checks)](#linux-pack-10-checks)
  - [GitHub Pack (6 checks)](#github-pack-6-checks)
  - [Network Pack (5 checks)](#network-pack-5-checks)
  - [Docker Pack (6 checks)](#docker-pack-6-checks)
- [Compliance Frameworks](#compliance-frameworks)
- [Output Examples](#output-examples)
- [Scheduling](#scheduling)
- [Creating Your Own Pack](#creating-your-own-pack)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [License](#license)

---

## Architecture

Comply-Intel is built on a clean separation between the **Core Engine** (a single Go binary) and the **Agent Packs** (self-contained directories of scripts). The engine knows nothing about AWS, Linux, or GitHub—it simply discovers packs, runs their scripts, and aggregates the results.

```
┌──────────────────────────────────────────────────────────────┐
│                    Core Engine (Go Binary)                    │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │  Config   │ │  Pack    │ │  Scheduler  │ │  Execution  │ │
│  │  Loader   │ │ Discovery│ │ cron/once/  │ │   Engine    │ │
│  │  (YAML)   │ │ (pack.  │ │  interval   │ │ concurrent  │ │
│  │           │ │  yaml)   │ │             │ │ + timeouts  │ │
│  └──────────┘ └──────────┘ └─────────────┘ └──────┬──────┘ │
│                                                    │        │
│  ┌─────────────────────────────────────────────────┴──────┐ │
│  │           Security Team Aggregation Layer               │ │
│  │                                                         │ │
│  │  ┌──────────────┐ ┌────────────────┐ ┌───────────────┐ │ │
│  │  │    Risk      │ │   Compliance   │ │  Remediation  │ │ │
│  │  │  Assessment  │ │    Mapper      │ │  Prioritizer  │ │ │
│  │  │    Agent     │ │  SOC2 | NIST   │ │  (severity-   │ │ │
│  │  │  (weighted   │ │  PCI  | CIS    │ │   ranked)     │ │ │
│  │  │   scoring)   │ │                │ │               │ │ │
│  │  └──────────────┘ └────────────────┘ └───────────────┘ │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌──────────────────────┐  ┌──────────────────────────────┐ │
│  │   Results Writer      │  │   Team Report Renderer       │ │
│  │   table | json | csv  │  │   dashboard + gap analysis   │ │
│  └──────────────────────┘  └──────────────────────────────┘ │
└────────────────────┬─────────────────────────────────────────┘
                     │ executes scripts
       ┌─────────┬───┼─────┬──────────┐
       ▼         ▼   ▼     ▼          ▼
  ┌─────────┐┌───────┐┌────────┐┌────────┐┌────────┐
  │   AWS   ││ Linux ││ GitHub ││Network ││ Docker │
  │ 17 chks ││10 chks││ 6 chks ││ 5 chks ││ 6 chks │
  │ Python  ││ Bash  ││ Python ││ Python ││  Bash  │
  └─────────┘└───────┘└────────┘└────────┘└────────┘
```

**Data flow:**

1. User writes `config.yaml` specifying which checks to run
2. Engine discovers all packs in `./packs/` by reading `pack.yaml` manifests
3. Engine resolves which checks to run, merges parameters
4. Execution engine dispatches scripts concurrently (configurable worker count)
5. Each script outputs a JSON array of findings to stdout
6. Engine enriches findings with metadata (timestamp, severity, frameworks)
7. Aggregation layer produces risk scores, compliance reports, and remediation plans
8. Results are rendered to terminal, JSON file, or CSV

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Go** | 1.21+ | Only needed to build from source |
| **Bash** | 4.0+ | For Linux and Docker pack scripts |
| **Python** | 3.6+ | For AWS, GitHub, and Network pack scripts |
| **boto3** | latest | `pip install boto3` — only for AWS pack |
| **Docker CLI** | any | Only for Docker pack (must be on `$PATH`) |

**Which packs work out of the box (no setup)?**
- **Linux pack** — just needs bash and read access to `/etc/` files
- **Docker pack** — just needs bash and docker CLI on PATH

**Which packs need credentials?**
- **AWS pack** — `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `boto3`
- **GitHub pack** — `GITHUB_TOKEN` with `repo` and `read:org` scopes
- **Network pack** — no credentials, but needs target hosts/URLs as parameters

---

## Installation

### Option A: Build from source (recommended)

```bash
# Clone the repository
git clone https://github.com/imanology1/Complintel.git
cd Complintel

# Build the binary (produces a single executable)
go build -o comply-intel ./cmd/comply-intel

# Make all agent scripts executable
chmod +x packs/*/scripts/*

# Verify
./comply-intel --version
# Output: comply-intel 2.0.0
```

### Option B: Cross-compile for another OS

```bash
# Build for Linux (from macOS or Windows)
GOOS=linux GOARCH=amd64 go build -o comply-intel-linux ./cmd/comply-intel

# Build for macOS (from Linux or Windows)
GOOS=darwin GOARCH=arm64 go build -o comply-intel-mac ./cmd/comply-intel

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o comply-intel.exe ./cmd/comply-intel
```

The output is a **single static binary** — copy it to any machine along with the `packs/` directory and `config.yaml`. No runtime dependencies for the engine itself.

---

## Quick Start

### 1. Run Linux checks immediately (no setup required)

```bash
# The default config.yaml has all Linux checks enabled
./comply-intel --config config.yaml --report
```

This scans your local system for password policy, SSH hardening, file permissions, firewall status, audit logging, kernel parameters, user accounts, and more.

### 2. Enable AWS checks

Edit `config.yaml`:

```yaml
credentials:
  AWS_ACCESS_KEY_ID: "AKIA..."
  AWS_SECRET_ACCESS_KEY: "..."
  AWS_REGION: "us-east-1"

checks:
  # Uncomment the AWS checks you want:
  - pack: aws
    check: s3-encryption
    params:
      region: "us-east-1"
  - pack: aws
    check: iam-mfa-enabled
  - pack: aws
    check: cloudtrail-enabled
  # ... etc
```

Then install boto3 and run:

```bash
pip install boto3
./comply-intel --config config.yaml --report
```

### 3. Enable GitHub checks

```yaml
credentials:
  GITHUB_TOKEN: "ghp_xxxxxxxxxxxx"

checks:
  - pack: github
    check: branch-protection
    params:
      org: "your-org-name"
  - pack: github
    check: secret-scanning
    params:
      org: "your-org-name"
```

### 4. Save results to a file

```yaml
output:
  format: "json"      # or "csv"
  target: "file"
  path: "./results/scan-2024-01.json"
```

---

## CLI Reference

```
Usage:
  comply-intel [flags]

Flags:
  --config string       Path to configuration file (default "config.yaml")
  --version             Print version and exit
  --report              Generate full security team report to terminal
  --report-json         Generate full security team report as JSON
  --framework string    Filter report to a specific framework:
                          SOC2, NIST-800-53, PCI-DSS, CIS
```

### Usage examples

```bash
# Basic scan — just findings table
./comply-intel

# Full security team report — risk assessment + all frameworks + remediation
./comply-intel --report

# SOC 2 focused audit report
./comply-intel --report --framework SOC2

# NIST 800-53 compliance assessment
./comply-intel --report --framework NIST-800-53

# PCI-DSS readiness check
./comply-intel --report --framework PCI-DSS

# CIS Benchmark scoring
./comply-intel --report --framework CIS

# Export full structured report as JSON (pipe to jq, feed to dashboards)
./comply-intel --report-json > report.json

# Export findings as CSV for spreadsheet analysis
# (set output.format: "csv" and output.target: "file" in config.yaml)
./comply-intel

# Use a different config for production vs. dev
./comply-intel --config configs/production.yaml --report
./comply-intel --config configs/dev-only.yaml --report

# Run on a schedule (continuous monitoring)
# Set schedule: "every 1h" in config.yaml, then:
./comply-intel --report
# Engine will re-run every hour until you press Ctrl+C
```

---

## Configuration Reference

The engine is controlled by a single `config.yaml` file. Here is every field explained:

```yaml
# ===================================================================
# CORE SETTINGS
# ===================================================================

# Where to find agent packs (relative or absolute path)
packs_dir: "./packs"

# When to run checks:
#   "once"       — single scan, then exit (default)
#   "every 5m"   — repeat every 5 minutes
#   "every 1h"   — repeat every hour
#   "0 2 * * *"  — cron expression (daily at 2 AM)
#   "*/15 * * *" — cron (every 15 minutes)
schedule: "once"

# How many check scripts to execute simultaneously.
# Higher = faster scans, but more resource usage.
# Set to 1 for sequential execution.
concurrency: 8

# Maximum time a single check script can run before being killed.
# Prevents hung scripts from blocking the entire scan.
timeout: "120s"

# ===================================================================
# OUTPUT SETTINGS
# ===================================================================
output:
  # Format for raw findings output:
  #   "table"  — human-readable terminal table (default)
  #   "json"   — JSON array of enriched findings
  #   "csv"    — CSV with headers
  format: "table"

  # Where to write output:
  #   "stdout" — print to terminal (default)
  #   "file"   — write to a file (must set path below)
  target: "stdout"

  # File path when target is "file":
  # path: "./results/findings.json"

# ===================================================================
# CREDENTIALS
# ===================================================================
# These are injected as environment variables into every agent script.
# The engine NEVER passes them on the command line.
#
# SECURITY BEST PRACTICE: For production, do NOT store secrets here.
# Instead, set them in your shell environment before running:
#   export AWS_ACCESS_KEY_ID="..."
#   export GITHUB_TOKEN="..."
#   ./comply-intel --report
#
# The credentials section is for convenience during development/testing.
credentials:
  # AWS_ACCESS_KEY_ID: "AKIA..."
  # AWS_SECRET_ACCESS_KEY: "..."
  # AWS_REGION: "us-east-1"
  # AWS_PROFILE: "my-profile"
  # GITHUB_TOKEN: "ghp_..."

# ===================================================================
# CHECKS
# ===================================================================
# Each entry specifies:
#   pack:   — name of the agent pack (matches the "name" in pack.yaml)
#   check:  — ID of the specific check within that pack
#   params: — (optional) key-value parameters passed to the script
checks:
  - pack: linux
    check: password-policy
    params:
      min_length: "14"    # Override the default minimum password length
      max_days: "90"      # Override the default max password age
  - pack: linux
    check: ssh-config
  # ... add more checks here
```

### Environment variable precedence

Credentials can come from three sources, in order of precedence:

1. **System environment** — variables already set in your shell (`export AWS_REGION=...`)
2. **config.yaml `credentials` section** — merged on top of system env
3. **Pack defaults** — parameter defaults defined in `pack.yaml`

This means you can keep `config.yaml` clean and set secrets externally:

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export GITHUB_TOKEN="ghp_..."
./comply-intel --report
```

---

## The Virtual Security Team

When you run with `--report`, Comply-Intel activates its **aggregation layer** — a set of specialized agents that transform raw check findings into executive-level security intelligence.

### 1. Risk Assessment Agent

The Risk Assessment Agent calculates an overall **compliance score** from 0-100% using a weighted formula:

- **Critical** findings: weight 10
- **High** findings: weight 7
- **Medium** findings: weight 4
- **Low** findings: weight 1

The score blends the raw pass rate (% of checks passing) with the weighted severity score, so a single critical failure weighs more than several low-severity issues.

**Risk classification:**

| Score | Risk Level | Meaning |
|-------|------------|---------|
| 90-100% | LOW | Meets compliance posture targets |
| 70-89% | MEDIUM | Notable gaps requiring attention |
| 50-69% | HIGH | Significant security gaps |
| 0-49% | CRITICAL | Immediate intervention required |

Output includes:
- Overall score with visual indicator
- Per-category score breakdown with ASCII progress bars
- Top 10 risks ranked by severity
- Total pass / fail / error counts

### 2. Compliance Mapper Agents

Four independent agents map your findings to real-world compliance framework controls:

#### SOC 2 Type II Agent
Maps to **18 Trust Service Criteria** across 7 categories:
- **CC1-CC5**: Control Environment, Communication, Risk Assessment, Monitoring, Control Activities
- **CC6**: Logical and Physical Access Controls (CC6.1-CC6.8)
- **CC7**: System Operations (CC7.1-CC7.3)
- **CC8**: Change Management
- **A1**: Availability (A1.1-A1.2)
- **C1**: Confidentiality

#### NIST SP 800-53 Rev 5 Agent
Maps to **21 controls** across 8 families:
- **AC** (Access Control): AC-2, AC-3, AC-4, AC-6
- **AU** (Audit): AU-2, AU-3, AU-9
- **CM** (Configuration Management): CM-6, CM-7
- **CP** (Contingency Planning): CP-9
- **IA** (Identification/Authentication): IA-2, IA-5
- **SA** (System Acquisition): SA-11
- **SC** (System/Communications): SC-6, SC-7, SC-8, SC-17, SC-20, SC-28
- **SI** (System Integrity): SI-2, SI-10

#### PCI DSS v4.0 Agent
Maps to **17 controls** across Requirements 1-12:
- **Req 1**: Network security (1.1, 1.2, 1.3)
- **Req 2**: Secure configuration (2.2.2)
- **Req 3**: Protect stored data (3.4)
- **Req 4**: Encrypt transmission (4.1)
- **Req 6**: Secure development (6.2, 6.5)
- **Req 7**: Restrict access (7.1)
- **Req 8**: Identify users (8.1.4, 8.2, 8.2.4, 8.3)
- **Req 10**: Log and monitor (10.1, 10.2, 10.5)
- **Req 12**: Security policy (12.10)

#### CIS Benchmarks Agent
Maps to **30+ controls** across 4 benchmark suites:
- **CIS AWS** (1.x-5.x): IAM, Storage, Logging, Networking
- **CIS Linux** (2.x-6.x): Services, Network, Logging, Access, Maintenance
- **CIS Docker** (2.x-5.x): Daemon, Images, Runtime
- **CIS GitHub** (1.x-3.x): Authentication, Access, Code Security, CI/CD

Each compliance agent outputs:
- **Control-level results**: PASS, FAIL, PARTIAL, or NOT_TESTED per control
- **Overall compliance percentage**: only over tested controls
- **Compliance status**: COMPLIANT (>=95%), PARTIAL (>=70%), or NON-COMPLIANT (<70%)
- **Gap analysis**: identifies every failing control with the specific checks that need remediation

### 3. Remediation Prioritizer

Consumes all failing findings and produces a **prioritized action plan**:

| Priority | Severity | SLA Target | Description |
|----------|----------|------------|-------------|
| 1-N | Critical | **24 hours** | Immediate risk of data breach or unauthorized access |
| N+1... | High | **7 days** | Significant security gap that could lead to compromise |
| ... | Medium | **30 days** | Moderate risk, address in next sprint cycle |
| ... | Low | **90 days** | Minor issue for continuous improvement |

Each remediation item includes:
- **Specific action** (e.g., "Enable MFA on the AWS root account immediately")
- **Affected resource** (e.g., the specific S3 bucket or IAM user)
- **Impacted frameworks** (which compliance frameworks are affected)
- **Impact statement** with SLA guidance

---

## Agent Packs (44 checks)

### AWS Pack (17 checks)

**Language:** Python 3 (requires `boto3`)
**Credentials:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`

| ID | Description | Severity | Frameworks |
|----|-------------|----------|------------|
| `s3-encryption` | Verify all S3 buckets have default encryption enabled | High | SOC2-CC6.1, NIST-SC-28, CIS-AWS-2.1.1, PCI-DSS-3.4 |
| `s3-public-access` | Verify S3 buckets block all public access | Critical | SOC2-CC6.1, SOC2-CC6.6, PCI-DSS-1.3, CIS-AWS-2.1.2, NIST-AC-3 |
| `s3-versioning` | Verify S3 buckets have versioning enabled for data recovery | Medium | SOC2-A1.2, NIST-CP-9, CIS-AWS-2.1.3 |
| `s3-logging` | Verify S3 buckets have server access logging enabled | Medium | SOC2-CC7.2, NIST-AU-2, CIS-AWS-2.1.4, PCI-DSS-10.2 |
| `iam-password-policy` | Verify IAM account password policy meets minimum requirements (length >= 14, complexity, rotation <= 90 days) | High | SOC2-CC6.1, NIST-IA-5, CIS-AWS-1.8, PCI-DSS-8.2 |
| `iam-mfa-enabled` | Verify all IAM users with console access have MFA enabled | Critical | SOC2-CC6.1, SOC2-CC6.2, NIST-IA-2, CIS-AWS-1.10, PCI-DSS-8.3 |
| `iam-root-mfa` | Verify the root account has MFA enabled | Critical | SOC2-CC6.1, NIST-IA-2, CIS-AWS-1.5, PCI-DSS-8.3 |
| `iam-unused-credentials` | Detect IAM credentials not used in the last N days | Medium | SOC2-CC6.2, NIST-AC-2, CIS-AWS-1.12, PCI-DSS-8.1.4 |
| `iam-access-key-rotation` | Verify IAM access keys are rotated within N days | High | SOC2-CC6.1, NIST-IA-5, CIS-AWS-1.14, PCI-DSS-8.2.4 |
| `cloudtrail-enabled` | Verify CloudTrail is enabled in all regions with multi-region logging | Critical | SOC2-CC7.2, SOC2-CC7.3, NIST-AU-2, NIST-AU-3, CIS-AWS-3.1, PCI-DSS-10.1 |
| `cloudtrail-log-validation` | Verify CloudTrail log file validation is enabled | High | SOC2-CC7.2, NIST-AU-9, CIS-AWS-3.2, PCI-DSS-10.5 |
| `sg-unrestricted-ssh` | Detect security groups allowing SSH from 0.0.0.0/0 (port 22) | Critical | SOC2-CC6.6, NIST-AC-4, CIS-AWS-5.2, PCI-DSS-1.2 |
| `sg-unrestricted-rdp` | Detect security groups allowing RDP from 0.0.0.0/0 (port 3389) | Critical | SOC2-CC6.6, NIST-AC-4, CIS-AWS-5.3, PCI-DSS-1.2 |
| `ebs-encryption` | Verify EBS volumes are encrypted | High | SOC2-CC6.1, NIST-SC-28, CIS-AWS-2.2.1, PCI-DSS-3.4 |
| `rds-encryption` | Verify RDS instances have encryption at rest enabled | High | SOC2-CC6.1, NIST-SC-28, CIS-AWS-2.3.1, PCI-DSS-3.4 |
| `rds-public-access` | Verify RDS instances are not publicly accessible | Critical | SOC2-CC6.6, NIST-AC-4, PCI-DSS-1.3 |
| `rds-backup-enabled` | Verify RDS instances have automated backups with retention | Medium | SOC2-A1.2, NIST-CP-9, PCI-DSS-12.10 |

**Parameters:**

| Check | Parameter | Default | Description |
|-------|-----------|---------|-------------|
| Most S3/EC2/RDS checks | `region` | `us-east-1` | AWS region to scan |
| `iam-unused-credentials` | `max_age_days` | `90` | Days before credentials are flagged stale |
| `iam-access-key-rotation` | `max_age_days` | `90` | Days before keys are flagged unrotated |

---

### Linux Pack (10 checks)

**Language:** Bash
**Credentials:** None (reads local system files)
**Requirements:** Root or sudo access recommended for full results

| ID | Description | Severity | What it checks |
|----|-------------|----------|----------------|
| `password-policy` | Password length, expiration, PAM modules | High | `/etc/login.defs` (PASS_MIN_LEN, PASS_MAX_DAYS), `/etc/pam.d/common-password` or `system-auth` for pam_pwquality |
| `ssh-config` | SSH daemon hardening | Critical | `/etc/ssh/sshd_config`: PermitRootLogin, PasswordAuthentication, X11Forwarding, MaxAuthTries, PermitEmptyPasswords |
| `file-permissions` | Critical file permissions | High | `/etc/passwd` (644, root:root), `/etc/shadow` (640, root:shadow), `/etc/group` (644, root:root), `/etc/gshadow` (640, root:shadow) |
| `firewall-status` | Firewall active with default-deny | Critical | Checks iptables, nftables, and ufw. Verifies at least one is active with a default DROP/REJECT input policy |
| `audit-logging` | auditd installation and rules | High | Checks auditd is installed and running. Verifies audit rules for: identity files, time changes, user/group mods, network config, login events, privilege escalation, immutable flag |
| `unnecessary-services` | Legacy insecure services | Medium | Detects telnet, rsh, rlogin, rexec, NIS (ypserv), tftp, xinetd. Checks for legacy inetd service ports |
| `kernel-hardening` | Sysctl security parameters | High | 20+ sysctl checks: ASLR, SYN cookies, IP forwarding, source routing, ICMP redirects, martian logging, reverse path filtering, ptrace scope, core dumps, NX bit |
| `filesystem-encryption` | Disk encryption detection | High | Scans for LUKS volumes (`/dev/mapper`), checks for encrypted mount types (ecryptfs, fscrypt), verifies `/tmp` and swap encryption |
| `user-accounts` | Account security audit | Critical | UID 0 duplicates, empty passwords, system accounts with login shells, duplicate UIDs/GIDs/usernames, root password status, password aging, GID 0 membership |
| `cron-permissions` | Cron file ownership and ACLs | Medium | `/etc/crontab`, `/etc/cron.{hourly,daily,weekly,monthly,d}` permissions and ownership. `/etc/cron.allow` and `/etc/cron.deny` existence. `/etc/at.allow` and `/etc/at.deny`. World-writable scripts in cron directories |

**Parameters:**

| Check | Parameter | Default | Description |
|-------|-----------|---------|-------------|
| `password-policy` | `min_length` | `14` | Minimum required password length |
| `password-policy` | `max_days` | `90` | Maximum password age in days |

---

### GitHub Pack (6 checks)

**Language:** Python 3 (standard library only, no pip installs)
**Credentials:** `GITHUB_TOKEN` with `repo` and `read:org` scopes

| ID | Description | Severity | What it checks |
|----|-------------|----------|----------------|
| `branch-protection` | Default branch protection rules | High | Require PR reviews (>= 1 approval), require status checks (strict mode), no force push, no branch deletion |
| `secret-scanning` | Secret scanning enabled on repos | Critical | Uses GitHub API to verify secret scanning is enabled on each repository |
| `dependabot-alerts` | Unresolved vulnerability alerts | High | Queries Dependabot alerts API, flags repos with unresolved critical/high alerts |
| `org-2fa` | Organization 2FA enforcement | Critical | Checks if two-factor authentication is required for all org members |
| `repo-visibility` | Unintended public repositories | Critical | Lists all repos in the org, flags any that are public (useful for orgs that should be private-by-default) |
| `actions-security` | GitHub Actions permissions | High | Checks Actions workflow permissions (should be read-only default) and allowed actions policy (should restrict to verified/selected) |

**Parameters:**

| Check | Parameter | Required | Default | Description |
|-------|-----------|----------|---------|-------------|
| All | `org` | Yes | — | GitHub organization name |
| Most | `repo` | No | *(all repos)* | Specific repo to check (omit to scan entire org) |

---

### Network Pack (5 checks)

**Language:** Python 3 (standard library only — uses `ssl`, `socket`, `http.client`)
**Credentials:** None
**Note:** These checks make real network connections to the specified targets.

| ID | Description | Severity | What it checks |
|----|-------------|----------|----------------|
| `tls-config` | TLS protocol and cipher verification | Critical | Connects to each target, verifies TLS 1.2+ is required, checks for weak cipher suites (RC4, DES, NULL, EXPORT, MD5) |
| `open-ports` | Unexpected open port detection | High | TCP connects to common ports on each target, flags any open port not in the `allowed_ports` list |
| `dns-security` | DNS security posture | Medium | Checks DNSSEC support (queries for DNSKEY records), tests for zone transfer vulnerability (AXFR) |
| `http-headers` | HTTP security header audit | High | Checks for: Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| `certificate-expiry` | TLS certificate expiration | Critical | Connects to each target, extracts cert expiration date, flags as FAIL if within `warn_days` of expiry or already expired |

**Parameters:**

| Check | Parameter | Required | Default | Description |
|-------|-----------|----------|---------|-------------|
| `tls-config` | `targets` | Yes | — | Comma-separated `host:port` list (e.g., `api.example.com:443,web.example.com:443`) |
| `open-ports` | `targets` | Yes | — | Comma-separated hostnames or IPs |
| `open-ports` | `allowed_ports` | No | `22,80,443` | Comma-separated list of expected open ports |
| `dns-security` | `domains` | Yes | — | Comma-separated domain names |
| `http-headers` | `targets` | Yes | — | Comma-separated URLs (e.g., `https://example.com`) |
| `certificate-expiry` | `targets` | Yes | — | Comma-separated `host:port` list |
| `certificate-expiry` | `warn_days` | No | `30` | Days before expiry to flag as warning |

---

### Docker Pack (6 checks)

**Language:** Bash
**Credentials:** None
**Requirements:** Docker CLI on `$PATH`, Docker daemon running

| ID | Description | Severity | What it checks |
|----|-------------|----------|----------------|
| `docker-daemon-config` | Docker daemon security | Critical | `/etc/docker/daemon.json` exists, checks: `live-restore`, `userns-remap`, `no-new-privileges`, `icc` (inter-container communication), `log-driver`, `storage-driver` |
| `container-privileges` | Privileged container detection | Critical | Inspects all running containers for: `--privileged` flag, running as root (UID 0), missing seccomp profile, `--pid=host` or `--network=host` |
| `image-vulnerabilities` | Outdated image detection | High | Checks running containers for images without recent tags, images older than configurable threshold, and images not from trusted registries |
| `container-networking` | Network isolation audit | High | Checks for containers using `--network=host`, ports bound to 0.0.0.0 (all interfaces) instead of 127.0.0.1, and containers sharing network namespaces |
| `docker-logging` | Container logging configuration | Medium | Verifies each running container has a logging driver configured (not `none`), checks for log rotation settings |
| `docker-resource-limits` | Resource constraint audit | Medium | Inspects running containers for missing CPU limits (`--cpus`), missing memory limits (`--memory`), and unlimited PIDs |

---

## Compliance Frameworks

Comply-Intel maps every check to specific compliance framework controls using tags in each pack's `pack.yaml`. The aggregation engine uses these tags to produce framework-specific reports.

### How framework mapping works

Each check declares which framework controls it satisfies:

```yaml
# In pack.yaml
- id: s3-encryption
  frameworks:
    - SOC2-CC6.1     # SOC 2: Logical and Physical Access
    - NIST-SC-28     # NIST: Protection of Information at Rest
    - PCI-DSS-3.4    # PCI: Encryption at Rest
    - CIS-AWS-2.1.1  # CIS: S3 Encryption
```

When you run `--report`, the aggregation engine:
1. Collects all findings with their framework tags
2. Groups findings by framework control
3. Calculates per-control and overall compliance scores
4. Identifies gaps (controls that have failing checks)

### Supported framework controls

| Framework | Total Controls | Categories |
|-----------|---------------|------------|
| **SOC 2 Type II** | 18 | Control Environment, Communication, Risk Assessment, Monitoring, Control Activities, Logical Access (CC6.1-CC6.8), System Operations (CC7.1-CC7.3), Change Management, Availability, Confidentiality |
| **NIST 800-53 Rev 5** | 21 | Access Control (AC-2/3/4/6), Audit (AU-2/3/9), Configuration Mgmt (CM-6/7), Contingency (CP-9), Auth (IA-2/5), Acquisition (SA-11), System Protection (SC-6/7/8/17/20/28), Integrity (SI-2/10) |
| **PCI DSS v4.0** | 17 | Network Security (1.x), Secure Config (2.x), Stored Data (3.x), Encryption (4.x), Development (6.x), Access (7.x), Auth (8.x), Logging (10.x), Policy (12.x) |
| **CIS Benchmarks** | 30+ | AWS IAM/Storage/Logging/Networking, Linux Services/Network/Logging/Access/Maintenance, Docker Daemon/Images/Runtime, GitHub Auth/Access/Code Security/CI-CD |

---

## Output Examples

### Basic scan (default table output)

```
STATUS  SEVERITY  PACK   CHECK            RESOURCE                       MESSAGE
------  --------  ----   -----            --------                       -------
PASS    critical  linux  user-accounts    uid:0                          Only root has UID 0
FAIL    high      linux  password-policy  /etc/login.defs                Minimum password length is 8 (required: 14)
FAIL    critical  linux  ssh-config       /etc/ssh/sshd_config:Root      Root login is NOT disabled
ERROR   high      linux  audit-logging    auditd:package                 auditd is not installed

--- Scan Summary ---
Total findings: 63 | PASS: 15 | FAIL: 23 | ERROR: 25
```

### Security team report (`--report`)

```
=============================================================
          COMPLY-INTEL :: SECURITY TEAM REPORT
=============================================================
  Generated: 2026-02-13T14:30:00Z

--- RISK ASSESSMENT AGENT ---

  Overall Compliance Score: 52% [!! HIGH !!]
  Risk Level:              HIGH
  Total Findings:          63
  Passed:                  15
  Failed:                  23
  Errors:                  25

  Category Scores:
    linux                [###########-------------------] 39%

--- TOP RISKS ---

  #  SEVERITY  PACK   CHECK            RESOURCE           DESCRIPTION
  1  critical  linux  user-accounts    user:postgres      System account has login shell
  2  critical  linux  user-accounts    accounts:aging     No password expiration set
  3  high      linux  audit-logging    auditd:package     auditd is not installed
  ...

--- COMPLIANCE DASHBOARD ---

  FRAMEWORK             SCORE             STATUS         PASS  FAIL  NOT TESTED
  SOC 2 Type II         [-------] 0%      NON-COMPLIANT  0     18    0
  NIST SP 800-53 Rev 5  [##-----] 20%     NON-COMPLIANT  1     4     16
  PCI DSS v4.0          [######-] 88%     PARTIAL        15    2     0
  CIS Benchmarks        [-------] 0%      NON-COMPLIANT  0     7     26

--- GAP ANALYSIS ---

  [SOC 2 Type II]
    SOC2-CC6.1 (Logical and Physical Access)
      Gap: Partially implemented — some checks pass but others fail.
      Failing checks: password-policy, user-accounts, cron-permissions

  [NIST SP 800-53 Rev 5]
    NIST-AU-2 (Audit Events)
      Gap: Not implemented — all related checks are failing.
      Failing checks: audit-logging

--- REMEDIATION PLAN (Prioritized) ---

  #  SEVERITY  ACTION                                                    IMPACT
  1  critical  Remediate user account issue [user:postgres]             24h SLA
  2  high      Install and enable auditd [auditd:package]              7 day SLA
  3  high      Update password policy [/etc/login.defs]                7 day SLA

=============================================================
                    END OF REPORT
=============================================================
```

### JSON report (`--report-json`)

```json
{
  "generated_at": "2026-02-13T14:30:00Z",
  "risk_assessment": {
    "overall_score": 52,
    "overall_risk": "HIGH",
    "total_findings": 63,
    "pass_count": 15,
    "fail_count": 23,
    "error_count": 25,
    "category_scores": { "linux": 39 },
    "top_risks": [ ... ],
    "remediation_plan": [ ... ]
  },
  "compliance_reports": [
    {
      "framework": "SOC2",
      "framework_name": "SOC 2 Type II",
      "overall_score": 0,
      "status": "NON-COMPLIANT",
      "total_controls": 18,
      "passed_controls": 0,
      "failed_controls": 18,
      "not_tested": 0,
      "control_results": [ ... ],
      "gap_analysis": [ ... ]
    }
  ]
}
```

---

## Scheduling

The engine supports three scheduling modes, configured in `config.yaml`:

| Mode | Config Value | Behavior |
|------|-------------|----------|
| **Run once** | `schedule: "once"` | Execute all checks once, print results, exit. Best for CI/CD pipelines and ad-hoc audits. |
| **Interval** | `schedule: "every 5m"` | Run checks on a fixed interval. Supports Go duration strings: `30s`, `5m`, `1h`, `24h`. Minimum interval: 10 seconds. |
| **Cron** | `schedule: "0 2 * * *"` | Standard 5-field cron expression. Runs checks when the cron fires. |

**Cron expression format:** `minute hour day-of-month month day-of-week`

| Example | Meaning |
|---------|---------|
| `0 2 * * *` | Daily at 2:00 AM |
| `0 */6 * * *` | Every 6 hours |
| `0 9 * * 1` | Every Monday at 9:00 AM |
| `0 0 1 * *` | First of every month at midnight |
| `*/15 * * * *` | Every 15 minutes |

**Graceful shutdown:** Press `Ctrl+C` (sends SIGINT) to stop scheduled scans cleanly.

---

## Creating Your Own Pack

The power of Comply-Intel is that anyone can write a new check without touching the Go engine. Here's the complete process:

### Step 1: Create the directory structure

```bash
mkdir -p packs/my-pack/scripts
```

### Step 2: Write the manifest (`pack.yaml`)

```yaml
name: my-pack
version: "1.0.0"
description: "My custom compliance checks for internal systems"

checks:
  - id: database-encryption
    description: "Verify PostgreSQL databases use encryption at rest"
    script: check_db_encryption.sh
    severity: high
    frameworks:
      - SOC2-CC6.1
      - NIST-SC-28
      - PCI-DSS-3.4
    params:
      - name: pg_host
        required: true
      - name: pg_port
        required: false
        default: "5432"

  - id: backup-retention
    description: "Verify backup retention policy meets 30-day minimum"
    script: check_backup_retention.py
    severity: medium
    frameworks:
      - SOC2-A1.2
      - NIST-CP-9
    params:
      - name: min_days
        required: false
        default: "30"
```

### Step 3: Write the check script

Scripts must follow a strict contract:

1. **Executable** — must have `chmod +x`
2. **Stateless** — no state stored between runs
3. **Input** — credentials from environment variables, parameters from `--key=value` args
4. **Output** — JSON array of findings to `stdout`. Nothing else.
5. **Errors** — any `stderr` output or non-zero exit causes the check to fail

**Finding JSON schema:**

```json
[
  {
    "resource_id": "string (required) — unique identifier of the resource checked",
    "resource_type": "string (required) — category/type of the resource",
    "status": "string (required) — PASS, FAIL, or ERROR",
    "message": "string (required) — human-readable description",
    "details": "string (optional) — additional context or raw data"
  }
]
```

**Example Bash script:**

```bash
#!/usr/bin/env bash
set -euo pipefail

PG_HOST=""
PG_PORT="5432"

for arg in "$@"; do
    case "$arg" in
        --pg_host=*) PG_HOST="${arg#*=}" ;;
        --pg_port=*) PG_PORT="${arg#*=}" ;;
    esac
done

# Your check logic here...
# Output JSON array to stdout:
echo '[{"resource_id":"mydb","resource_type":"PostgreSQL::Database","status":"PASS","message":"Encryption enabled"}]'
```

**Example Python script:**

```python
#!/usr/bin/env python3
import json, os, sys

def main():
    findings = []
    host = os.environ.get("DB_HOST", "")

    for arg in sys.argv[1:]:
        if arg.startswith("--pg_host="):
            host = arg.split("=", 1)[1]

    # Your check logic here...
    findings.append({
        "resource_id": host,
        "resource_type": "PostgreSQL::Database",
        "status": "PASS",
        "message": "Encryption at rest is enabled"
    })

    json.dump(findings, sys.stdout, indent=2)

if __name__ == "__main__":
    main()
```

### Step 4: Reference in config.yaml

```yaml
checks:
  - pack: my-pack
    check: database-encryption
    params:
      pg_host: "db.internal.example.com"
  - pack: my-pack
    check: backup-retention
```

### Step 5: Run

```bash
./comply-intel --config config.yaml --report
```

The engine automatically discovers your pack, validates the manifest, executes the scripts, and maps findings to compliance frameworks.

### Framework tag reference

Use these tag prefixes to map your checks to frameworks:

| Prefix | Framework | Example |
|--------|-----------|---------|
| `SOC2-` | SOC 2 Type II | `SOC2-CC6.1`, `SOC2-A1.2`, `SOC2-C1.1` |
| `NIST-` | NIST 800-53 | `NIST-SC-28`, `NIST-AC-3`, `NIST-AU-2` |
| `PCI-DSS-` | PCI DSS v4.0 | `PCI-DSS-3.4`, `PCI-DSS-8.3`, `PCI-DSS-10.1` |
| `CIS-AWS-` | CIS AWS Benchmark | `CIS-AWS-1.5`, `CIS-AWS-2.1.1` |
| `CIS-Linux-` | CIS Linux Benchmark | `CIS-Linux-4.1`, `CIS-Linux-6.2` |
| `CIS-Docker-` | CIS Docker Benchmark | `CIS-Docker-5.1`, `CIS-Docker-2.12` |
| `CIS-GitHub-` | CIS GitHub Benchmark | `CIS-GitHub-1.1`, `CIS-GitHub-3.1` |

---

## Project Structure

```
comply-intel/
│
├── cmd/
│   └── comply-intel/
│       └── main.go                  # CLI entry point, flag parsing, orchestration
│
├── internal/
│   ├── config/
│   │   ├── types.go                 # Config struct definitions
│   │   └── loader.go                # YAML parsing, validation, error messages
│   │
│   ├── discovery/
│   │   ├── types.go                 # Pack and Check struct definitions
│   │   └── loader.go                # Pack discovery, manifest validation, check lookup
│   │
│   ├── executor/
│   │   ├── finding.go               # Finding and EnrichedFinding types
│   │   └── executor.go              # Job building, concurrent dispatch, output parsing
│   │
│   ├── results/
│   │   └── writer.go                # Table, JSON, CSV output formatters
│   │
│   ├── scheduler/
│   │   └── scheduler.go             # Cron parser, interval runner, signal handling
│   │
│   └── aggregator/                  # THE SECURITY TEAM
│       ├── frameworks.go            # SOC2, NIST, PCI-DSS, CIS control definitions
│       ├── risk.go                  # Risk scoring, remediation plan generation
│       ├── compliance.go            # Framework compliance mapping, gap analysis
│       └── report.go                # Team report rendering (terminal + JSON)
│
├── packs/
│   ├── aws-pack/                    # 17 checks
│   │   ├── pack.yaml                # Manifest
│   │   ├── README.md                # Pack-specific documentation
│   │   └── scripts/
│   │       ├── check_s3_encryption.py
│   │       ├── check_s3_public_access.py
│   │       ├── check_s3_versioning.py
│   │       ├── check_s3_logging.py
│   │       ├── check_iam_password_policy.py
│   │       ├── check_iam_mfa.py
│   │       ├── check_iam_root_mfa.py
│   │       ├── check_iam_unused_creds.py
│   │       ├── check_iam_key_rotation.py
│   │       ├── check_cloudtrail_enabled.py
│   │       ├── check_cloudtrail_validation.py
│   │       ├── check_sg_ssh.py
│   │       ├── check_sg_rdp.py
│   │       ├── check_ebs_encryption.py
│   │       ├── check_rds_encryption.py
│   │       ├── check_rds_public.py
│   │       └── check_rds_backup.py
│   │
│   ├── linux-pack/                  # 10 checks
│   │   ├── pack.yaml
│   │   ├── README.md
│   │   └── scripts/
│   │       ├── check_password_policy.sh
│   │       ├── check_ssh_config.sh
│   │       ├── check_file_permissions.sh
│   │       ├── check_firewall.sh
│   │       ├── check_audit_logging.sh
│   │       ├── check_services.sh
│   │       ├── check_kernel_hardening.sh
│   │       ├── check_fs_encryption.sh
│   │       ├── check_user_accounts.sh
│   │       └── check_cron_permissions.sh
│   │
│   ├── github-pack/                 # 6 checks
│   │   ├── pack.yaml
│   │   ├── README.md
│   │   └── scripts/
│   │       ├── check_branch_protection.py
│   │       ├── check_secret_scanning.py
│   │       ├── check_dependabot.py
│   │       ├── check_org_2fa.py
│   │       ├── check_repo_visibility.py
│   │       └── check_actions_security.py
│   │
│   ├── network-pack/                # 5 checks
│   │   ├── pack.yaml
│   │   ├── README.md
│   │   └── scripts/
│   │       ├── check_tls_config.py
│   │       ├── check_open_ports.py
│   │       ├── check_dns_security.py
│   │       ├── check_http_headers.py
│   │       └── check_cert_expiry.py
│   │
│   └── docker-pack/                 # 6 checks
│       ├── pack.yaml
│       ├── README.md
│       └── scripts/
│           ├── check_daemon_config.sh
│           ├── check_container_privileges.sh
│           ├── check_image_vulnerabilities.sh
│           ├── check_container_networking.sh
│           ├── check_docker_logging.sh
│           └── check_resource_limits.sh
│
├── config.yaml                      # User configuration (edit this)
├── go.mod                           # Go module definition
├── go.sum                           # Go dependency checksums
└── .gitignore
```

---

## Security Considerations

### Credential handling
- Credentials are **never passed on the command line** — they are injected as environment variables into script subprocesses
- For production deployments, set credentials in your shell environment or use a secrets manager rather than storing them in `config.yaml`
- The `.gitignore` excludes `.env`, `*.pem`, `*.key`, and `credentials.json`

### Script execution
- Every script runs with a configurable **timeout** — hung scripts are killed automatically
- Scripts that produce **any output to stderr** are treated as failures (prevents partial/corrupt output)
- The engine strictly expects **valid JSON arrays** on stdout — malformed output causes the check to fail with a clear error
- Scripts run as the same user as the engine — use appropriate permissions

### Data handling
- All scripts are **stateless** — no data persists between runs
- The engine **validates every pack manifest** before execution
- Malformed packs are disabled with a clear warning, not silently skipped

### Network checks
- Network pack scripts make **real connections** to specified targets
- Only run network checks against infrastructure you own or have authorization to test
- Certificate and TLS checks use standard Python `ssl` module — no custom crypto

---

## Troubleshooting

### "no valid agent packs found"
The `packs_dir` in your config doesn't contain any valid packs. Check:
- The path is correct (relative to where you run the binary)
- Each pack subdirectory contains a `pack.yaml`
- The `pack.yaml` has the required `name`, `version`, and `checks` fields

### "script failed: exit status 1"
A check script crashed. Common causes:
- Missing dependencies (`pip install boto3` for AWS checks)
- Missing permissions (run as root/sudo for Linux checks that read `/etc/shadow`)
- Script isn't executable (`chmod +x packs/*/scripts/*`)

### "script produced stderr output"
The engine treats any stderr as a fatal error for that check. This is by design to ensure clean JSON output. Check the error message for the specific stderr content.

### "script output is not valid JSON array"
The check script printed something other than a JSON array to stdout. Ensure:
- The script outputs `[]` for no findings (not empty string)
- No debug `print()` statements go to stdout (use stderr or remove them)
- The JSON is a top-level array `[...]`, not a single object `{...}`

### AWS checks return "boto3 library is not installed"
```bash
pip install boto3
# or
pip3 install boto3
```

### Kernel hardening checks show "parameter not available"
This is expected in containerized or minimal environments where `/proc/sys/` is restricted. These show as ERROR (not FAIL) to distinguish from actual misconfigurations.

### Scheduled mode won't stop
Press `Ctrl+C` to send SIGINT. The engine handles it gracefully and finishes the current scan before exiting.

---

## Roadmap

Potential future enhancements:

- **Azure pack** — Azure AD, Storage, NSG, Key Vault checks
- **GCP pack** — IAM, Cloud Storage, VPC, Cloud Audit Logs
- **Kubernetes pack** — RBAC, network policies, pod security standards
- **Webhook output** — POST results to Slack, PagerDuty, or custom endpoints
- **PostgreSQL/InfluxDB storage** — persistent historical data
- **Grafana dashboard** — compliance posture visualization over time
- **Evidence collection** — auto-generate audit evidence packages for SOC 2 auditors
- **Policy-as-code** — OPA/Rego integration for custom policy evaluation
- **SBOM analysis pack** — software bill of materials compliance checks

---

## License

This project is proprietary. All rights reserved.
