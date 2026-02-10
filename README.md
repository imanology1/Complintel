# Comply-Intel — GRC Agent Factory

A pluggable Governance, Risk, and Compliance (GRC) automation platform. Define compliance checks as simple scripts, organize them into agent packs, and let the core engine handle scheduling, execution, and reporting.

## Architecture

```
┌─────────────────────────────────────────────┐
│              Core Engine (Go)               │
│  ┌──────────┐ ┌──────────┐ ┌─────────────┐ │
│  │  Config   │ │ Discovery│ │  Scheduler  │ │
│  │  Loader   │ │  Loader  │ │ (cron/once) │ │
│  └──────────┘ └──────────┘ └─────────────┘ │
│  ┌──────────────────┐  ┌──────────────────┐ │
│  │ Execution Engine  │  │ Results Writer   │ │
│  │ (concurrent,      │  │ (JSON/CSV/table) │ │
│  │  timeouts, env)   │  │                  │ │
│  └──────────────────┘  └──────────────────┘ │
└────────────────┬────────────────────────────┘
                 │ executes
    ┌────────────┼────────────┐
    ▼            ▼            ▼
┌─────────┐ ┌─────────┐ ┌──────────┐
│ AWS Pack│ │Linux Pack│ │GitHub Pack│
│ (Python)│ │ (Bash)  │ │ (Python) │
└─────────┘ └─────────┘ └──────────┘
```

## Quick Start

### 1. Build the engine

```bash
go build -o comply-intel ./cmd/comply-intel
```

### 2. Make agent scripts executable

```bash
chmod +x packs/*/scripts/*
```

### 3. Configure

Edit `config.yaml` to select which checks to run and provide credentials:

```yaml
packs_dir: "./packs"
schedule: "once"
concurrency: 4
timeout: "120s"

output:
  format: "table"
  target: "stdout"

credentials:
  AWS_REGION: "us-east-1"

checks:
  - pack: linux
    check: password-policy
  - pack: linux
    check: ssh-config
```

### 4. Run

```bash
./comply-intel --config config.yaml
```

## Output Formats

| Format | Description |
|--------|-------------|
| `table` | Human-readable table to terminal (default) |
| `json` | Full JSON array of enriched findings |
| `csv` | CSV file with headers |

Output can be directed to `stdout` or a `file` (set `output.target` and `output.path`).

## Scheduling

| Value | Behavior |
|-------|----------|
| `once` | Single scan, then exit |
| `every 5m` | Run every 5 minutes |
| `every 1h` | Run every hour |
| `0 2 * * *` | Cron: daily at 2:00 AM |

## Agent Packs

Agent packs are self-contained directories with a `pack.yaml` manifest and a `scripts/` folder.

### Available Packs

| Pack | Checks | Language |
|------|--------|----------|
| **aws** | `s3-encryption`, `s3-public-access` | Python (boto3) |
| **linux** | `password-policy`, `ssh-config` | Bash |
| **github** | `branch-protection` | Python (stdlib) |

See each pack's `README.md` for details on credentials and parameters.

### Creating Your Own Pack

1. Create a directory under `packs/` (e.g., `packs/my-pack/`)
2. Add a `pack.yaml` manifest:

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
      - SOC2
    params:
      - name: threshold
        required: false
        default: "10"
```

3. Add your script to `packs/my-pack/scripts/my_check.sh`
4. Your script MUST output a JSON array of findings to stdout:

```json
[
  {
    "resource_id": "the-resource",
    "resource_type": "MySystem::Resource",
    "status": "PASS",
    "message": "Check passed"
  }
]
```

5. Reference it in `config.yaml` and run.

### Finding Schema

Every agent script must output a JSON array where each object has:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resource_id` | string | Yes | Identifier of the resource checked |
| `resource_type` | string | Yes | Type/category of the resource |
| `status` | string | Yes | `PASS`, `FAIL`, or `ERROR` |
| `message` | string | Yes | Human-readable result |
| `details` | string | No | Additional context |

## Project Structure

```
comply-intel/
├── cmd/comply-intel/main.go    # CLI entry point
├── internal/
│   ├── config/                 # Config loader & types
│   ├── discovery/              # Pack discovery & validation
│   ├── executor/               # Concurrent script execution
│   ├── results/                # Output formatting (JSON/CSV/table)
│   └── scheduler/              # Cron & interval scheduling
├── packs/
│   ├── aws-pack/               # AWS compliance checks
│   ├── linux-pack/             # Linux hardening checks
│   └── github-pack/            # GitHub security checks
├── config.yaml                 # User configuration
└── go.mod
```

## Security Notes

- Credentials are passed to scripts via **environment variables**, never command-line arguments
- Agent scripts run with configurable **timeouts** to prevent hangs
- Scripts that produce `stderr` output are treated as failures
- Each script is **stateless** — no data persists between runs
