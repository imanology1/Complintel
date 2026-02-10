# Linux Agent Pack

System hardening and compliance checks for Linux servers.

## Checks

| ID | Description | Severity | Frameworks |
|----|-------------|----------|------------|
| `password-policy` | Verify password policies (length, expiration, PAM modules) | High | CIS-Linux, NIST-800-53, SOC2 |
| `ssh-config` | Verify SSH daemon hardening (no root login, key-only auth) | Critical | CIS-Linux, NIST-800-53, PCI-DSS |

## Prerequisites

- Bash 4.0+
- Read access to `/etc/login.defs`, `/etc/ssh/sshd_config`, and PAM config files

## Parameters

### password-policy

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `min_length` | No | `14` | Minimum required password length |
| `max_days` | No | `90` | Maximum password age in days |

### ssh-config

No parameters required.

## Example Findings

```json
[
  {
    "resource_id": "/etc/login.defs",
    "resource_type": "Linux::PasswordPolicy",
    "status": "FAIL",
    "message": "Minimum password length is 8 (required: 14)"
  },
  {
    "resource_id": "/etc/ssh/sshd_config:PermitRootLogin",
    "resource_type": "Linux::SSHConfig",
    "status": "PASS",
    "message": "Root login is disabled"
  }
]
```
