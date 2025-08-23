# Linux Hardening Audit Report
_Generated: 2025-08-23 13:26:27_

**Compliance Score:** 29 / 95  (30.5%)

## System
- Kernel/Distro:  (kernel 24.5.0)

## Summary
- firewall: **FAIL** (0/10)
- ssh: **FAIL** (0/15)
- file_perms: **FAIL** (0/10)
- password_policy: **FAIL** (0/10)
- suid_sgid: **PASS** (8/8)
- open_ports: **PASS** (8/8)
- updates: **PASS** (8/8)
- auditd: **FAIL** (0/8)
- time_sync: **FAIL** (0/6)
- fail2ban: **FAIL** (0/7)
- selinux: **PASS** (5/5)

## Detailed Findings
### Firewall
- **engine**: `none`
- **status**: `unknown`
- **rules_present**: `False`
- **evidence**: `No firewall tooling found`

### SSH Config
- **evidence**: `{'port': '<unset>', 'permitrootlogin': '<unset>', 'passwordauthentication': '<unset>', 'x11forwarding': '<unset>', 'maxauthtries': '<unset>', 'permitemptypasswords': '<unset>', 'protocol': '<unset>'}`
- **findings**: `["PasswordAuthentication should be 'no' (use keys)", 'MaxAuthTries should be <= 4']`

### File Permissions
- **issues**: `['/etc/shadow mode N/A > 0640']`
- **evidence**: `{'/etc/passwd': '0o644', '/etc/shadow': 'N/A', '/etc/group': '0o644'}`

### Password Policy
- **evidence**: `{'login.defs': {}, 'pwquality.minlen': None}`
- **findings**: `['PASS_MAX_DAYS should be <= 365', 'PASS_MIN_DAYS should be >= 1', 'PASS_WARN_AGE should be >= 7']`

### SUID/SGID
- **count**: `13`
- **samples**: `['/bin/ps', '/usr/bin/write', '/usr/bin/top', '/usr/bin/atq', '/usr/bin/crontab', '/usr/bin/atrm', '/usr/bin/newgrp', '/usr/bin/su', '/usr/bin/batch', '/usr/bin/at', '/usr/bin/quota', '/usr/bin/sudo', '/usr/bin/login']`

### Open Ports
- **count**: `0`
- **samples**: `[]`

### Updates
- **evidence**: `no package manager detected`

### auditd
- **active**: `False`
- **enabled**: `False`

### Time Sync
- **services**: `{'systemd-timesyncd': {'active': False, 'enabled': False}, 'chronyd': {'active': False, 'enabled': False}, 'ntpd': {'active': False, 'enabled': False}}`

### Fail2ban
- **active**: `False`
- **enabled**: `False`

### SELinux
- **evidence**: `SELinux not available (likely Debian/Ubuntu)`

---
**Note:** This is a baseline audit. Always review findings in context of the system's role and security policy.