# Linux Hardening Audit Report
_Generated: 2025-08-23 13:57:02_

**Compliance Score:** 47 / 95  (49.5%)

## System
- Kernel/Distro: Kali GNU/Linux Rolling (kernel 6.12.33+kali-arm64)

## Summary
- firewall: **PASS** (10/10)
- ssh: **FAIL** (0/15)
- file_perms: **PASS** (10/10)
- password_policy: **FAIL** (0/10)
- suid_sgid: **PASS** (8/8)
- open_ports: **PASS** (8/8)
- updates: **FAIL** (0/8)
- auditd: **FAIL** (0/8)
- time_sync: **PASS** (6/6)
- fail2ban: **FAIL** (0/7)
- selinux: **PASS** (5/5)

## Detailed Findings
### Firewall
- **engine**: `ufw`
- **status**: `active`
- **rules_present**: `True`
- **evidence**: `Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere                  
23/tcp                     DENY        Anywhere                  
23/tcp on lo               DENY        Anywhere                  
22/tcp (v6)                ALLOW       Anywhere (v6)             
23/tcp (v6)                DENY        Anywhere (v6)             
23/tcp (v6) on lo          DENY        Anywhere (v6)`

### SSH Config
- **evidence**: `{'port': '<unset>', 'permitrootlogin': '<unset>', 'passwordauthentication': '<unset>', 'x11forwarding': 'yes', 'maxauthtries': '<unset>', 'permitemptypasswords': '<unset>', 'protocol': '<unset>'}`
- **findings**: `["PasswordAuthentication should be 'no' (use keys)", "X11Forwarding should be 'no'", 'MaxAuthTries should be <= 4']`

### File Permissions
- **issues**: `[]`
- **evidence**: `{'/etc/passwd': '0o644', '/etc/shadow': '0o640', '/etc/group': '0o644'}`

### Password Policy
- **evidence**: `{'login.defs': {'PASS_MAX_DAYS': 99999, 'PASS_MIN_DAYS': 0, 'PASS_WARN_AGE': 7}, 'pwquality.minlen': None}`
- **findings**: `['PASS_MAX_DAYS should be <= 365', 'PASS_MIN_DAYS should be >= 1']`

### SUID/SGID
- **count**: `35`
- **samples**: `['/usr/bin/kismet_cap_hak5_wifi_coconut', '/usr/bin/kismet_cap_nxp_kw41z', '/usr/bin/ssh-agent', '/usr/bin/passwd', '/usr/bin/kismet_cap_linux_bluetooth', '/usr/bin/fusermount3', '/usr/bin/ntfs-3g', '/usr/bin/kismet_cap_nrf_51822', '/usr/bin/rsh-redone-rsh', '/usr/bin/sudo', '/usr/bin/newgrp', '/usr/bin/dotlockfile', '/usr/bin/kismet_cap_ti_cc_2531', '/usr/bin/mount', '/usr/bin/pkexec']`

### Open Ports
- **count**: `3`
- **samples**: `['udp   UNCONN 0      0      [fe80::7c90:e6ff:fec6:6a87]%eth0:546          [::]:*', 'tcp   LISTEN 0      128                             0.0.0.0:22        0.0.0.0:*', 'tcp   LISTEN 0      128                                [::]:22           [::]:*']`

### Updates
- **upgradeable**: `449`
- **evidence**: `7zip/kali-rolling 25.01+dfsg-1 arm64 [upgradable from: 24.09+dfsg-8]
apache2-bin/kali-rolling 2.4.65-3+b1 arm64 [upgradable from: 2.4.65-2]
apache2-data/kali-rolling 2.4.65-3 all [upgradable from: 2.4.65-2]
apache2-utils/kali-rolling 2.4.65-3+b1 arm64 [upgradable from: 2.4.65-2]
apache2/kali-rolling 2.4.65-3+b1 arm64 [upgradable from: 2.4.65-2]
apt-transport-https/kali-rolling 3.1.4+kali1 all [upgradable from: 3.0.3+kali1]
apt-utils/kali-rolling 3.1.4+kali1 arm64 [upgradable from: 3.0.3+kali1]
apt/kali-rolling 3.1.4+kali1 arm64 [upgradable from: 3.0.3+kali1]
arping/kali-rolling 2.26-1 arm64 [upgradable from: 2.25-1+b1]
atril-common/kali-rolling 1.26.2-5 all [upgradable from: 1.26.2-4]
atril/kali-rolling 1.26.2-5+b1 arm64 [upgradable from: 1.26.2-4]
base-files/kali-rolling 1:2025.3.0 arm64 [upgradable from: 1:2025.2.0]
bind9-dnsutils/kali-rolling 1:9.20.11-4+b1 arm64 [upgradable from: 1:9.20.11-4]
bind9-host/kali-rolling 1:9.20.11-4+b1 arm64 [upgradable from: 1:9.20.11-4]
bind9-libs/kali-rolling 1:9.20.11-4+b1 arm64 [upgradable from: 1:9.20.11-4]
bsdextrautils/kali-rolling 2.41.1-1 arm64 [upgradable from: 2.41-5]
bsdutils/kali-rolling 1:2.41.1-1 arm64 [upgradable from: 1:2.41-5]
cherrytree/kali-rolling 1.2.0+dfsg-1+b1 arm64 [upgradable from: 1.2.0+dfsg-1]
chromium-common/kali-rolling 139.0.7258.127-2 arm64 [upgradable from: 138.0.7204.183-1]
chromium-sandbox/kali-rolling 139.0.7258.127-2 arm64 [upgradable from: 138.0.7204.183-1]`

### auditd
- **active**: `False`
- **enabled**: `False`

### Time Sync
- **services**: `{'systemd-timesyncd': {'active': True, 'enabled': True}, 'chronyd': {'active': False, 'enabled': False}, 'ntpd': {'active': False, 'enabled': False}}`

### Fail2ban
- **active**: `False`
- **enabled**: `False`

### SELinux
- **evidence**: `SELinux not available (likely Debian/Ubuntu)`

---
**Note:** This is a baseline audit. Always review findings in context of the system's role and security policy.