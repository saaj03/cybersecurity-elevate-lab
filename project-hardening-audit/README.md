# Linux & macOS Hardening Audit Project

## 📌 Introduction
This project was completed as part of my internship cybersecurity lab.  
The goal was to **audit and harden two operating systems** — Kali Linux and macOS —  
to detect vulnerabilities, apply security controls, and demonstrate improved compliance.

---

## 📌 Tools Used
- **Python** – custom `linux_audit.py` script for Linux hardening checks
- **Bash** – `mac_audit.sh` script for macOS quick audit
- **Linux Services** – `ufw`, `auditd`, `fail2ban`, `systemd-timesyncd`
- **macOS Utilities** – `socketfilterfw`, `softwareupdate`, `fdesetup` (FileVault)

---

## 📌 Steps
1. **Baseline Audit**
   - Ran `linux_audit.py` on Kali Linux → initial compliance **49.5%**.
   - Ran `mac_audit.sh` on macOS → initial compliance **30.5%**.
   - Collected findings into `.md` and `.json` reports.

2. **Findings**
   - Kali Linux: Weak SSH config, no password policy, 449 outdated packages, auditd & Fail2ban disabled.
   - macOS: Firewall undetected, SSH defaults weak, password policy missing, audit logging disabled.

3. **Remediation**
   - Kali Linux:
     - Patched system (`apt full-upgrade`).
     - Hardened SSH (`PasswordAuthentication no`, `MaxAuthTries 4`, `X11Forwarding no`).
     - Enabled `auditd` and `fail2ban`.
     - Enforced password policies in `/etc/login.defs` and `/etc/security/pwquality.conf`.
   - macOS:
     - Enabled Application Firewall.
     - Disabled Remote Login when not needed.
     - Applied updates via `softwareupdate -ia`.
     - Verified FileVault (disk encryption) enabled.

4. **Re-Audit**
   - Reports confirmed improved compliance after fixes.
   - Critical issues (weak SSH, outdated software) resolved.

---

## 📌 Conclusion
This project demonstrated how **system auditing and hardening** can improve endpoint security.  
By applying patches, enforcing strong SSH and password policies, enabling logging and brute-force protection, both **Kali Linux and macOS showed measurable security improvements**.  
Future work includes automating patch management and aligning with CIS benchmarks.

---
