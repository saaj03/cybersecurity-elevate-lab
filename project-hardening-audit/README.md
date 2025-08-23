# 🔐 Linux & macOS Hardening Audit Project

## 📌 Introduction
This project was developed as part of my internship cybersecurity lab.  
The goal was to **audit and harden two operating systems** — Kali Linux and macOS —  
to detect vulnerabilities, apply security controls, and demonstrate improved compliance.

---

## 📊 Baseline Findings
- **Kali Linux:** Compliance Score **49.5%**  
  - Weak SSH configuration  
  - No password policy enforced  
  - 449 outdated packages  
  - `auditd` and `fail2ban` disabled  

- **macOS:** Compliance Score **30.5%**  
  - Firewall undetected by script  
  - SSH defaults not hardened  
  - Password policy missing  
  - Audit logging disabled  

---

## 🛠 Tools Used
- **Python** – custom [`linux_audit.py`](linux_audit.py) script for Linux auditing  
- **Bash** – `mac_audit.sh` script for macOS auditing  
- **Linux Services** – `ufw`, `auditd`, `fail2ban`, `systemd-timesyncd`  
- **macOS Utilities** – `socketfilterfw` (firewall), `softwareupdate`, `fdesetup` (FileVault)  

---

## 🚀 Steps
1. **Baseline Audit**  
   - Ran `linux_audit.py` on Kali → initial score 49.5%  
   - Ran `mac_audit.sh` on macOS → initial score 30.5%  

2. **Identified Issues**  
   - Outdated software, weak SSH/password settings, disabled logging  

3. **Remediation**  
   - **Kali:** Updated packages, hardened SSH, enabled auditd + fail2ban, enforced password policies  
   - **macOS:** Enabled firewall + FileVault, disabled Remote Login, applied OS updates  

4. **Re-Audit**  
   - Verified improved compliance and resolved critical risks  

---

## ✅ Conclusion
Hardening improved both systems significantly, reducing exposure to brute-force attacks, unpatched vulnerabilities, and weak authentication.  
This project demonstrates the importance of **continuous auditing, patching, and layered defenses** across Linux and macOS.  

---
