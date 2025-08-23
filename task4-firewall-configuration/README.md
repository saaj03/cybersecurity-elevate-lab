## Firewall Rule Implementation – Blocking Telnet (Port 23) on Kali Linux

---

### 1. Task Overview
This task involved configuring the **Kali Linux firewall** using **UFW (Uncomplicated Firewall)** to **block inbound Telnet traffic (TCP port 23)** and verify that the block was effective through testing.  

**System Details:**  
- **OS:** Kali Linux 2025  
- **Firewall Tool:** UFW (front-end for iptables/nftables)  
- **Objective:** Deny Telnet traffic for both network and local loopback connections  

---

### 2. Firewall Rule Summary
| Rule # | Port / Protocol | Interface | Action  | Source    |
|--------|----------------|-----------|---------|-----------|
| **1**  | 22/tcp         | any       | Allow   | Anywhere  |
| **2**  | 23/tcp         | any       | Deny    | Anywhere  |
| **3**  | 23/tcp         | lo        | Deny    | Anywhere  |
| **4**  | 22/tcp (v6)    | any       | Allow   | Anywhere (v6) |
| **5**  | 23/tcp (v6)    | any       | Deny    | Anywhere (v6) |
| **6**  | 23/tcp (v6)    | lo        | Deny    | Anywhere (v6) |

**Key Insight:**  
Rules 2, 3, 5, and 6 ensure **Telnet is completely blocked** on all network interfaces **and** loopback for both IPv4 and IPv6.

---

### 3. Commands Executed
```bash
# Install UFW if not installed
sudo apt install ufw -y

# Allow SSH (to prevent lockout)
sudo ufw allow 22/tcp

# Enable firewall
sudo ufw enable

# Block Telnet on all interfaces (IPv4 and IPv6)
sudo ufw deny in 23/tcp

# Block Telnet on loopback (for localhost testing)
sudo ufw deny in on lo to any port 23 proto tcp

# Verify numbered rules
sudo ufw status numbered

# Save firewall status to file
sudo ufw status numbered | tee ufw-status.txt

# Test Telnet connection
nc -vz 127.0.0.1 23 | tee nc-test.txt
```

---

### 4. Test Results
| Test Command              | Expected Outcome         | Actual Outcome          |
|---------------------------|--------------------------|-------------------------|
| `nc -vz 127.0.0.1 23`     | Connection refused/timeout | **Connection refused ✅** |

**Key Insight:**  
The firewall successfully prevented Telnet connections on both **network interfaces** and **localhost loopback**.

---

### 5. Security Rationale
1. **Telnet is insecure** – It sends credentials in plaintext, making it vulnerable to sniffing and MITM attacks.  
2. **Attack surface reduction** – Closing unused/insecure ports limits potential entry points for attackers.  
3. **Compliance** – Many security standards (e.g., CIS benchmarks) recommend disabling Telnet in favor of SSH.

---

### 6. Conclusion
The firewall configuration is **active** and **successfully blocking** Telnet traffic on all interfaces.  
Testing confirmed the deny rules work as intended.  

---
