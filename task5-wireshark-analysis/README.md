## Network Traffic Capture & Analysis – DNS Protocol using Wireshark

---

### 1. Task Overview
This task involved capturing **live network packets** using **Wireshark**, filtering for **DNS traffic**, and analyzing the packet structure, protocol hierarchy, and query details. The main objective was to understand how DNS queries and responses occur when accessing a website.  

**System Details:**  
- **OS:** Kali Linux 2025  
- **Tool:** Wireshark (GUI-based network protocol analyzer)  
- **Objective:** Capture DNS packets and analyze their structure & protocol hierarchy  

---

### 2. Capture Summary
| Step # | Action Performed                                           | Outcome |
|--------|------------------------------------------------------------|---------|
| **1**  | Selected active network interface (`eth0`) in Wireshark    | Ready for capture |
| **2**  | Started packet capture                                     | Traffic recorded |
| **3**  | Opened `www.youtube.com` in browser to generate DNS queries| DNS packets generated |
| **4**  | Applied display filter: `dns`                              | Only DNS packets shown |
| **5**  | Analyzed one DNS query & response pair                     | Domain resolution observed |
| **6**  | Viewed **Protocol Hierarchy Statistics**                   | % of traffic by protocol |
| **7**  | Exported `.pcapng` and saved screenshots                   | Files ready for submission |

---

### 4. Commands / Filters Used
```bash
# Update package list
sudo apt update

# Install Wireshark
sudo apt install wireshark -y

# Grant permission to capture packets without root
sudo usermod -aG wireshark $USER

# Open Wireshark
wireshark &

# Start capture on active interface (GUI)
# Apply display filter for DNS packets
dns

# Export capture file
File → Export Specified Packets → Save as .pcapng

# View protocol hierarchy in Wireshark
Statistics → Protocol Hierarchy
```

---

### 5. Observations
1. All captured packets in this session were **DNS protocol over UDP**.  
2. The DNS server queried was **192.168.64.1**, responding to client **192.168.64.2**.  
3. The DNS query for `www.youtube.com` resulted in multiple CNAME resolutions before returning the final IP addresses.  
4. DNS packet sizes were small, averaging **~60–75 bytes**, which is typical for DNS requests.  

---

### 6. Conclusion
The Wireshark capture successfully demonstrated **how DNS queries and responses work**.  
By filtering with `dns`, it was easy to isolate relevant packets and observe the query–response process.  
The protocol hierarchy confirmed that **100% of traffic in this capture was DNS over UDP**, meeting the task objective.  

---
