## Phishing Email Header Analysis – Amazon Order Summary

### 1. Email Overview
This email appeared to be an **Amazon Order Confirmation** but is a **phishing attempt** designed to trick users into clicking a malicious link.  

**Key Details from Gmail “Show Original”:**  
- **Message-ID:** 20250805182000.random@fakehost.ru  
- **Created At:** 8/6/2025, 2:40:42 AM GMT+5:30  
- **From:** Amazon Order Summary <orders@amazn-secure.com>  
- **To:** Customer <your_email@gmail.com>  
- **Subject:** Order Confirmation: Your Receipt #459203  

---

### 2. Email Authentication Results
| Authentication Check | Status | Observation |
|----------------------|--------|-------------|
| **SPF**              | **Fail** | Sending IP is not authorized for `amazn-secure.com` |
| **DKIM**             | **Fail** | Signature does not match the claimed domain |
| **DMARC**            | **Fail** | Domain policy requires SPF or DKIM pass, both failed |

**Key Insight:**  
All three email authentication checks **failed**, confirming that the sender is **unauthorized** and the email is **spoofed**.

---

### 3. Mail Transmission Path
```
mail.fakehost.ru  →  [Google] mx.google.com via ESMTPS
```
- The email originated from **mail.fakehost.ru** (unrelated to Amazon).  
- Gmail detected **SPF/DKIM failures** on arrival.  

---

### 4. Phishing Indicators in Header
1. **Spoofed domain:** `amazn-secure.com` instead of `amazon.com`  
2. **Failed SPF/DKIM/DMARC checks:** Indicates sender is not legitimate  
3. **Suspicious Message-ID:** Generated from `fakehost.ru`, unrelated to Amazon  
4. **Unknown sending IP:** Suggests use of a compromised or malicious server  

---

### 5. Conclusion
The email header analysis clearly demonstrates **classic phishing behavior**:  
- Spoofed sender identity  
- Unauthorized mail server usage  
- Complete failure of standard email authentication (SPF, DKIM, DMARC)  

These indicators confirm that this email is **phishing** and should be **reported and deleted immediately**.

**Reference Screenshot:**  
<img width="1327" height="643" alt="Screenshot 2025-08-05 at 6 12 56 PM" src="https://github.com/user-attachments/assets/cd0d1186-759f-4e56-877b-d6af038a1386" />

