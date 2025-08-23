## Objectives
- Perform a basic vulnerability scan on local macOS system using Nessus Essentials.
- Identify vulnerabilities of varying severity levels (Critical, High, Medium, Low, Info).
- Document detailed findings with screenshots.
- Suggest possible remediation steps for detected vulnerabilities.

## Scan Details
| Field          | Value |
|----------------|-------|
| Tool Used      | Nessus Essentials |
| Scan Type      | Basic Network Scan |
| Target         | Local IP (192.168.1.35) |
| OS             | macOS 15.5 |
| Scan Duration  | 36 minutes |
| Total Findings | 50 vulnerabilities |

## Steps Performed
1. Installed and launched Nessus Essentials on macOS.
2. Selected **Basic Network Scan** template.
3. Entered local IP (`192.168.1.35`) as the scan target.
4. Ran the scan and waited for completion (~36 minutes).
5. Reviewed scan results and noted vulnerabilities by severity.
6. Captured screenshots:
   - `summary.png` – Overall scan summary with vulnerability counts.
   - `medium-rexml.png` – Medium severity Ruby REXML DoS vulnerability.
   - `high-critical-nodejs.png` – High and Critical Node.js vulnerabilities.
7. Prepared remediation recommendations based on Nessus report.

## Observations
- Vulnerabilities found across Critical, High, Medium, and Informational categories.
- Critical & High vulnerabilities caused by outdated Node.js versions.
- Medium vulnerability due to outdated Ruby REXML library (DoS risk).
- Several informational findings about running services & software versions.
- Most issues can be mitigated by updating packages and applying OS patches.

## Conclusion
The Nessus Essentials scan revealed key areas needing security updates on my macOS system.  
Regular scanning, timely patching, and minimizing exposed services are essential for maintaining system security.  
This task improved my skills in using Nessus Essentials, understanding CVSS scoring, and prioritizing remediation.
