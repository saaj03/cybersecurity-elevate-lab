#!/usr/bin/env python3
"""
Linux Hardening Audit Tool
- Generates a compliance score and a Markdown report.
- Focuses on pragmatic, interview-ready checks mapped to common CIS hardening themes.
- No external Python packages required.
Tested on: Ubuntu/Debian, RHEL/CentOS/AlmaLinux/Rocky, and generic systemd hosts.
"""
import os, re, json, shutil, subprocess, stat, platform, datetime, argparse
from typing import Dict, Any, List, Tuple

# ----------------------------- helpers -----------------------------

def run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found"
    except Exception as e:
        return 1, "", str(e)

def read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def file_mode(path: str) -> str:
    try:
        m = os.stat(path).st_mode
        return oct(stat.S_IMODE(m))
    except Exception:
        return "N/A"

def is_systemd() -> bool:
    return shutil.which("systemctl") is not None

def service_active(name: str) -> bool:
    if not is_systemd(): 
        return False
    code, out, _ = run(["systemctl", "is-active", name])
    return (code == 0) and (out.strip() == "active")

def service_enabled(name: str) -> bool:
    if not is_systemd():
        return False
    code, out, _ = run(["systemctl", "is-enabled", name])
    return (code == 0) and (out.strip() == "enabled")

def which_first(*names) -> str:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return ""

# ----------------------------- checks -----------------------------

def detect_os() -> Dict[str, Any]:
    data = {"name": platform.system(), "release": platform.release(), "version": platform.version(), "distro": ""}
    os_release = read_file("/etc/os-release")
    m = re.search(r'^PRETTY_NAME="?(.*?)"?$', os_release, flags=re.MULTILINE)
    if m:
        data["distro"] = m.group(1)
    return {"ok": True, "details": data, "evidence": os_release[:300]}

def check_firewall() -> Dict[str, Any]:
    # Support ufw, firewalld, nftables, iptables
    result = {"ok": False, "engine": None, "status": "unknown", "rules_present": False, "evidence": ""}
    # ufw
    if which_first("ufw"):
        code, out, _ = run(["ufw", "status"])
        result["engine"] = "ufw"
        result["evidence"] = out
        if "Status: active" in out:
            result["ok"] = True
            result["status"] = "active"
        else:
            result["status"] = "inactive"
        result["rules_present"] = any(line.strip().startswith(("To", "Anywhere")) for line in out.splitlines())
        return result
    # firewalld
    if which_first("firewall-cmd"):
        code, out, _ = run(["firewall-cmd", "--state"])
        result["engine"] = "firewalld"
        result["evidence"] = out
        if out.strip() == "running":
            result["ok"] = True
            result["status"] = "active"
        else:
            result["status"] = "inactive"
        return result
    # nftables
    if which_first("nft"):
        code, out, _ = run(["nft", "list", "ruleset"])
        result["engine"] = "nftables"
        result["evidence"] = out[:500]
        result["ok"] = (code == 0) and ("table" in out)
        result["status"] = "ruleset-present" if result["ok"] else "empty"
        result["rules_present"] = result["ok"]
        return result
    # iptables fallback
    if which_first("iptables"):
        code, out, _ = run(["iptables", "-L"])
        result["engine"] = "iptables"
        result["evidence"] = out[:500]
        result["ok"] = (code == 0) and ("Chain" in out)
        result["status"] = "rules-present" if result["ok"] else "empty"
        result["rules_present"] = result["ok"]
        return result
    result["engine"] = "none"
    result["evidence"] = "No firewall tooling found"
    return result

def parse_sshd_config() -> Dict[str, str]:
    text = read_file("/etc/ssh/sshd_config")
    conf = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            k, v = parts
            conf[k.lower()] = v.strip()
    return conf

def check_ssh_config() -> Dict[str, Any]:
    conf = parse_sshd_config()
    evidence = {k: conf.get(k, "<unset>") for k in [
        "port","permitrootlogin","passwordauthentication","x11forwarding",
        "maxauthtries","permitemptypasswords","protocol"
    ]}
    ok = True
    findings = []
    # Defaults are distro specific; use sensible hardening expectations
    if conf.get("permitrootlogin", "prohibit-password").lower() not in ["no", "prohibit-password", "without-password"]:
        ok = False; findings.append("PermitRootLogin should be 'no' or 'prohibit-password'")
    if conf.get("passwordauthentication", "yes").lower() != "no":
        findings.append("PasswordAuthentication should be 'no' (use keys)")
        ok = False
    if conf.get("x11forwarding", "no").lower() != "no":
        findings.append("X11Forwarding should be 'no'")
        ok = False
    if int(conf.get("maxauthtries", "6")) > 4:
        findings.append("MaxAuthTries should be <= 4")
        ok = False
    if conf.get("permitemptypasswords", "no").lower() != "no":
        findings.append("PermitEmptyPasswords should be 'no'")
        ok = False
    return {"ok": ok, "evidence": evidence, "findings": findings}

def check_file_permissions() -> Dict[str, Any]:
    paths = ["/etc/passwd", "/etc/shadow", "/etc/group"]
    expected = {
        "/etc/passwd": {"max_mode":"0644"},
        "/etc/group": {"max_mode":"0644"},
        "/etc/shadow": {"max_mode":"0640"}  # some distros use 0600; we'll accept <=0640
    }
    issues = []
    for p in paths:
        mode = file_mode(p)
        exp = expected[p]["max_mode"]
        try:
            ok = int(mode, 8) <= int(exp, 8)
        except Exception:
            ok = False
        if not ok:
            issues.append(f"{p} mode {mode} > {exp}")
    return {"ok": len(issues) == 0, "issues": issues, "evidence": {p: file_mode(p) for p in paths}}

def check_password_policy() -> Dict[str, Any]:
    content = read_file("/etc/login.defs")
    values = {}
    for key in ["PASS_MAX_DAYS","PASS_MIN_DAYS","PASS_WARN_AGE"]:
        m = re.search(rf"^{key}\s+(\d+)", content, flags=re.MULTILINE)
        if m: values[key] = int(m.group(1))
    # pwquality
    pwq_conf = read_file("/etc/security/pwquality.conf")
    minlen = None
    m = re.search(r"^\s*minlen\s*=\s*(\d+)", pwq_conf, flags=re.MULTILINE)
    if m: minlen = int(m.group(1))
    # expectations
    findings = []
    ok = True
    if values.get("PASS_MAX_DAYS", 99999) > 365:
        findings.append("PASS_MAX_DAYS should be <= 365"); ok = False
    if values.get("PASS_MIN_DAYS", 0) < 1:
        findings.append("PASS_MIN_DAYS should be >= 1"); ok = False
    if values.get("PASS_WARN_AGE", 0) < 7:
        findings.append("PASS_WARN_AGE should be >= 7"); ok = False
    if minlen is not None and minlen < 12:
        findings.append("pwquality minlen should be >= 12"); ok = False
    return {"ok": ok, "evidence": {"login.defs": values, "pwquality.minlen": minlen}, "findings": findings}

def check_suid_sgid() -> Dict[str, Any]:
    # search common binary paths to reduce load
    paths = ["/bin","/usr/bin","/sbin","/usr/sbin"]
    findings = []
    for root in paths:
        if not os.path.isdir(root): 
            continue
        try:
            # use find for accuracy if available
            if shutil.which("find"):
                code, out, _ = run(["find", root, "-xdev", "-perm", "-4000", "-o", "-perm", "-2000", "-type", "f"])
                if code == 0 and out:
                    for line in out.splitlines():
                        findings.append(line.strip())
            else:
                # python fallback
                for dirpath, _, filenames in os.walk(root):
                    for f in filenames:
                        p = os.path.join(dirpath, f)
                        try:
                            st = os.lstat(p).st_mode
                            if (st & stat.S_ISUID) or (st & stat.S_ISGID):
                                findings.append(p)
                        except Exception:
                            pass
        except Exception:
            pass
    # Known safe SUID/SGID exist; we just report count here. Hardening would review and prune.
    ok = len(findings) <= 35  # heuristic threshold
    return {"ok": ok, "count": len(findings), "samples": findings[:15]}

def check_open_ports() -> Dict[str, Any]:
    cmd = which_first("ss","netstat")
    if not cmd:
        return {"ok": True, "evidence": "no ss/netstat found"}
    if os.path.basename(cmd) == "ss":
        code, out, _ = run(["ss","-tuln"])
    else:
        code, out, _ = run(["netstat","-tuln"])
    listeners = []
    if out:
        for line in out.splitlines():
            if any(proto in line for proto in ("tcp","udp")) and ("LISTEN" in line or "udp" in line):
                listeners.append(line.strip())
    # Heuristic: <=5 listeners often OK on servers
    ok = len(listeners) <= 10
    return {"ok": ok, "count": len(listeners), "samples": listeners[:15]}

def check_updates() -> Dict[str, Any]:
    # Debian/Ubuntu
    if which_first("apt"):
        code, out, err = run(["apt","list","--upgradeable"])
        lines = [l for l in out.splitlines() if l and "Listing..." not in l]
        return {"ok": len(lines) == 0, "upgradeable": len(lines), "evidence": "\n".join(lines[:20])}
    # RHEL/CentOS/Alma/Rocky
    if which_first("dnf"):
        code, out, err = run(["dnf","check-update"])
        # dnf check-update returns 100 if updates available, 0 if none
        ok = (code == 0)
        return {"ok": ok, "code": code, "evidence": (out or err)[:500]}
    if which_first("yum"):
        code, out, err = run(["yum","check-update"])
        ok = (code == 0)
        return {"ok": ok, "code": code, "evidence": (out or err)[:500]}
    return {"ok": True, "evidence": "no package manager detected"}

def check_auditd() -> Dict[str, Any]:
    ok_active = service_active("auditd")
    ok_enabled = service_enabled("auditd")
    return {"ok": ok_active, "active": ok_active, "enabled": ok_enabled}

def check_time_sync() -> Dict[str, Any]:
    candidates = ["systemd-timesyncd","chronyd","ntpd"]
    active_any = any(service_active(svc) for svc in candidates)
    return {"ok": active_any, "services": {svc: {"active": service_active(svc), "enabled": service_enabled(svc)} for svc in candidates}}

def check_fail2ban() -> Dict[str, Any]:
    active = service_active("fail2ban")
    enabled = service_enabled("fail2ban")
    return {"ok": active, "active": active, "enabled": enabled}

def check_selinux() -> Dict[str, Any]:
    getenforce = shutil.which("getenforce")
    if not getenforce:
        return {"ok": True, "evidence": "SELinux not available (likely Debian/Ubuntu)"}
    code, out, _ = run(["getenforce"])
    return {"ok": out.strip() in ("Enforcing","Permissive"), "mode": out.strip()}

# ----------------------------- scoring -----------------------------

WEIGHTS = {
    "firewall": 10,
    "ssh": 15,
    "file_perms": 10,
    "password_policy": 10,
    "suid_sgid": 8,
    "open_ports": 8,
    "updates": 8,
    "auditd": 8,
    "time_sync": 6,
    "fail2ban": 7,
    "selinux": 5,
}

def score(results: Dict[str, Any]) -> Dict[str, Any]:
    total = 0
    max_total = sum(WEIGHTS.values())
    breakdown = {}
    for key, weight in WEIGHTS.items():
        ok = results.get(key, {}).get("ok", False)
        pts = weight if ok else 0
        total += pts
        breakdown[key] = {"ok": ok, "points": pts, "weight": weight}
    percent = round(100 * total / max_total, 1) if max_total else 0.0
    return {"score": total, "max": max_total, "percent": percent, "breakdown": breakdown}

# ----------------------------- report -----------------------------

def generate_markdown(results: Dict[str, Any], out_path: str) -> None:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    s = score(results)
    lines = []
    lines.append(f"# Linux Hardening Audit Report")
    lines.append(f"_Generated: {now}_")
    lines.append("")
    lines.append(f"**Compliance Score:** {s['score']} / {s['max']}  ({s['percent']}%)")
    lines.append("")
    lines.append("## System")
    sysd = results.get("system", {}).get("details", {})
    lines.append(f"- Kernel/Distro: {sysd.get('distro','')} (kernel {sysd.get('release','')})")
    lines.append("")
    lines.append("## Summary")
    for k, b in s["breakdown"].items():
        status = "PASS" if b["ok"] else "FAIL"
        lines.append(f"- {k}: **{status}** ({b['points']}/{b['weight']})")
    lines.append("")
    lines.append("## Detailed Findings")
    def add_block(name, obj):
        lines.append(f"### {name}")
        if isinstance(obj, dict):
            for kk, vv in obj.items():
                if kk in ("ok",): 
                    continue
                lines.append(f"- **{kk}**: `{vv}`")
        else:
            lines.append(f"- {obj}")
        lines.append("")
    add_block("Firewall", results["firewall"])
    add_block("SSH Config", {"evidence": results["ssh"]["evidence"], "findings": results["ssh"]["findings"]})
    add_block("File Permissions", results["file_perms"])
    add_block("Password Policy", results["password_policy"])
    add_block("SUID/SGID", {"count": results["suid_sgid"]["count"], "samples": results["suid_sgid"]["samples"]})
    add_block("Open Ports", {"count": results["open_ports"].get("count"), "samples": results["open_ports"].get("samples")})
    add_block("Updates", results["updates"])
    add_block("auditd", results["auditd"])
    add_block("Time Sync", results["time_sync"])
    add_block("Fail2ban", results["fail2ban"])
    add_block("SELinux", results["selinux"])
    lines.append("---")
    lines.append("**Note:** This is a baseline audit. Always review findings in context of the system's role and security policy.")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ----------------------------- main -----------------------------

def run_all() -> Dict[str, Any]:
    results = {}
    results["system"] = detect_os()
    results["firewall"] = check_firewall()
    results["ssh"] = check_ssh_config()
    results["file_perms"] = check_file_permissions()
    results["password_policy"] = check_password_policy()
    results["suid_sgid"] = check_suid_sgid()
    results["open_ports"] = check_open_ports()
    results["updates"] = check_updates()
    results["auditd"] = check_auditd()
    results["time_sync"] = check_time_sync()
    results["fail2ban"] = check_fail2ban()
    results["selinux"] = check_selinux()
    results["score"] = score(results)
    return results

def main():
    ap = argparse.ArgumentParser(description="Linux Hardening Audit Tool")
    ap.add_argument("-o", "--output", default="linux_audit_report.md", help="Output markdown report path")
    ap.add_argument("--json", default=None, help="Optional JSON output path")
    args = ap.parse_args()
    results = run_all()
    generate_markdown(results, args.output)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
    print(f"[+] Report written to {args.output}")
    if args.json:
        print(f"[+] JSON written to {args.json}")
    print(f"[+] Compliance: {results['score']['percent']}%")

if __name__ == "__main__":
    main()
