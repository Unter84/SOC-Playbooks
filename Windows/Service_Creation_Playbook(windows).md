# 🛡️ Playbook: Service Creation Alert (Windows)

## Why it Matters
Attackers often create new Windows services to **maintain persistence** or **run malware** automatically after reboot.  
Legit admins also create services (for monitoring agents, backup tools, etc.), so analysts must carefully validate.

---

## Step-by-Step Analyst Actions

### 🔹 L1 Analyst
1. **Validate the alert source**  
   - Check event ID (Windows **7045: "A new service was installed in the system"**).  
   - Confirm hostname, timestamp, service name, binary path.  

2. **Check context**  
   - Is the service name suspicious/random? (e.g., `xysvc`, `Updater123`).  
   - Binary path: Normal = `C:\Windows\System32\`  
     Suspicious = `C:\Users\Public\`, `%TEMP%`, `Downloads`.  

3. **Correlate with user activity**  
   - Which account created the service?  
   - Was it **Admin/SYSTEM** (expected) or a normal user (suspicious)?  

4. **Escalation decision**  
   - If service looks **legit** (AV agent, backup, patch service) → document & close.  
   - If **unclear/suspicious** → escalate to L2 with evidence.  

---

### 🔹 L2 Analyst
1. **Deep log review**  
   - Review Sysmon logs (**Event ID 7045, Sysmon 6: Service Creation**).  
   - Check **binary hash** → scan in VirusTotal / sandbox.  
   - Check **process ancestry** → was it created by `sc.exe`, `powershell.exe`, a script?  

2. **Check timeline**  
   - Normal hours vs. unusual (e.g., 2 AM).  
   - Failed logins before service creation?  

3. **Threat intel check**  
   - Compare service/binary name with threat reports.  
   - Look for IOCs (file hashes, domains, IPs).  

4. **Action**  
   - If confirmed **malicious** → disable service, quarantine binary, escalate to L3.  
   - If **benign but undocumented** → confirm with system owner, document exception.  

---

### 🔹 L3 Analyst
1. **Root cause analysis**  
   - Was the service creation attacker persistence?  
   - Map to MITRE ATT&CK:  
     - **T1543.003 – Create or Modify System Process: Windows Service**  
   - Check for **lateral movement** (same account used elsewhere?).  

2. **Containment & remediation**  
   - Disable compromised accounts.  
   - Remove malicious binary + service.  
   - Patch exploited vulnerabilities.  

3. **Preventive actions**  
   - Improve detection for suspicious service creation.  
   - Restrict service creation rights (admins only).  
   - Deploy EDR/SIEM rules for abnormal paths.  

---

## 📝 Root Cause Analysis (RCA) – Example

**Alert:** New service created on host `WIN-SERVER01`  
**Event:** Windows Event 7045 – Service Name `UpdaterSvc`  
**Binary Path:** `C:\Users\Public\updater.exe`  
**Account Used:** `DOMAIN\UserA`  

**Investigation Findings:**
- Binary hash flagged as **Cobalt Strike beacon**.  
- Service created via `sc.exe` from a **remote PowerShell session**.  
- `UserA` account compromised via phishing (confirmed in O365 logs).  

**Root Cause:**  
Attacker stole `UserA`’s credentials and used PowerShell remoting to create a **malicious Windows service** for persistence.  

**Impact:**  
- Persistence on one server.  
- No lateral spread confirmed.  

**Corrective Actions:**  
- Disabled & removed malicious service.  
- Reset compromised account.  
- Enabled **MFA for all admins**.  
- Added SIEM detection → alert if service created outside standard IT tool list.  

---

## ✅ Summary
- **L1**: Validate & escalate suspicious service creation.  
- **L2**: Investigate logs, binaries, intel.  
- **L3**: Confirm persistence, remediate, prevent recurrence.  

> 📌 This playbook can be stored in your SOC runbook repository for quick reference.
