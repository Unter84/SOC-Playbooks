*This playbook provides triage, investigation, and response guidance for “Shadow Volume Created” alerts. It includes SPL queries for Sysmon and Windows logs, correlation with backup activity, MITRE ATT\&CK mapping, and recommendations for containment and prevention.*

# 🛡️ Playbook: Shadow Volume Created (Windows VSS)

**Filename:** `playbook-shadow-volume-created.md`  
**Category:** Windows / Ransomware Detection  
**Use Case:** Investigating alerts when Volume Shadow Copies are created on Windows endpoints.

---

## 🎯 Alert Context — Why this matters
Volume Shadow Copy Service (VSS) is used legitimately for **backups and system restore**, but attackers abuse it to:  
- Prepare to **delete shadow copies** (so victims cannot restore after ransomware).  
- Create hidden copies for **data exfiltration or persistence**.  

⚠️ Suspicious creation of shadow volumes outside normal backup schedules may indicate **malware activity, credential abuse, or ransomware staging**.

**Relevant Detection Sources**
- Windows Security logs  
- Sysmon (Event ID 1 – process creation)  
- EDR telemetry (Defender, CrowdStrike, SentinelOne, etc.)  
- Backup software logs (to confirm scheduled activity)  

---

## 🧭 Analyst Actions (L1 → L2 → L3)

### L1 — Initial Triage
- ✅ Identify the **host** and **user** that created the shadow copy.  
- ✅ Extract the **process command line** used (common: `vssadmin.exe create shadow /for=C:`).  
- ✅ Check whether this action aligns with a **scheduled backup** or **IT operation**.  
- 🚩 Escalate to L2 if:
  - Process initiated by **non-backup application** (cmd, PowerShell, malware).  
  - Host is **server with critical data**.  
  - Event occurred **outside backup window**.

**SPL — Detect shadow volume creation (Sysmon/Windows):**
```spl
index=sysmon EventCode=1
| search Image="*vssadmin.exe" OR Image="*wmic.exe" OR Image="*powershell.exe"
| search CommandLine="*create shadow*"
| table _time host user Image CommandLine ParentImage
````

---

### L2 — Deep Investigation & Correlation

**1. Process Lineage**

* Review parent/child processes (was it launched by `cmd.exe`, `powershell.exe`, or backup agent?).
* Look for suspicious PowerShell modules: `Get-WmiObject Win32_ShadowCopy`, `Invoke-WmiMethod`.

```spl
index=sysmon EventCode=1
| search CommandLine="*shadow*"
| table _time host user Image CommandLine ParentImage ParentCommandLine
```

**2. Windows Security Events**

* Event ID 4688 → process creation (with command line if logging enabled).
* Event ID 4670/4663 → access to system files (check if unusual accounts accessed VSS volumes).

**3. EDR Telemetry**

* Check if security tools flagged the same process as malicious (tamper protection events).
* Hunt for ransomware precursors: file encryption, registry changes, mass file modifications.

**4. Backup Logs**

* Correlate with legitimate backup job schedule (e.g., Veeam, Windows Backup, Commvault).

**5. Firewall / Network Logs**

* Look for outbound connections from same host to suspicious IPs (may signal data exfiltration).

**6. Threat Intelligence**

* Cross-check hash of executable (if custom binary executed shadow creation).

---

### L3 — Confirm & Respond

**If Confirmed Malicious:**

* 🛑 Contain

  * Isolate host from network.
  * Suspend/disable user account that initiated process.
  * Preserve forensic evidence (command line, Sysmon logs, memory).
* 🔎 Eradicate

  * Kill rogue process.
  * Remove persistence mechanisms.
* 🔁 Recover

  * Restore host from clean image if ransomware infection confirmed.
  * Validate backup integrity.

**If Legitimate:**

* ✅ Document backup vendor/tool used.
* ✅ Add exception for legitimate scheduled tasks.
* ✅ Update detection rules to ignore known backup service accounts.

---

## 🧩 MITRE ATT\&CK Mapping

* **T1490 – Inhibit System Recovery** (manipulating shadow copies).
* **T1059 – Command and Scripting Interpreter** (cmd.exe, PowerShell usage).
* **T1569.002 – System Services: Service Execution** (WMI, vssadmin).
* **T1070.004 – Indicator Removal: File Deletion** (if followed by deletion of shadows).

---

## 📝 Root Cause Analysis (RCA) Template

**1) Executive Summary**

* *What happened:* Shadow volume created on host `<X>` by `<process/user>`
* *Impact:* Possible ransomware staging / backup operation
* *Disposition:* `<True Positive / False Positive>`

**2) Timeline**

* T0: Alert generated
* T1: Shadow copy command executed
* T2: Correlation with backup schedule or suspicious process
* T3: Containment/remediation steps taken

**3) Root Cause**

* `[Malware / Ransomware staging | IT backup job | User misconfiguration]`

**4) Scope**

* Number of hosts affected
* Users/processes involved

**5) Actions Taken**

* Containment, eradication, recovery

**6) Preventive Measures**

* Restrict `vssadmin.exe` execution
* Monitor PowerShell/WMI for shadow copy creation
* Harden EDR policies

**7) Lessons Learned**

* Need for improved backup validation or process monitoring

---

## 🛡 Recommendations

* **Immediate**

  * Alert on shadow copy creation outside backup schedule.
  * Block `vssadmin.exe` for non-admin users.
  * Ensure EDR monitors PowerShell/WMI commands.

* **Hardening**

  * Restrict VSS operations to backup service accounts only.
  * Monitor Event IDs: 4688, 4670, Sysmon 1/22.
  * Apply application whitelisting (AppLocker, WDAC).

* **Monitoring**

  * SPL alerts for shadow creation via unusual parent processes.
  * Detect sequence: *create shadow → delete shadows → mass file modification*.

* **Process**

  * Ensure SOC validates backup job times with IT teams.
  * Update playbooks to escalate suspicious shadow copy events as potential ransomware.

---

## 📎 Before Escalating to Customer

Include:

* Hostname, user, time of shadow copy creation
* Process lineage (`ParentImage`, `CommandLine`)
* Backup logs (legitimate vs none)
* EDR verdicts (malware flagged or clean)
* Correlated network activity (if exfil suspected)
* Analyst recommendation (block, isolate, allow)



