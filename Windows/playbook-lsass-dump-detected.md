# 🛡️ Playbook: LSASS Dump Detected

**Filename:** `playbook-lsass-dump-detected.md`  
**Category:** Endpoint / Credential Access  
**Use Case:** Investigating alerts triggered when LSASS (Local Security Authority Subsystem Service) memory is accessed or dumped.

---

## 🎯 Alert Context — Why this matters
- **LSASS** (lsass.exe) stores Windows authentication secrets (NTLM hashes, Kerberos tickets, plaintext creds in some cases).  
- Attackers dump LSASS memory to steal credentials for **lateral movement, persistence, or domain compromise**.  
- Common tools: `procdump.exe`, `taskmgr.exe`, `comsvcs.dll`, Mimikatz, Cobalt Strike, custom malware.  
- **Risk:** If successful, an attacker can impersonate admins and escalate domain-wide.  

⚠️ Any LSASS dump alert should be treated as **critical severity**.

**Relevant Detection Sources**
- Sysmon Event ID 10 (ProcessAccess) targeting `lsass.exe`  
- Sysmon Event ID 1 (ProcessCreate) with suspicious dump tools  
- EDR/XDR alerts (“credential theft”, “memory dump”)  
- Windows Security logs (Event ID 4688, 4670)  
- Memory protection logs (Windows Defender, AV)  

---

## 🧭 Analyst Actions (L1 → L2 → L3)

### L1 — Initial Triage
- ✅ Review alert details: host, user, process, timestamp.  
- ✅ Confirm which process tried to access LSASS:
  - Legitimate (AV/EDR agent, backup software)?  
  - Suspicious (Mimikatz, procdump, custom binary)?  
- ✅ Check if the process is **signed, from valid path**.  
- 🚩 Escalate to L2 if:
  - Process is unsigned, suspicious path (AppData, Temp).  
  - Known dumping tools used.  
  - Elevated or SYSTEM account involved.  

**SPL — Detect processes accessing LSASS**
```spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| table _time host User SourceImage SourceProcessId TargetImage GrantedAccess CallTrace
| sort 0 _time


⸻

L2 — Deep Investigation

1. Process Lineage
	•	Trace parent and child processes for the dumping tool.

index=sysmon EventCode=1 host=<HOST> ProcessId=<SourceProcessId>
| table _time Image CommandLine ParentImage ParentCommandLine User

2. Binary Validation
	•	Extract file hash and check with VirusTotal / internal TI.
	•	Confirm digital signature status.

index=sysmon EventCode=1 Image="<SourceImage>"
| stats values(SHA256) as hash values(Company) as vendor values(Signed) as signed by Image

3. Logon Context
	•	Correlate with logon events (4624/4672) to see which account was active.

index=wineventlog (EventCode=4624 OR EventCode=4672) host=<HOST>
| search LogonId=<LogonId_from_Sysmon>
| table _time TargetUserName IpAddress LogonType AuthenticationPackageName

4. Other Credential Access Attempts
	•	Check for registry hive access (SAM, SYSTEM, SECURITY).
	•	Sysmon Event ID 11 (file creation of suspicious dump files, e.g., .dmp).

index=sysmon EventCode=11 host=<HOST>
| search TargetFilename="*.dmp"
| table _time host TargetFilename Image User

5. Network Activity
	•	Did the dumping tool beacon out?

index=sysmon EventCode=3 ProcessId=<SourceProcessId>
| table _time dest_ip dest_port ProcessName


⸻

L2 — Lateral Movement Investigation

Because LSASS dumps often precede lateral spread, check for:

A) Abnormal Logons After Dump
	•	Successful logons (4624) from dumped account creds.

index=wineventlog EventCode=4624 host!=<ORIGINAL_HOST>
| search AccountName=<SuspectedAccount>
| table _time host AccountName LogonType IpAddress AuthenticationPackageName

B) Remote Execution Tools
	•	psexec.exe, wmic.exe, schtasks.exe, RDP (3389), SMB (445).

index=sysmon EventCode=1 host=<ORIGINAL_HOST>
| search Image IN ("*psexec.exe","*wmic.exe","*schtasks.exe","*mstsc.exe")
| table _time host User Image CommandLine ParentImage

C) Kerberos/NTLM Abuse
	•	Unusual 4769 (Kerberos tickets) or 4624 LogonType=3 with NTLM.

⸻

L3 — Confirm & Respond

If Malicious (True Positive):
	•	🛑 Contain
	•	Isolate the host.
	•	Suspend/kill the dumping process.
	•	🔎 Eradicate
	•	Collect memory/image for forensic analysis.
	•	Remove persistence.
	•	🔁 Recover
	•	Reset credentials for accounts that logged into the host.
	•	Reimage host if SYSTEM compromise confirmed.

If Benign (False Positive):
	•	✅ Some security products (AV/EDR) legitimately query LSASS.
	•	✅ Verify vendor documentation.
	•	✅ Add to allowlist if confirmed benign.

⸻

🧩 MITRE ATT&CK Mapping
	•	T1003.001 – OS Credential Dumping: LSASS Memory
	•	T1055 – Process Injection (if injected into LSASS)
	•	T1547 – Boot or Logon Autostart Execution (if persistence observed)
	•	T1021 – Remote Services (if stolen creds used for lateral movement)

⸻

📝 Root Cause Analysis (RCA) Template

1) Executive Summary
	•	What happened: LSASS dump attempt detected on host <X> by process <Y>.
	•	Impact: <Credentials potentially exposed>
	•	Disposition: <True Positive | False Positive>

2) Timeline
	•	T0: LSASS dump alert triggered.
	•	T1: Source process lineage and hash verified.
	•	T2: User/logon session reviewed.
	•	T3: Containment/remediation actions taken.

3) Root Cause
	•	[Malware tool | Penetration test | AV agent | Admin action]

4) Scope
	•	Hosts affected, accounts exposed, lateral movement indicators.

5) Actions Taken
	•	Containment, eradication, recovery.

6) Preventive Measures
	•	Enable LSASS protection (RunAsPPL).
	•	Enforce credential guard.
	•	Restrict admin accounts.

7) Lessons Learned
	•	Improve LSASS dump detection fidelity.
	•	Enhance log correlation to lateral activity.

⸻

🛡 Recommendations
	•	Immediate
	•	Isolate host.
	•	Reset credentials cached on system.
	•	Block known dumping tools (e.g., procdump, mimikatz).
	•	Hardening
	•	Enable LSASS protection (RunAsPPL).
	•	Deploy Windows Defender Credential Guard.
	•	Restrict access to lsass.exe to only SYSTEM and protected processes.
	•	Monitor for unsigned binaries in sensitive directories.
	•	Monitoring
	•	Correlate Event ID 10 (LSASS access) + Event ID 11 (dump file creation).
	•	Detect known dump tool names (procdump.exe, lsass.dmp).
	•	Alert on abnormal remote logons after LSASS dump attempts.
	•	Process
	•	Maintain allowlist for known security software accessing LSASS.
	•	Escalate all other cases as critical.

⸻

📎 Before Escalating to Customer

Include:
	•	Hostname, username, timestamp.
	•	Source process details (path, hash, signature).
	•	Dump method used (ProcessAccess, procdump, comsvcs.dll).
	•	Any .dmp files created.
	•	Lateral movement evidence after dump.
	•	TI results for involved binaries.
	•	Analyst recommendation (containment, remediation, preventive actions).

