# 🛡️ Playbook: Communication to Malicious Domain

**Filename:** `playbook-communication-to-malicious-domain.md`  
**Category:** Network / Threat Intel Detection  
**Use Case:** Investigating alerts triggered when an internal host attempts communication with a known or suspected malicious domain (per threat intel feed, sandbox verdict, or security control blocklist).

---

## 🎯 Alert Context — Why this matters
Outbound connections to known malicious domains may indicate:
- Malware C2 (command & control) beaconing
- Data exfiltration attempts
- Phishing email payload callbacks
- Drive-by download follow-ups
- Legitimate apps connecting to compromised CDN/hosting provider (false positive risk)

**Relevant Detection Sources**
- Firewall / Proxy logs (e.g., Palo Alto, Bluecoat, Cisco ASA/FTD)
- DNS logs (Windows DNS, Infoblox, Bind, cloud resolvers)
- Endpoint telemetry (Sysmon DNS events, EDR network events)
- Threat intel feeds (MISP, OTX, vendor feeds)
- Web/application logs (reverse proxy, WAF, IIS, Apache)

---

## 🧭 Analyst Actions (L1 → L2 → L3)

### L1 — Initial Triage
- ✅ Identify the **internal source** (hostname, IP, user)
- ✅ Verify the **malicious domain** from alert (cross-check with multiple TI feeds)
- ✅ Check if alert came from **DNS query** or **direct HTTP/HTTPS request**
- ✅ Correlate with email logs (was this domain linked in recent phishing emails?)
- 🚩 Escalate to L2 if:
  - Critical host or privileged user involved
  - Domain is confirmed C2/active IOC
  - Repeated communications observed

**SPL — Quick triage (firewall logs):**
```spl
index=firewall sourcetype="pan:traffic"
| search dest_domain="malicious.com"
| table _time src_ip src_user dest_domain dest_ip app action rule_name


⸻

L2 — Deep Investigation & Correlation

1. DNS Logs
	•	Look for all queries to the domain across the environment
	•	Check if query resolved successfully & what IP was returned

index=dns
| search query="malicious.com"
| stats count values(answer) as ResolvedIPs by src_ip src_user

2. Firewall / Proxy Logs
	•	Review all outbound connections to the resolved IPs
	•	Identify if traffic was allowed or blocked
	•	Check for patterns of beaconing (regular intervals, small packets)

index=firewall
| search dest_ip IN([subsearch: index=dns query="malicious.com" | stats values(answer) as ResolvedIPs | mvexpand ResolvedIPs | return $ResolvedIPs])
| timechart count by src_ip span=5m

3. Endpoint (EDR / Sysmon)
	•	Sysmon Event ID 22 (DNS query), Event ID 3 (Network connection)
	•	Look for processes making DNS queries or outbound connections

index=sysmon EventCode=22 QueryName="malicious.com"
| table _time host ProcessId ProcessName QueryName QueryResults

index=sysmon EventCode=3 dest_ip=<IOC_IP>
| table _time host ProcessName dest_ip dest_port Protocol

4. Email Logs
	•	Check if domain appeared in EmailURLInfo or EmailAttachmentInfo (Microsoft Defender/O365)

index=o365 sourcetype=EmailUrlInfo
| search Url="*malicious.com*"
| table _time SenderRecipientSubject Url

5. Web Server / WAF Logs
	•	If the domain is tied to your web apps (callback injection), check WAF/IIS/Apache logs for inbound/outbound references

index=web sourcetype=iis
| search cs_host="malicious.com"
| table _time c_ip cs_username cs_host cs_uri_stem sc_status

6. Threat Intel Validation
	•	Cross-check the domain/IP in TI sources (MISP, VirusTotal, OTX, etc.)
	•	Confirm if it’s still active and reputation score

⸻

L3 — Confirm & Respond

If Malicious (True Positive):
	•	🛑 Contain
	•	Block domain/IP at firewall, proxy, DNS sinkhole
	•	Isolate affected endpoint(s)
	•	🔎 Eradicate
	•	Collect memory/image of endpoint
	•	Investigate parent process (possible malware infection)
	•	🔁 Recover
	•	Reimage/clean endpoint, restore connectivity
	•	Monitor for re-attempts to other domains/IPs in same campaign

If Benign (False Positive):
	•	✅ Document why it’s benign (e.g., security vendor sandbox, misclassified CDN)
	•	✅ Add to allowlist (if confirmed safe)
	•	✅ Tune rule to reduce noise

⸻

🧩 MITRE ATT&CK Mapping
	•	T1071 – Application Layer Protocol (malware using HTTP/HTTPS for C2)
	•	T1071.004 – DNS (C2 via DNS tunneling/queries)
	•	T1095 – Non-Application Layer Protocol (raw TCP/UDP callbacks)
	•	T1041 – Exfiltration over C2 Channel
	•	T1568 – Dynamic Resolution (malware using DGA or domain rotation)

⸻

📝 Root Cause Analysis (RCA) Template

1) Executive Summary
	•	What happened: Host <X> communicated with malicious domain <Y>
	•	Impact: Potential malware infection / data exfiltration attempt
	•	Disposition: <True Positive / False Positive>

2) Timeline
	•	Detection alert
	•	DNS query observed
	•	Outbound connection attempts
	•	Endpoint behavior (process, user activity)
	•	Containment & recovery

3) Root Cause
	•	Category: [Phishing payload | Malware infection | User browsing | TI misclassification]

4) Scope
	•	Number of hosts/accounts affected
	•	Any lateral movement or spread

5) Actions Taken
	•	Containment, eradication, recovery

6) Preventive Measures
	•	DNS sinkholing, EDR rules, proxy blocking, user awareness

7) Lessons Learned
	•	Gaps in TI ingestion, detection rules, endpoint visibility

⸻

🛡 Recommendations
	•	Immediate
	•	Block malicious domain/IPs across DNS, firewall, proxy
	•	Isolate affected hosts for forensic review
	•	Hardening
	•	Enforce egress filtering (only allow necessary ports/domains)
	•	Enable DNS logging & forwarding to SIEM
	•	Use TI feeds with we automated updates
	•	Monitoring
	•	Alert on repeated DNS queries after block (possible beaconing)
	•	Detect abnormal outbound traffic (beacon intervals, low-volume C2)
	•	Correlate with phishing campaigns in Email logs
	•	Process
	•	User awareness campaigns on phishing links
	•	Ensure incident playbooks reference cross-log correlation

⸻

📎 Before Escalating to Customer

Include:
	•	DNS queries & resolution results
	•	Firewall/proxy logs (allowed vs blocked)
	•	Endpoint telemetry (process making connection)
	•	Email/Web logs showing origin vector
	•	TI validation details (feed used, IOC context)
	•	Impact analysis (what host, what data at risk)
	•	Analyst recommendation (containment steps, preventive actions)

