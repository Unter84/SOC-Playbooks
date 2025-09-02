# 🛡️ Playbook: Distributed Denial of Service (DDoS) Alert

**Filename:** `ddos-alert.md`  
**Category:** Network / Threat Detection  
**Use Case:** Investigating DDoS alerts raised in Splunk from firewall, WAF, IDS/IPS, or other telemetry.

---

## 🎯 Alert Context — Why this matters
A Distributed Denial of Service (DDoS) attack aims to **overwhelm network, server, or application resources** to cause service disruption.  
Impact can include:
- Service outage (critical applications/websites unavailable)  
- Performance degradation (slow responses)  
- Diversionary tactic to mask other intrusions  

**Relevant Detection Sources**
- Firewall logs (high connection rates, SYN floods, UDP floods)  
- WAF logs (HTTP floods, malformed requests)  
- IDS/IPS (Snort/Suricata signatures for DDoS)  
- NetFlow/sFlow telemetry (spikes in PPS/bandwidth)  
- Endpoint/server logs (resource exhaustion, service unavailability)  
- Application logs (HTTP 5xx spikes, error bursts)

---

## 🧭 Analyst Actions (L1 → L2 → L3)

## L1 — Initial Triage
- ✅ Confirm the **target system** (IP, hostname, service)  
- ✅ Identify **attack vector** (SYN flood, UDP flood, HTTP flood, DNS amplification)  
- ✅ Check time range and scale (spike duration, PPS, bandwidth)  
- ✅ Look for **single vs multiple sources** (is it distributed?)  
- 🚩 Escalate to L2 if:
  - Multiple source IPs  
  - Traffic spike beyond normal baseline  
  - Critical/public-facing service impacted  

**SPL — Detect sudden spike in traffic (firewall logs):**
```
index=firewall action=allowed OR action=blocked
| bin _time span=1m
| stats count as conn by _time dest_ip
| eventstats avg(conn) as baseline, stdev(conn) as deviation by dest_ip
| eval threshold=baseline+(deviation*5)
| where conn > threshold
| table _time dest_ip conn baseline deviation
```

⸻
## L2 — Deep Investigation & Correlation

1. Firewall / IDS Logs
	•	Look for high-volume connections from single or multiple IPs
	•	Check if packets are incomplete (SYN without ACK)
```spl
index=firewall OR index=ids
| stats count by src_ip dest_ip dest_port protocol
| where count > 1000
```
2. Web Application Firewall (WAF)
	•	HTTP floods: excessive GET/POST requests to same URI
	•	Look for abnormal user-agents or missing headers
```
index=waf
| stats count by src_ip http_user_agent cs_uri_stem
| where count > 500
```
3. NetFlow / Network Telemetry
	•	PPS/throughput anomalies on targeted interface
```
index=netflow
| bin _time span=1m
| stats sum(bytes) as total_bytes sum(packets) as total_packets by _time dest_ip
| eventstats avg(total_packets) as baseline stdev(total_packets) as deviation
| where total_packets > baseline + (deviation*5)
```
4. Endpoint / Server Logs
	•	Resource exhaustion signs: service restarts, kernel TCP backlog full
	•	Windows: Event ID 2022 (server unable to accept connections)
	•	Linux: /var/log/messages showing socket drops

5. Application Logs
	•	HTTP 503/504/500 errors surging
	•	Correlate with WAF spikes
```
index=web sourcetype=iis OR sourcetype=apache
| stats count by sc_status dest_ip
| where sc_status IN ("500","503","504")
```

⸻

## L3 — Confirm & Respond

If Confirmed DDoS:
	•	🛑 Contain
	•	Engage ISP/Upstream provider for rate limiting or blackholing
	•	Enable DDoS protection (Cloudflare, Akamai, Azure/AWS Shield, Arbor)
	•	Apply ACLs/firewall rules to drop attack traffic
	•	🔎 Eradicate
	•	Identify malicious IP ranges, block at perimeter
	•	Ensure no secondary intrusion during distraction
	•	🔁 Recover
	•	Monitor service availability post-mitigation
	•	Tune Splunk thresholds to reduce false positives

If False Positive:
	•	✅ Document unusual but legitimate traffic (marketing campaign, vulnerability scan, load testing)
	•	✅ Add exception rules for expected traffic

⸻

🧩 MITRE ATT&CK Mapping
	•	T1498 – Network Denial of Service
	•	T1499 – Endpoint Denial of Service
	•	T1498.001 – Direct Network Flood
	•	T1498.002 – Reflection/Amplification

⸻

📝 Root Cause Analysis (RCA) Template

1) Executive Summary
	•	What happened: DDoS alert against service <X>
	•	Impact: <Service outage / performance degradation>
	•	Disposition: <True Positive / False Positive>

2) Timeline
	•	T0: Alert triggered in Splunk
	•	T1: Firewall/NetFlow spike detected
	•	T2: Service disruption observed
	•	T3: Mitigation applied (ISP block, WAF, ACLs)
	•	T4: Recovery

3) Root Cause
	•	Category: [SYN flood | UDP flood | HTTP flood | DNS amplification | False alarm]

4) Scope
	•	Services impacted, number of IPs, bandwidth consumed

5) Actions Taken
	•	Containment, eradication, recovery

6) Preventive Measures
	•	DDoS protection, rate limiting, monitoring improvements

7) Lessons Learned
	•	Gaps in thresholds, need for automated mitigation

⸻

🛡 Recommendations
	Immediate
	•	Block/blackhole malicious IP ranges
	•	Engage ISP or DDoS mitigation provider
	•	Isolate targeted systems if needed
	Hardening
	•	Deploy DDoS protection services (Cloudflare, Akamai, Arbor, AWS/Azure Shield)
	•	Implement rate limiting (firewall, WAF, reverse proxy)
	•	Geo-blocking for unused regions
	Monitoring
	•	Build anomaly detection on PPS/connection baselines
	•	Detect sudden spikes in error logs (500/503)
	•	Alert on high SYN vs ACK ratios
	Process
	•	Establish escalation to ISP/vendor SOC
	•	Document expected baselines for critical services

⸻

📎 Before Escalating to Customer

Include:
	•	Traffic spike details (PPS, bandwidth, duration)
	•	Firewall/WAF/IDS evidence with top talkers (IPs, ports)
	•	Service impact (downtime, latency, 5xx error surge)
	•	TI validation (IPs linked to known botnets, reflection/amplification sources)
	•	Containment steps applied (ACLs, DDoS protection, ISP engagement)
	•	Recommended next steps

⸻
