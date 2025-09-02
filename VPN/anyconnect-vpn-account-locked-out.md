# 🛡️ Playbook: AnyConnect VPN Account Locked Out

**Filename:** `playbook-anyconnect-vpn-account-locked-out.md`  
**Category:** VPN / Remote Access Security  
**Use Case:** Detecting and investigating user account lockouts during Cisco AnyConnect VPN authentication attempts.

---

## 🎯 Alert Context — Why this matters
VPN account lockouts can indicate:
- **Brute force / password spray** attempts targeting remote access  
- **Compromised accounts** being probed by attackers  
- **Misconfigured clients** (stale credentials cached in AnyConnect)  
- **User error** (wrong/expired password, multiple devices with old credentials)  

Since VPN provides a **direct pathway into internal infrastructure**, correlating with other security controls is critical to distinguish between benign misconfigurations and malicious activity.

**Relevant Events:**
- **Cisco ASA/FTD/AnyConnect logs** → failed logins, lockouts  
- **Windows AD logs** → 4740 (account locked out), 4625 (failed logon)  
- **IdP logs (Duo, Okta, Entra ID)** → failed authentications, MFA denials  

---

## 🧭 Analyst Actions (L1 → L2 → L3)

### L1 — Initial Triage
- ✅ Identify the user/account locked out  
- ✅ Extract IP, device type, and geolocation from VPN logs  
- ✅ Correlate with AD 4740 event (account lockout confirmation)  
- ✅ Check business context: is the user traveling, working offsite, or on leave?  
- 🚩 Escalate to L2 if:
  - Multiple lockouts in short time  
  - Privileged account affected  
  - Multiple source IPs involved  
  - IP reputation shows TOR/VPN hosting/blacklisted ASN  

---

### L2 — Deep Investigation & Correlation
**Correlate across multiple log sources:**

1. **Firewall Logs (Cisco ASA/FTD, Palo Alto, Fortinet)**  
   - Look for **connection attempts** from the same source IP(s)  
   - Identify **blocked vs allowed traffic** immediately before/after lockouts  
   - Look for port scans or anomalous traffic (e.g., to SSH/RDP ports) from the same IP  

2. **Endpoint Detection & Response (EDR/XDR)**  
   - On user endpoint: failed VPN client authentications in local logs  
   - Post-lockout: signs of credential theft, malware, keyloggers  
   - On critical servers: failed logons or service account usage from same source  

3. **Windows Active Directory / Domain Controller Logs**  
   - 4740 (account locked out) confirms identity store triggered the lockout  
   - 4625 (failed logons) → review failure reasons (bad password vs expired)  
   - 4768/4769 (Kerberos ticket requests) → repeated failures could indicate brute force  

4. **Identity Provider (IdP / MFA) Logs**  
   - Entra ID, Okta, Duo, Ping  
   - Failed MFA or repeated MFA prompts from unusual IP/device  
   - Impossible travel alerts  

5. **Web Application / Web Server Logs**  
   - Look for **login attempts to OWA, Citrix, or SSO portals** from same IP range  
   - Correlate timestamps to confirm if attacker is probing **multiple entry points**  

6. **Threat Intelligence Sources**  
   - IP/ASN reputation (known brute force campaigns, TOR exit nodes)  
   - Darknet chatter (if integrated with TIP)  

---

### L3 — Confirm & Respond
**If malicious:**
- 🛑 Contain  
  - Block source IPs/subnets at VPN gateway and firewall  
  - Reset and lock account until user identity is verified  
  - Force password reset and MFA re-registration  
  - Check for **other accounts targeted** from same IPs  
- 🔎 Eradicate & Harden  
  - Review AD logs for **spray attempts across users**  
  - Hunt for **indicators of compromise** on user’s endpoint  
- 🔁 Recover  
  - Restore account access with verified credentials  
  - Monitor for repeat attempts after containment  

**If benign:**
- ✅ Document misconfiguration or expired credentials  
- ✅ Educate user (avoid saving credentials, update cached passwords)  
- ✅ Tune monitoring to reduce noise (but don’t suppress globally)  

---

## 🧩 MITRE ATT&CK Mapping
- **T1110 – Brute Force** (Password Guessing / Password Spraying)  
- **T1078 – Valid Accounts** (use of stolen credentials)  
- **T1078.004 – Valid Accounts: Cloud Accounts** (if IdP integrated)  
- **T1133 – External Remote Services** (VPN exploitation)  

---

## 📝 Root Cause Analysis (RCA) Template

**1) Executive Summary**  
- *What happened:* Account `<X>` was locked out during VPN login attempts  
- *Impact:* `<Potential brute force attack | User disruption>`  
- *Disposition:* `<True Positive / False Positive / Benign>`  

**2) Timeline**  
- T0: VPN lockout detected  
- T1: Correlated firewall/IdP/AD logs  
- T2: User/business validation  
- T3: Containment actions taken  
- T4: Recovery  

**3) Root Cause**  
- `[Brute force | Password spray | Expired credentials | Cached credentials | User error]`  

**4) Scope**  
- Accounts impacted, IP ranges, other services targeted  

**5) Actions Taken**  
- Containment, eradication, recovery steps  

**6) Preventive Measures**  
- Harden VPN auth, enable MFA, enforce lockout policies  

**7) Lessons Learned**  
- Monitoring gaps, tuning, user awareness needs  

---

## 🛡 Recommendations

- **Immediate Containment**
  - Block malicious IPs at VPN/firewall  
  - Reset affected accounts, revoke active sessions  
  - Force MFA re-enrollment  

- **Hardening**
  - Enforce MFA on all VPN access  
  - Adaptive authentication (risk/geo-based)  
  - Strong password policies + lockout thresholds  
  - Restrict VPN to trusted IPs (geo-blocking if possible)  

- **Monitoring**
  - Correlate lockouts with firewall logs (brute force attempts)  
  - Alert on multiple account lockouts from same IP range  
  - Watch for “low-and-slow” password spray across accounts  
  - Monitor SSO/OWA/web apps for same IP activity  

- **Process**
  - User awareness training (VPN credential hygiene)  
  - Document recurring misconfigs to avoid false positives  

---

## 📎 Before Escalating to Customer

Include:
- VPN gateway logs (failed attempts, IPs, device type)  
- AD event 4740 confirmation  
- Firewall events from same IPs (scans, failed access attempts)  
- IdP/MFA logs (MFA failures, impossible travel)  
- Web server/app logs if attacker probed multiple portals  
- Threat intel reputation check for IPs  
- Business/user validation (legit user error vs attack)  
- Analyst recommendation (contain/block vs benign 
