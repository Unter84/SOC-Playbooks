````markdown
# 🛡️ Playbook: Brute Force Attack (Multiple Failed Logins)

**Filename:** `playbook-brute-force-attack.md`  
**Category:** Authentication / Threat Detection  
**Use Case:** Investigating brute force login attempts observed in Splunk from Active Directory, VPN, Linux, application, or cloud identity logs.

---

## 🎯 Alert Context — Why this matters
A brute force attack is when an adversary attempts **multiple login attempts** in rapid succession to guess valid credentials.  
- Can lead to **account compromise** if successful.  
- Common on external-facing systems (VPN, OWA, SSH, RDP, web apps).  
- May also appear as **password spray** (one password across many users).  

**Relevant Detection Sources**
- Windows AD security logs (Event IDs 4625 – failed logon, 4740 – account lockout, 4624 – successful logon)  
- VPN logs (AnyConnect, Palo Alto GlobalProtect, Fortinet SSL VPN)  
- Linux logs (`/var/log/secure`, `/var/log/auth.log`)  
- Firewall logs (blocked authentication attempts)  
- Identity provider logs (Okta, Entra ID, Duo)  
- Application/web server logs (failed login attempts via HTTP POSTs)

---

## 🧭 Analyst Actions (L1 → L2 → L3)

### L1 — Initial Triage
- ✅ Identify the **target account(s)** under attack.  
- ✅ Review source IPs and geolocation (single or multiple?).  
- ✅ Count the number of failed attempts and timeframe.  
- ✅ Look for corresponding lockouts (Event ID 4740) or eventual success (4624).  
- 🚩 Escalate to L2 if:
  - Privileged account is targeted  
  - Multiple users targeted from same IP (password spray)  
  - Large number of attempts in short timeframe  

**SPL — Detect repeated failures (Windows AD):**
```spl
index=wineventlog EventCode=4625
| stats count min(_time) as first_seen max(_time) as last_seen by src_ip TargetUserName
| where count >= 10
| table src_ip TargetUserName count first_seen last_seen
````

**SPL — VPN failed logins:**

```spl
index=vpn sourcetype="cisco:asa" OR sourcetype="pan:globalprotect"
| search action="failed"
| stats count by src_ip user
| where count > 10
```

---

### L2 — Deep Investigation & Correlation

**1. Windows Logs (AD / Server)**

* Event ID 4625 → failed logons
* Event ID 4740 → account lockouts
* Event ID 4624 → successful logon after multiple failures (potential compromise)

```spl
index=wineventlog (EventCode=4625 OR EventCode=4740 OR EventCode=4624)
| stats count values(EventCode) as EventIDs by src_ip TargetUserName
```

**2. VPN / Firewall Logs**

* Look for same IP attempting logins to many accounts → password spray
* Review for abnormal login times, geolocation

```spl
index=vpn OR index=firewall
| stats count by src_ip user
| where count > 20
```

**3. Endpoint Logs (Sysmon / EDR)**

* Look for abnormal authentication attempts from endpoints (local brute force)
* Check Sysmon Event ID 1 (process creation: repeated `net use`, `runas`, `PsExec`)

```spl
index=sysmon EventCode=1
| search CommandLine="*net use*"
| stats count by host, CommandLine
```

**4. Web / Application Logs**

* Failed login attempts in IIS/Apache/Nginx
* Detect repeated POSTs to login endpoints

```spl
index=web sourcetype=iis OR sourcetype=apache
| search cs_uri_stem="/login" sc_status=401
| stats count by c_ip cs_username
| where count > 15
```

**5. Identity Provider Logs (Okta, Entra ID, Duo)**

* Failed authentications (multiple users, single IP)
* Impossible travel alerts

```spl
index=okta eventType="user.authentication.failed"
| stats count by src_ip user
| where count > 10
```

---

### L3 — Confirm & Respond

**If Confirmed Brute Force:**

* 🛑 Contain

  * Block offending IPs at firewall/VPN
  * Lock/reset targeted accounts
  * Revoke tokens/sessions (cloud IdPs)
* 🔎 Eradicate

  * Check if any successful logons followed failures → possible compromise
  * Perform endpoint triage on affected systems
* 🔁 Recover

  * Restore access for legitimate users
  * Monitor for reattempts after blocks

**If False Positive:**

* ✅ Misconfigurations (apps or scripts retrying logins)
* ✅ User error (fat-fingered password)
* ✅ Document and suppress noisy sources

---

## 🧩 MITRE ATT\&CK Mapping

* **T1110 – Brute Force**
* **T1110.001 – Password Guessing**
* **T1110.003 – Password Spraying**
* **T1078 – Valid Accounts** (if compromise succeeds)
* **T1133 – External Remote Services** (VPN/SSH/OWA brute force)

---

## 📝 Root Cause Analysis (RCA) Template

**1) Executive Summary**

* *What happened:* Multiple failed login attempts detected for account(s) `<X>`
* *Impact:* `<Account lockout / potential compromise>`
* *Disposition:* `<True Positive / False Positive>`

**2) Timeline**

* T0: First failed logon detected
* T1: Lockout triggered or successful login observed
* T2: Containment actions applied (blocks, resets)
* T3: Recovery of legitimate access

**3) Root Cause**

* `[External brute force | Password spray | User error | Application misconfig]`

**4) Scope**

* Accounts targeted, IPs involved, services affected

**5) Actions Taken**

* Containment, eradication, recovery

**6) Preventive Measures**

* MFA, lockout policies, detection tuning

**7) Lessons Learned**

* Detection gaps, threshold tuning, user awareness

---

## 🛡 Recommendations

* **Immediate**

  * Block malicious IPs, lock/reset targeted accounts
  * Enforce password resets & MFA re-enrollment

* **Hardening**

  * Enforce MFA on VPN, RDP, OWA, SSH, SSO
  * Set account lockout thresholds with alerting
  * Geo-block unused regions

* **Monitoring**

  * Alert on multiple failed logons per user in short timeframe
  * Alert on multiple users failing from single IP (password spray)
  * Track successful logon after multiple failures

* **Process**

  * User training on credential hygiene
  * Document legitimate exceptions (apps with bad auth config)

---

## 📎 Before Escalating to Customer

Include:

* Source IPs, geolocation, ASN
* Accounts targeted (critical or not)
* Log evidence (Windows, VPN, firewall, IdP, app logs)
* Result (lockout, success, failed)
* Threat intel on IPs/domains involved
* Analyst recommendation (block, reset, tune detection)

---
