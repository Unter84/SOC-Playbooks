# 🛡️ Playbook: AnyConnect VPN Account Locked Out

**Filename:** `playbook-anyconnect-vpn-account-locked-out.md`  
**Category:** VPN / Remote Access Security  
**Use Case:** Detecting and investigating user account lockouts during Cisco AnyConnect VPN authentication attempts.

---

## 🎯 Alert Context — Why this matters
Account lockouts during VPN authentication can indicate:
- **Brute force or password spraying** attempts against remote access infrastructure  
- **Misconfigured clients** (stale credentials cached in AnyConnect)  
- **Compromised accounts** being tested by adversaries  
- **User behavior issues** (typing errors, expired password)  

Because VPN gateways provide **direct remote access to internal systems**, failed attempts and lockouts must be carefully reviewed.

**Relevant Logs/Sources:**
- Cisco ASA / FTD / AnyConnect VPN logs  
- SIEM normalized events (`vpn-login-failed`, `account-lockout`)  
- Windows AD logs (4740 = account locked out)  
- Identity provider logs (if integrated with SAML, Radius, Duo, Okta, Entra ID)

---

## 🧭 Analyst Actions (L1 → L2 → L3)

### L1 — Initial Triage
- ✅ Confirm the username/account that was locked out  
- ✅ Check the VPN log source (Cisco ASA/FTD) for multiple failed attempts leading to lockout  
- ✅ Review timestamp — was this during business hours or unusual/off-hours?  
- ✅ Identify the **source IP(s)** from which the login attempts originated  
- ✅ Cross-check with Active Directory event 4740 (account lockout) if integrated  
- 🚩 Escalate to L2 if:
  - Lockout caused by multiple IPs  
  - Lockout on privileged/critical user  
  - Repeated lockouts in short period (possible brute force)

### L2 — Deep Investigation
- 🔎 Review authentication pattern:
  - Single IP with many attempts = brute force  
  - Multiple IPs with distributed attempts = password spray  
- 🔎 Correlate IP reputation (check threat intel, geolocation, TOR/VPN hosting ASN)  
- 🔎 Verify if the account recently changed password or had expired credentials  
- 🔎 Check AD for previous logon failures (4625 events) tied to this account  
- 🔎 Review whether MFA was enabled — did MFA block access?  
- 🔎 Confirm with user/HR if they were actively trying to connect  

### L3 — Confirm & Respond
- 🛑 If malicious:
  - Block offending IP(s) at firewall / VPN gateway  
  - Reset credentials of impacted account; revoke sessions  
  - Force MFA re-registration and notify user  
  - Monitor for repeated attempts on other accounts from same IP ranges  
- ✅ If benign:
  - Educate user on password resets and VPN login process  
  - Document misconfiguration (cached creds, expired password, multiple devices)  
  - Suppress alert only if well understood and recurrently benign

---

## 🧩 MITRE ATT&CK Mapping
- **T1110 – Brute Force** (Password Guessing / Password Spraying)  
- **T1078 – Valid Accounts** (use of compromised credentials once obtained)  
- **T1078.004 – Valid Accounts: Cloud Accounts** (if IdP integrated with VPN)  
- **T1133 – External Remote Services** (exploitation of VPN for access)  

---

## 📝 Root Cause Analysis (RCA) Template

**1) Executive Summary**  
- *What happened:* Account `<X>` locked out on AnyConnect VPN gateway  
- *Impact:* `<User unable to connect / potential brute force detected>`  
- *Disposition:* `<True Positive / False Positive / Benign>`  

**2) Timeline**  
- T0: Detection of lockout (ASA/FTD/AD logs)  
- T1: Review of source IPs and number of attempts  
- T2: User contact / validation  
- T3: Containment actions taken (IP block, password reset)  
- T4: Recovery (account unlocked, VPN access restored)  

**3) Root Cause**  
- Category: `[Brute force attack | Password spraying | Misconfiguration | Expired credentials | User error]`  

**4) Scope**  
- Accounts impacted, number of IPs involved, geolocation  

**5) Actions Taken**  
- Containment, eradication, recovery  

**6) Preventive Measures**  
- Harden authentication, enable MFA, tune lockout thresholds  

**7) Lessons Learned**  
- Gaps in monitoring, thresholds, user awareness  

---

## 🛡 Recommendations

- **Immediate Containment**
  - Block malicious IPs and subnets  
  - Reset and unlock user account only after verification  
  - Force MFA re-registration if compromised  

- **Hardening**
  - Enforce MFA for all VPN logins  
  - Adjust account lockout thresholds (balance between security & usability)  
  - Implement adaptive authentication (risk-based, geo-aware policies)  
  - Enforce password hygiene policies (length, expiration, non-reuse)  

- **Monitoring**
  - Detect repeated lockouts across many accounts (password spray)  
  - Alert on lockouts from unusual geolocations or TOR exit nodes  
  - Monitor AD event 4740 in parallel with VPN logs  

- **Process**
  - User education: avoid saving credentials in VPN client  
  - Document recurring benign lockouts and whitelist expected behavior  

---

## 📎 Before Escalating to Customer

Include:
- VPN logs showing failed attempts and lockout  
- AD event 4740 evidence (if available)  
- Source IP details (geo, reputation, ASN, TOR/VPN detection)  
- Account criticality (normal user vs privileged user)  
- Business/user confirmation outcome  
- Analyst recommendation (malicious activity blocked vs benign misconfig)

---

## 📂 Suggested Repo Structure
