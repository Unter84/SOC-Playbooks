# 🛡️ Playbook: User Added to a Group (AD / Entra ID)

**Filename:** `playbook-user-added-to-group.md`  
**Category:** Windows / Identity Security  
**Use Case:** Detecting and investigating suspicious additions of users to Active Directory or Entra ID (Azure AD) groups.

---

## 🎯 Alert Context — Why this matters
Adding an account to a group can silently **elevate privileges**, grant **new access paths**, and enable **persistence**.  
Examples:
- Adding a compromised account to *Domain Admins*, *Administrators*, *DNSAdmins*, *Exchange Organization Management*, or Entra *Global Administrator*.  
- Used by adversaries for **Privilege Escalation** and **Persistence** (MITRE T1098, T1098.007).

**Relevant Events:**
- Windows: 4728 (global group), 4732 (domain local group), 4756 (universal group)  
- Entra ID: AuditLogs → *ActivityDisplayName = "Add member to group"* (Category=GroupManagement)

---

## 🧭 Analyst Actions (L1 → L2 → L3)

### L1 — Initial Triage
- ✅ Identify if the group is privileged (Domain Admins, Enterprise Admins, etc.)
- ✅ Collect event details (who performed the add, who was added, group name, source system)
- ✅ Check if change aligns with ticket/JML request
- ✅ Flag off-hours, suspicious IPs, or unusual devices
- 🚩 Escalate to L2 if: privileged group, no approval, unknown actor, or burst of additions

### L2 — Deep Investigation
- 🔎 Reconstruct timeline around the change (±2 hours)  
  - Look for related events: 4720 (user creation), 4724 (password reset), 4735 (group modified)  
- 🔎 Correlate with actor’s logon session (4624 logon, 4648 explicit creds, 4104 PowerShell usage)  
- 🔎 In Entra: validate actor sign-ins (IP, MFA, device compliance, impossible travel)  
- 🔎 Assess blast radius — were multiple accounts added? Were privileged roles assigned?  
- 🔎 Confirm with business if change was expected

### L3 — Confirm & Respond
- 🛑 If unauthorized:
  - Remove membership immediately
  - Disable or suspend added/actor accounts
  - Revoke cloud sessions and reset credentials
  - Collect forensic data (host logs, PS transcripts, Sysmon, Entra SignInLogs)
- ✅ If legitimate:
  - Document ticket/approval, justification, and update allowlists
  - Recommend process improvement if change bypassed workflows

---

## 🧩 MITRE ATT&CK Mapping
- **T1098 – Account Manipulation** (Privilege Escalation, Persistence)  
- **T1098.007 – Additional Local or Domain Groups**  
- **T1078 – Valid Accounts** (subsequent abuse of new access)

---

## 📝 Root Cause Analysis (RCA) Template

**1) Executive Summary**  
- What happened, impact, disposition (TP/FP/Benign)

**2) Timeline**  
- Detection → Change event → Actor sign-in → Post-change activity → Containment → Recovery

**3) Root Cause**  
- `[Compromised credentials | Policy gap | Unapproved change | Automation misconfig | Human error]`

**4) Scope**  
- Accounts, groups, systems, data affected

**5) Actions Taken**  
- Containment, eradication, recovery steps

**6) Preventive Measures**  
- Policy/process updates, detection improvements, additional controls

**7) Lessons Learned**  
- Follow-ups with owners and due dates

---

## 🛡 Recommendations

- **Containment:** Rollback unauthorized changes, disable impacted accounts, revoke sessions  
- **Hardening:**
  - Use Just-in-Time (PIM) access for admin groups
  - Enforce MFA + Conditional Access for admins
  - Require change approvals (CAB/JML workflows)
  - Separate admin accounts from daily-use accounts
- **Monitoring:**
  - Alert on 4728/4732/4756 for privileged groups
  - Detect burst additions or off-hours changes
  - Track Entra “Add member to group” logs and PIM role activations
- **Process:**
  - Prohibit permanent standing memberships
  - Document service account memberships and monitor for drift

---

## 📎 Before Escalating to Customer

Include:
- Event evidence (Windows/Entra logs)  
- Actor identity and session details (IP, logon type, MFA status)  
- Tooling observed (PowerShell, DS commands, portal changes)  
- Ticket/approval reference (or lack thereof)  
- Impact analysis (what systems/data could be accessed)  
- Analyst recommendation (rollback vs. accept, preventive fix)

---

## 📂 Suggested Repo Structure
