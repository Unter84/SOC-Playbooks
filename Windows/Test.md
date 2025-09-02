🛡️ Playbook: User Added to a Group (AD / Entra ID)

Use this whenever your SIEM/IDP raises an alert that a user (or service principal) was added to a local/domain/M365/Entra group.

⸻

🎯 Alert Context — Why this matters

Adding an account to a group can silently elevate privileges, grant new access paths, and enable persistence (e.g., adding a compromised account to Domain Admins, Local Administrators, Exchange Org Management, or high-impact Entra roles). In ATT&CK terms this is typically Account Manipulation (T1098) for Privilege Escalation and Persistence and often precedes abuse of Valid Accounts (T1078) for lateral movement.  ￼

Primary log signals you’ll use
	•	Windows Security Log: 4728 (added to global security group), 4732 (added to local/domain local security group), 4756 (added to universal security group).  ￼
	•	Entra ID (Azure AD) AuditLogs: ActivityDisplayName = “Add member to group” (Category=GroupManagement).  ￼

⸻

🧭 Analyst Actions (L1 → L2 → L3)

L1 — Initial triage (5–10 mins)

Goal: Quickly decide “benign admin/JML or risky change?” and collect baseline facts.
	1.	Confirm the target group’s criticality
	•	Is it privileged (e.g., Domain Admins, Administrators on servers, DNSAdmins, Exchange Org Mgmt, Entra “Global Administrator/Privileged Role Administrator”)? If yes, raise priority.
	2.	Extract the who/when/where
	•	From Windows events 4728/4732/4756 capture:
	•	Subject (who performed the add), Member (who was added), Group, Logon ID, Computer.  ￼
	•	From Entra AuditLogs capture:
	•	InitiatedBy, TargetResources.displayName, Category=GroupManagement, ActivityDisplayName=Add member to group, IPAddress, UserAgent.  ￼
	3.	Approval/context check
	•	Look for a change ticket/JML workflow, maintenance window, or CAB change. If found and matches: note evidence and continue to L2 validation (don’t close yet).
	4.	Time & location sanity
	•	Off-hours? New/unknown source IP/device? Impossible travel around the same time (compare Entra SignInLogs if available).
	5.	Immediate flags for escalate-to-L2
	•	Privileged group, no ticket, unknown admin, automation/service performing unusual change, or multiple adds in burst.

Quick SPL (Windows Security):

index=wineventlog sourcetype=WinEventLog:Security (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| eval CriticalGroup=if(match(Group_Name,"(?i)Domain Admins|Administrators|Enterprise Admins|Schema Admins|DnsAdmins|Exchange Organization Management"),"YES","NO")
| table _time, EventCode, SubjectUserName, SubjectLogonId, MemberName, MemberSid, Group_Name, CriticalGroup, ComputerName
| sort -_time

Quick KQL (Entra ID):

AuditLogs
| where Category == "GroupManagement" and ActivityDisplayName == "Add member to group"
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.displayName),
          ActorUPN = tostring(InitiatedBy.user.userPrincipalName),
          IPAddress, ActivityDisplayName, Group=tostring(TargetResources[0].displayName),
          AddedMember=tostring(TargetResources[1].displayName)
| order by TimeGenerated desc

(Fields per Microsoft Learn AuditLogs. Exact columns vary by tenant/connector.)  ￼

⸻

L2 — Deep investigation (20–40 mins)

Goal: Prove legitimacy or build an incident narrative with evidence.
	1.	Reconstruct the timeline
	•	±2 hours around the change. Look for:
	•	Recent account creation (4720), password reset (4724), user changed (4738), account enabled (4722) near the add (possible attacker setup).  ￼
	•	“Group changed” (4735/4755) just before/after the add (sometimes accompanies 4732/4756).  ￼
	2.	Correlate the actor’s session & tool
	•	Windows: tie SubjectLogonId from 4728/4732/4756 to 4624 logon (source IP, logon type). Check for 4648 (logon with explicit creds).
	•	Hunt for admin tools: PowerShell 4104 (Add-ADGroupMember, Set-ADGroup, net localgroup administrators /add, dsmod/dsadd), Sysmon 1 (process creation) on the admin host.
	3.	Cloud-side validation
	•	Entra: match AuditLogs change with SignInLogs of the InitiatedBy user (IP, device compliance, MFA). Look for unfamiliar ISP, TOR/VPN, disabled MFA.
	4.	Blast radius
	•	How many other additions in the same window/actor? Any changes to privileged groups? Any new role assignments in Entra (PIM activations)? (These can also fall under T1098 variants.)  ￼
	5.	Business validation
	•	Confirm with app/team owners whether the new access was requested/needed. If yes, capture ticket reference & approver; if no, proceed to L3.

Helpful SPL snippets

/* Link group-add to the actor's logon and admin tooling */
(index=wineventlog sourcetype=WinEventLog:Security (EventCode=4728 OR 4732 OR 4756))
| rename SubjectLogonId as LogonId
| join LogonId [ search index=wineventlog EventCode=4624 | fields LogonId, IpAddress, LogonType, ComputerName, TargetUserName, _time]
| eval AdminToolSuspect=if(match(_raw,"Add-ADGroupMember|net localgroup|dsmod|dsadd"),"Yes","No")
| table _time, Group_Name, MemberName, SubjectUserName, IpAddress, LogonType, ComputerName, AdminToolSuspect

Helpful KQL

// Tie group add to actor sign-ins (Entra)
let adds = AuditLogs
| where Category == "GroupManagement" and ActivityDisplayName == "Add member to group"
| project AddTime=TimeGenerated, Actor=tostring(InitiatedBy.user.userPrincipalName),
          Group=tostring(TargetResources[0].displayName),
          AddedMember=tostring(TargetResources[1].displayName), IP=IPAddress;
SignInLogs
| where UserPrincipalName in (adds | project Actor)
| project SignInTime=TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, DeviceDetail
| join kind=innerunique adds on $left.UserPrincipalName == $right.Actor
| where datetime_diff("minute", AddTime, SignInTime) between (-120 .. 120)
| project AddTime, Group, AddedMember, Actor, IP, SignInTime, IPAddress, AppDisplayName, DeviceDetail

(Entra log model per Microsoft Learn.)  ￼

⸻

L3 — Confirm & respond (60+ mins)

If suspicious or unapproved:
	1.	Contain
	•	Remove the membership from the privileged group (record the exact change).
	•	Disable or suspend the added account (and the actor account if compromised).
	•	If cloud: revoke sessions/refresh tokens for involved identities; force password reset and MFA re-registration.
	2.	Eradicate & harden
	•	On the actor host: collect volatile data, processes, PS transcripts, and hunt for credential theft tools; re-image if needed.
	•	Review/rotate credentials for any impacted service accounts; check other groups the actor touched in the same window.
	3.	Recover
	•	Restore legitimate access via approved workflow; monitor for re-add attempts.
	•	Open a full incident ticket and proceed to RCA.

If legitimate (approved change):
	•	Document ticket/approver, business justification, any policy gaps (e.g., change done outside JML/PIM), and update allowlists (automation accounts, approved admins).

⸻

🧩 MITRE ATT&CK Mapping (with links)
	•	T1098 – Account Manipulation (Privilege Escalation, Persistence): adding accounts to groups/roles to retain or elevate access.  ￼
	•	T1098.007 – Additional Local or Domain Groups: explicitly covers adding accounts to Windows local/domain groups (e.g., Local Administrators, RDP).  ￼
	•	T1078 – Valid Accounts: subsequent use of the newly granted permissions for logon/lateral movement.  ￼

⸻

🔎 Detection & Query Cookbook

Windows (SIEM) — core events
	•	4728: member added to global security group
	•	4732: member added to local/domain local security group
	•	4756: member added to universal security group  ￼

Splunk — privileged group watch

index=wineventlog sourcetype=WinEventLog:Security (EventCode=4728 OR 4732 OR 4756)
| lookup privileged_groups groupName OUTPUT isPrivileged as Priv
| where Priv="true"
| stats count min(_time) as first_seen max(_time) as last_seen by Group_Name, MemberName, SubjectUserName, SubjectLogonId, ComputerName

Splunk — burst adds / same actor

index=wineventlog sourcetype=WinEventLog:Security (EventCode=4728 OR 4732 OR 4756)
| bin _time span=15m
| stats dc(MemberSid) as distinct_members values(MemberName) as members by _time, SubjectUserName, Group_Name
| where distinct_members>=3

KQL — Entra AuditLogs (group adds)

AuditLogs
| where Category == "GroupManagement" and ActivityDisplayName == "Add member to group"
| extend Group=tostring(TargetResources[0].displayName), Added=tostring(TargetResources[1].displayName)
| summarize adds=count(), members=make_set(Added) by Actor=tostring(InitiatedBy.user.userPrincipalName), Group, bin(TimeGenerated, 30m)
| where adds >= 3

(Entra AuditLogs references. Fields may vary slightly by connector.)  ￼

⸻

📝 Root Cause Analysis (RCA) Template

1) Executive Summary
	•	What happened: User <X> was added to group <Y> on <date/time TZ>.
	•	Impact: Access granted to <systems/data>; potential for <priv esc / lateral movement>.
	•	Disposition: <True Positive / Benign Change / Inconclusive>.

2) Timeline (absolute dates/times)
	•	T0: Detection (alert ID, source)
	•	T1: Group membership change (event ID / AuditLogs record)
	•	T2: Actor sign-in context (source IP, device, MFA)
	•	T3: Post-change activity (admin actions, logons)
	•	T4: Containment/rollback
	•	T5: Recovery & monitoring

3) Root Cause
	•	Category: [Compromised credentials | Policy gap | Unapproved change | Automation misconfig | Human error]
	•	Evidence: (Event IDs 4728/4732/4756, Entra AuditLogs entries, sign-in telemetry, PS transcripts).  ￼

4) Affected Scope
	•	Accounts, groups, systems, data domains.

5) Actions Taken
	•	Containment, eradication, recovery (who/when).

6) Preventive Measures
	•	Policy/process fixes, detections added, controls deployed (see recommendations below).

7) Lessons Learned & Owners
	•	Concrete follow-ups with due dates.

⸻

🛡 Recommendations — Containment, Remediation, Prevention

Immediate containment (if suspicious)
	•	Remove the membership; disable the involved account(s); revoke sessions (cloud) and force password resets; capture/secure evidence first. (Audit and log steps in ticket; align with your legal/compliance process.)

Hardening & process
	•	Just-In-Time access via Entra PIM / time-bound group membership; require approval + MFA for elevation.
	•	Enforce MFA and strong Conditional Access for all admins; restrict admin tasks to Privileged Access Workstations (PAW).
	•	Centralize group changes via JML workflow (no ad-hoc console changes).
	•	Tiered admin model; separate roles; prohibit daily-driver accounts from holding admin memberships.
	•	Audit & logging: ensure Windows Security Group Management auditing (4728/4732/4756) is enabled, plus PowerShell 4104, Process Creation (Sysmon 1), and Entra AuditLogs/SignInLogs collection.  ￼
	•	Detections:
	•	Privileged group watchlist (alert on any add/remove).
	•	Burst additions by same actor.
	•	Adds followed by immediate admin activity (service control, RDP, DC logon).
	•	Actor from new IP/ASN or from device failing compliance.
	•	Prevent policy gaps:
	•	Disallow standing membership in top-tier groups; prefer PIM/JIT.
	•	Service accounts: document fixed memberships; monitor drift.

⸻

📎 Appendix — What to capture before escalating to customer
	•	Exact event(s) (IDs, JSON/XML or full AuditLogs record).  ￼
	•	Actor identity + session details (4624/SignInLogs: IP, logon type, device).
	•	Tooling used (4104 commands, Sysmon process lineage).
	•	Ticket/approval references or explicit absence.
	•	Impact analysis: what the group grants (systems/data), any use of new privileges after the change.
	•	Your recommendation: rollback or accept, plus preventive control(s).

⸻

Reference Notes
	•	MITRE ATT&CK: T1098 Account Manipulation and sub-technique T1098.007 Additional Local or Domain Groups (adding to local/domain groups).  ￼
	•	Windows events for group membership additions: 4728/4732/4756 (global/local/universal).  ￼
	•	Entra ID AuditLogs include Add member to group under GroupManagement.  ￼

⸻
