# 🛡️ SOC Playbooks Repository

## 📖 Overview
This repository is a collection of **Security Operations Center (SOC) playbooks**.  
The goal is to provide SOC analysts with **structured, repeatable guidance** for investigating and responding to security alerts across different environments.

Each playbook includes:
- 📌 **Alert Context** – Why the alert matters  
- 🧭 **Analyst Actions (L1 → L2 → L3)** – Step-by-step triage and investigation  
- 🧩 **MITRE ATT&CK Mapping** – Links to adversary techniques  
- 📝 **Root Cause Analysis (RCA) Template** – For confirmed incidents  
- 🛡 **Recommendations** – Containment, remediation, and prevention  

---

## 🗂 Repository Structure
Playbooks are grouped by **technology/environment** for easy navigation:
---

## 📑 Folder Index

### 🔹 `windows/`
Playbooks for Windows-related alerts such as:
- Service creation (Event ID 7045 / Sysmon 6)  
- Multiple failed logins  
- Suspicious PowerShell execution  
- Disabled account re-enabled  

### 🔹 `linux/`
Playbooks for Linux-based investigations:
- SSH brute-force detection  
- Suspicious use of `sudo`  
- Unexpected cron jobs  
- Webshell detections  

### 🔹 `firewall/`
Playbooks for firewall and network security alerts:
- F5 configuration changes  
- Cross-site scripting attempts (XSS)  
- Palo Alto allowed intrusion events  
- Reconnaissance or port scanning  

---

## 🚀 How to Use
1. Identify the **type of alert** (Windows, Linux, Firewall, etc.).  
2. Navigate to the respective folder.  
3. Open the relevant playbook and follow the **tiered guidance (L1 → L2 → L3)**.  
4. Use the RCA template to document findings if the alert is confirmed as an incident.  

---

## 🎯 Target Audience
- **L1 Analysts** → Initial triage and escalation  
- **L2 Analysts** → In-depth investigation, enrichment, and validation  
- **L3 Analysts / Incident Responders** → Root cause analysis, containment, eradication, and reporting  

---

## 🔗 MITRE ATT&CK Mapping
Each playbook references relevant **MITRE ATT&CK techniques** to align with adversary TTPs.  
👉 [MITRE ATT&CK Framework](https://attack.mitre.org/)  

---

## 🤝 Contributing
- Use the naming convention: `Playbook_<AlertName>.md`  
- Place the playbook in the correct technology folder (`windows/`, `linux/`, `firewall/`, etc.)  
- Keep formatting consistent across all playbooks  
- Submit Pull Requests for new playbooks or improvements  

---

## 📜 License
This repository is licensed under the MIT License – free to use and adapt for your SOC team.
