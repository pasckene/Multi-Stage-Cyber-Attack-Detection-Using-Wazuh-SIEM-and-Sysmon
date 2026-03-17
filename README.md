# Multi-Stage Cyber Attack Detection Using Wazuh SIEM and Sysmon

```text
Project Type: SOC Detection Engineering Lab
Framework: MITRE ATT&CK
Focus: Attack Simulation • SIEM Detection • Incident Investigation
```

---

# Table of Contents

1. [Project Overview](#project-overview)
2. [Lab Architecture](#lab-architecture)
3. [Telemetry Collection](#telemetry-collection)
4. [Attack Simulation](#attack-simulation)
5. [Stage 1 – Initial Access](#stage-1--initial-access)
6. [Stage 2 – Execution](#stage-2--execution)
7. [Stage 3 – Persistence](#stage-3--persistence)
8. [Stage 4 – Defense Evasion](#stage-4--defense-evasion)
9. [Stage 5 – Command and Control](#stage-5--command-and-control)
10. [Detection Engineering](#detection-engineering)
11. [Correlation Rules](#correlation-rules)
12. [Threat Hunting Queries](#threat-hunting-queries)
13. [Indicators of Compromise (IOCs)](#indicators-of-compromise-iocs)
14. [Attack Timeline](#attack-timeline)
15. [Detection Logic Explanation](#detection-logic-explanation)
16. [Purple Team Validation](#purple-team-validation)
17. [Detection Coverage Matrix](#detection-coverage-matrix)
18. [SOC Investigation Workflow](#soc-investigation-workflow)
19. [Incident Response Actions](#incident-response-actions)
20. [Technologies Used](#technologies-used)
21. [Skills Demonstrated](#skills-demonstrated)

---

# Project Overview

This project demonstrates **end-to-end detection of a multi-stage cyber attack** using **Wazuh** and **Sysmon**.

It simulates a realistic adversary attack chain and shows how a **Security Operations Center (SOC)** detects, correlates, and investigates malicious activity using centralized logging and detection engineering. The attack lifecycle follows the **MITRE ATT&CK** framework.

Attack stages simulated:

* Initial Access
* Execution
* Persistence
* Defense Evasion
* Command and Control

---

# Lab Architecture

The environment simulates attacker, victim, and monitoring infrastructure.

```text
Kali Linux (Attacker)
        │
        │ Attack Simulation
        ▼
Windows 11 Victim
(Sysmon + Wazuh Agent)
        │
        │ Endpoint Logs
        ▼
Wazuh Manager
        │
        ▼
Wazuh Dashboard
```

### Architecture Screenshot

![Lab Architecture](screenshots/lab-architecture.png)
*(Insert diagram showing attacker, victim, and Wazuh manager)*

---

# Telemetry Collection

Sysmon provides detailed endpoint telemetry for detection.

Important Sysmon event types:

| Event ID | Description           |
| -------- | --------------------- |
| 1        | Process Creation      |
| 3        | Network Connection    |
| 7        | Image Loaded          |
| 10       | Process Access        |
| 13       | Registry Modification |
| 22       | DNS Query             |

These logs are forwarded to Wazuh for analysis.

### Sysmon Logging Screenshot

![Sysmon Logs](screenshots/sysmon-events.png)
*(Insert screenshot showing Sysmon event viewer logs)*

---

# Attack Simulation

The simulated adversary executes a multi-stage attack chain to replicate real-world intrusion behavior.

---

# Stage 1 – Initial Access

### Attack Command

```powershell
powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEMAbwBtAHAAcgBvAG0AaQBzAGUAZAAiAA==
```

### Description

This simulates PowerShell malware execution using Base64 encoding.

Adversaries frequently employ obfuscation such as command encoding to bypass security controls and gain initial access to the target environment.

MITRE Technique

```
T1059 – Command and Scripting Interpreter
```

### Detection

* Sysmon Event ID 1
* Command-line inspection
* Detection of `-enc`

📷 Screenshot Placeholder

```
screenshots/initial-access-alert.png
```

---

---

# Stage 2 – Execution

The attacker performs reconnaissance commands on the compromised system.

```text
whoami
net user
ipconfig
```

Telemetry Source: Sysmon Event ID 1

### Reconnaissance Screenshot

![Recon Commands](screenshots/recon-commands.png)
*(Insert screenshot showing attacker commands executed)*

---

# Stage 3 – Persistence

The attacker creates a scheduled task to maintain persistence.

```text
schtasks /create /sc minute /tn updater /tr malware.exe
```

MITRE Technique: T1053 – Scheduled Task

### Persistence Screenshot

![Persistence](screenshots/persistence-task.png)
*(Insert screenshot showing scheduled task creation)*

---



## 🔴 Stage 4 – Defense Evasion

The attacker attempts to impair system defenses by disabling security monitoring mechanisms, specifically targeting real-time protection to reduce detection visibility.

### 💻 Command Executed

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

---

### 🎯 Objective

To disable **Microsoft Defender’s real-time monitoring**, allowing malicious activities to execute without immediate detection.

---

### 🧠 MITRE ATT&CK Mapping

* **Technique:** T1562 – Impair Defenses
* **Sub-technique:** T1562.001 – Disable or Modify Security Tools

---

### 📡 Expected Telemetry

* **Event Source:** PowerShell / Windows Defender
* **Relevant Logs:**

  * PowerShell Script Block Logging (Event ID 4104)
  * Windows Defender Operational Logs
* **Sysmon:**

  * Event ID 1 (Process Creation – PowerShell execution)

---


### Defense Evasion Screenshot

![Defense Evasion](screenshots/sysmon-stop.png)
*(Insert screenshot showing attempt to stop Sysmon)*

---

# Stage 5 – Command and Control

The attacker establishes a reverse shell connection.

```text
nc -lvnp 4444
```

MITRE Technique: T1071 – Command and Control

### Reverse Shell Screenshot

![Reverse Shell](screenshots/reverse-shell.png)
*(Insert screenshot showing attacker shell session)*

---

# Detection Engineering

Custom Wazuh detection rules identify malicious activity.

### Encoded PowerShell Detection

```xml
<rule id="100100" level="12">
  <if_sid>61600</if_sid>
  <match>-enc</match>
  <description>Encoded PowerShell command detected</description>
</rule>
```

### Detection Screenshot

![Wazuh Detection](screenshots/wazuh-powershell-alert.png)
*(Insert screenshot showing alert triggered in Wazuh)*

---

### Scheduled Task Persistence Detection

```xml
<rule id="100101" level="10">
  <if_sid>18107</if_sid>
  <description>Suspicious scheduled task created</description>
</rule>
```

### Persistence Alert Screenshot

![Persistence Alert](screenshots/wazuh-persistence-alert.png)

---

### Defense Evasion Detection

```xml
<rule id="100102" level="12">
  <match>Stop-Service Sysmon</match>
  <description>Possible attempt to disable monitoring</description>
</rule>
```

### Defense Evasion Alert Screenshot

![Defense Evasion Alert](screenshots/wazuh-defense-evasion.png)

---

# Correlation Rules

Detect multi-stage attack patterns across events.

```xml
<rule id="100200" level="15" frequency="3" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <if_matched_sid>100101</if_matched_sid>
  <if_matched_sid>100102</if_matched_sid>
  <description>Multi-stage attack behavior detected</description>
</rule>
```

### Correlated Alert Screenshot

![Correlation Alert](screenshots/correlation-alert.png)

---

# Threat Hunting Queries

Proactively searching for suspicious behavior.

### PowerShell Abuse

```text
powershell AND ("-enc" OR "Invoke-WebRequest")
```

### Reverse Shell Hunting

```text
destination_port:4444
```

### Threat Hunting Screenshot

![Threat Hunting](screenshots/threat-hunting.png)

---

# Indicators of Compromise (IOCs)

| IOC Type | Indicator           | Description                         |
| -------- | ------------------- | ----------------------------------- |
| Process  | powershell.exe -enc | Encoded PowerShell command          |
| Command  | schtasks /create    | Persistence via scheduled task      |
| Service  | Stop-Service Sysmon | Attempt to disable monitoring       |
| Network  | Port 4444           | Reverse shell communication         |
| Tool     | nc.exe              | Netcat used for command and control |

### IOC Investigation Screenshot

![IOC Analysis](screenshots/ioc-analysis.png)

---

# Attack Timeline

| Time  | Event                                   |
| ----- | --------------------------------------- |
| 10:12 | Encoded PowerShell payload executed     |
| 10:13 | System reconnaissance commands executed |
| 10:14 | Scheduled task persistence created      |
| 10:15 | Reverse shell connection established    |
| 10:16 | Monitoring tools targeted for shutdown  |

### Attack Timeline Screenshot

![Attack Timeline](screenshots/attack-timeline.png)

---

# Detection Logic Explanation

### Detection Strategy

1. **Suspicious Command Execution** – detect encoded PowerShell:
   `powershell AND "-enc"`

2. **Persistence Detection** – monitor scheduled task creation:
   `schtasks /create`

3. **Security Tool Tampering** – detect attempts to stop monitoring:
   `Stop-Service Sysmon`

### Detection Logic Screenshot

![Detection Logic](screenshots/detection-logic.png)

---

# Purple Team Validation

| Attack Technique   | Command Used          | Detection Result          |
| ------------------ | --------------------- | ------------------------- |
| Encoded PowerShell | `powershell -enc`     | Alert Triggered           |
| Recon Commands     | `whoami`, `net user`  | Logged                    |
| Persistence        | `schtasks /create`    | Alert Triggered           |
| Defense Evasion    | `Stop-Service Sysmon` | Alert Triggered           |
| Reverse Shell      | `nc -lvnp 4444`       | Network Activity Detected |

### Purple Team Workflow

```text
Attacker Action
      │
      ▼
Sysmon Log Generated
      │
      ▼
Wazuh Agent Forwarded Log
      │
      ▼
Wazuh Detection Rule Triggered
      │
      ▼
Alert Displayed in Dashboard
```

### Purple Team Validation Screenshot

![Purple Team Validation](screenshots/purple-team-validation.png)

---

# Detection Coverage Matrix

| Technique | Detection Source | Method                    |
| --------- | ---------------- | ------------------------- |
| T1059     | Sysmon Event 1   | PowerShell detection      |
| T1053     | Sysmon Event 13  | Scheduled task rule       |
| T1562     | Windows logs     | Service stop detection    |
| T1071     | Sysmon Event 3   | Network anomaly detection |

---

# SOC Investigation Workflow

| Time  | Event                       |
| ----- | --------------------------- |
| 10:12 | Encoded PowerShell executed |
| 10:13 | Recon commands executed     |
| 10:14 | Persistence created         |
| 10:15 | Reverse shell established   |

### Investigation Screenshot

![Investigation](screenshots/investigation-timeline.png)

---

# Incident Response Actions

1. Isolate compromised host
2. Terminate malicious processes
3. Remove persistence mechanisms
4. Reset compromised credentials

### Investigation Commands

```text
tasklist /v
netstat -ano
```

---

# Technologies Used

• Wazuh
• Sysmon
• Kali Linux
• Windows 11
• Netcat

---
