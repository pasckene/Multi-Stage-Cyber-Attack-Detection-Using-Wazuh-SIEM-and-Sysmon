---

# Multi-Stage Cyber Attack Detection Using Wazuh SIEM and Sysmon

```text
Project Type: SOC Detection Engineering Lab
Framework: MITRE ATT&CK
Focus: Attack Simulation • SIEM Detection • Incident Investigation
```

---

# Project Overview

This project demonstrates **end-to-end detection of a multi-stage cyber attack** using **Wazuh** and **Sysmon**.

The lab simulates a realistic adversary attack chain and demonstrates how a **Security Operations Center (SOC)** detects, correlates, and investigates malicious activity using centralized logging and detection engineering.

The attack lifecycle follows techniques from the **MITRE ATT&CK** framework.

Attack stages simulated in this project:

1. Initial Access
2. Execution
3. Persistence
4. Defense Evasion
5. Command and Control

---

# Lab Architecture

The environment simulates attacker, victim, and monitoring infrastructure.

```
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

The simulated adversary executes a multi-stage attack chain designed to replicate real-world intrusion behavior.

---

# Stage 1 – Initial Access

The attacker executes a malicious encoded PowerShell payload.

Example command:

```powershell
powershell -enc <encoded_payload>
```

MITRE Technique:

T1059 – Command and Scripting Interpreter

### Attack Execution Screenshot

![PowerShell Attack](screenshots/powershell-attack.png)

*(Insert screenshot showing encoded PowerShell command execution)*

---

# Stage 2 – Execution

The attacker performs reconnaissance commands on the compromised system.

Example commands:

```
whoami
net user
ipconfig
```

Telemetry Source:

Sysmon Event ID 1

### Reconnaissance Screenshot

![Recon Commands](screenshots/recon-commands.png)

*(Insert screenshot showing attacker commands executed)*

---

# Stage 3 – Persistence

The attacker creates a scheduled task to maintain persistence.

Example command:

```
schtasks /create /sc minute /tn updater /tr malware.exe
```

MITRE Technique:

T1053 – Scheduled Task

### Persistence Screenshot

![Persistence](screenshots/persistence-task.png)

*(Insert screenshot showing scheduled task creation)*

---

# Stage 4 – Defense Evasion

The attacker attempts to disable monitoring tools.

Example command:

```
Stop-Service Sysmon
```

MITRE Technique:

T1562 – Impair Defenses

### Defense Evasion Screenshot

![Defense Evasion](screenshots/sysmon-stop.png)

*(Insert screenshot showing attempt to stop Sysmon)*

---

# Stage 5 – Command and Control

The attacker establishes a reverse shell connection.

Listener on attacker machine:

```
nc -lvnp 4444
```

MITRE Technique:

T1071 – Command and Control

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

# Scheduled Task Persistence Detection

```xml
<rule id="100101" level="10">
  <if_sid>18107</if_sid>
  <description>Suspicious scheduled task created</description>
</rule>
```

### Persistence Alert Screenshot

![Persistence Alert](screenshots/wazuh-persistence-alert.png)

---

# Defense Evasion Detection

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

Correlation rules detect attack patterns across multiple events.

```xml
<rule id="100200" level="15" frequency="3" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <if_matched_sid>100101</if_matched_sid>
  <if_matched_sid>100102</if_matched_sid>
  <description>Multi-stage attack behavior detected</description>
</rule>
```

If multiple suspicious activities occur within the timeframe, a **high-severity alert is triggered**.

### Correlated Alert Screenshot

![Correlation Alert](screenshots/correlation-alert.png)

---

# Threat Hunting Queries

Threat hunting was used to proactively search for malicious behavior.

### PowerShell Abuse Hunting

```
powershell AND ("-enc" OR "Invoke-WebRequest")
```

### Reverse Shell Hunting

```
destination_port:4444
```

### Threat Hunting Screenshot

![Threat Hunting](screenshots/threat-hunting.png)

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

Example investigation timeline:

```
10:12  Encoded PowerShell executed
10:13  Recon commands executed
10:14  Persistence created
10:15  Reverse shell established
```

SOC analyst steps:

1. Review process creation logs
2. Identify suspicious PowerShell execution
3. Investigate persistence mechanisms
4. Analyze network activity

### Investigation Screenshot

![Investigation](screenshots/investigation-timeline.png)

---

# Incident Response Actions

Recommended response actions:

1. Isolate compromised host
2. Terminate malicious processes
3. Remove persistence mechanisms
4. Reset compromised credentials

Example investigation commands:

```
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

If you want, I can also show you **how to make your GitHub repo look extremely elite with 5 small additions (badges, diagrams, and alert samples) that immediately grab recruiters’ attention**.
