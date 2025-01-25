# THM-Writeup-ThreatHunting-Foothold
Writeup for TryHackMe ThreatHunting: Foothold - analyzing Initial Access, Execution, Defense Evasion, Persistence, and C2 tactics using ELK and MITRE ATT&amp;CK.

By Ramyar Daneshgar 

### **TryHackMe: Threat Hunting - Foothold Write-Up**  
**By Ramyar Daneshgar**

---

This lab focused on analyzing indicators of compromise (IoCs) to identify an adversary's activities during the **Initial Access**, **Execution**, **Defense Evasion**, **Persistence**, and **Command and Control (C2)** phases of an attack. This exercise demonstrates how to detect, analyze, and mitigate potential threats using **Kibana** and **ELK stack** for threat hunting.

---

### **Setup**
The environment provided included:
1. **Virtual Machines (VMs)**:
   - **JUMPHOST**: An Ubuntu bastion server.
   - **WEB01**: An external-facing web server.
   - **WKSTN-1 and WKSTN-2**: Windows workstations.
   - **DC01**: A domain controller.

2. **ELK Stack**:
   - **Indices**:
     - `filebeat-*`: Logs from Linux hosts.
     - `winlogbeat-*`: Logs from Windows machines.
     - `packetbeat-*`: Network traffic logs.

3. **Credentials**:  
   - URL: `http://<MACHINE_IP>`  
   - Username: `elastic`  
   - Password: `elastic`  

The objective was to correlate logs and detect anomalous activities, following the **MITRE ATT&CK framework**, to identify the adversary's techniques and tactics.

---

## **Key Phases of the Investigation**

---

### **1. Initial Access (MITRE: TA0001)**
**Objective**: Identify how the adversary gained initial access to the network.

#### **Scenario 1: Brute-Force via SSH**
1. **Kibana Query**:  
   Using the `filebeat-*` index, I searched for failed SSH authentication attempts:
   ```kql
   host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Failed
   ```
   - Result: **500+ failed authentication attempts** from two IPs.
   
2. **Successful Authentication**:  
   Narrowed the query to find accepted SSH authentication from these IPs:
   ```kql
   host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Accepted AND source.ip: (167.71.198.43 OR 218.92.0.115)
   ```
   - Result: The adversary accessed the **JUMPHOST server** on **Jul 3, 2023 @ 14:14:09.000** using the **dev** account.

---

#### **Scenario 2: Remote Code Execution on WEB01**
1. **Kibana Query**:  
   Using the `packetbeat-*` index, I investigated HTTP requests to `WEB01`:
   ```kql
   host.name: web01 AND network.protocol: http AND destination.port: 80
   ```
   - Result: The adversary used **Gobuster** to enumerate directories.

2. **Exploitation**:  
   After discovering `/gila`, the attacker injected malicious PHP code using the **User-Agent** field to achieve remote code execution. The adversary accessed sensitive files such as `config.php`.

---

### **2. Execution (MITRE: TA0002)**
**Objective**: Trace the execution of malicious commands on compromised systems.

#### **Scenario 1: Command-Line Tools**
- Investigated events from `powershell.exe` and `cmd.exe`:
  ```kql
  host.name: WKSTN-* AND winlog.event_id: 1 AND process.name: (cmd.exe OR powershell.exe)
  ```
  - Observed:  
    - `cmd.exe` was spawned by `C:\Windows\Temp\installer.exe`.
    - The first command executed was `whoami /priv`.

#### **Scenario 2: Living Off the Land Binaries (LOLBAS)**
- Explored binaries like `certutil.exe`, `mshta.exe`, and `regsvr32.exe`:
  ```kql
  host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND process.name: (mshta.exe OR certutil.exe OR regsvr32.exe)
  ```
  - Observed:  
    - `certutil.exe` downloaded `installer.exe`.
    - `mshta.exe` executed an encoded PowerShell command.

---

### **3. Defense Evasion (MITRE: TA0005)**
**Objective**: Identify techniques used to avoid detection.

#### **Scenario 1: Disabling Security Software**
- Query for disabling Windows Defender:
  ```kql
  host.name: WKSTN-* AND (*DisableRealtimeMonitoring* OR *RemoveDefinitions*)
  ```
  - Observed:
    - `Set-MpPreference` disabled real-time monitoring.
    - `MpCmdRun.exe` removed Defender definitions.

#### **Scenario 2: Log Deletion**
- Query for event logs cleared:
  ```kql
  host.name: WKSTN-* AND winlog.event_id: 1102
  ```
  - Observed:
    - Logs were cleared on `WKSTN-1`.

---

### **4. Persistence (MITRE: TA0003)**
**Objective**: Track methods used to maintain long-term access.

#### **Scenario 1: Scheduled Task Creation**
- Query for task creation:
  ```kql
  host.name: WKSTN-* AND winlog.event_id: 4698
  ```
  - Observed:
    - A malicious task named **Windows Update** was scheduled to run every minute, executing commands tied to `installer.exe`.

#### **Scenario 2: Registry Modification**
- Query for registry changes:
  ```kql
  host.name: WKSTN-* AND winlog.event_id: 13 AND registry.path: (*CurrentVersion\\Run* OR *CurrentVersion\\Explorer\\Shell*)
  ```
  - Observed:
    - A key pointing to `C:\Windows\Temp\installer.exe` was created in the `RunOnce` registry path.

---

### **5. Command and Control (MITRE: TA0011)**
**Objective**: Uncover communication channels between the adversary and compromised systems.

#### **Scenario 1: DNS-Based C2**
- Query for unusual DNS requests:
  ```kql
  network.protocol: dns AND NOT dns.question.name: *arpa
  ```
  - Observed:
    - `167.71.198.43` queried **golge.xyz** over 2000 times using TXT and CNAME records.

#### **Scenario 2: Discord C2**
- Query for connections to Discord:
  ```kql
  host.name: WKSTN-1* AND *discord.gg*
  ```
  - Observed:
    - `installer.exe` initiated communication with **discord.gg**.

#### **Scenario 3: Encrypted HTTP Traffic**
- Query for outbound HTTP traffic:
  ```kql
  network.protocol: http AND network.direction: egress
  ```
  - Observed:
    - High-volume GET requests to **cdn.golge.xyz** from both `WKSTN-1` and `WKSTN-2`.

---

### **Conclusion**
Through systematic threat hunting, I successfully identified the adversary's tactics, techniques, and procedures (TTPs) across the cyber kill chain:

1. **Key Findings**:
   - Initial access was achieved via SSH brute force and remote code execution.
   - Execution relied on command-line tools and LOLBAS.
   - Defense evasion included disabling Windows Defender and clearing event logs.
   - Persistence was maintained via scheduled tasks and registry modifications.
   - C2 was established over DNS, Discord, and encrypted HTTP.

2. **Lessons Learned**:
   - **Visibility**: Comprehensive logging across endpoints, networks, and applications is critical.
   - **Anomaly Detection**: Patterns such as excessive DNS queries or encrypted HTTP traffic can indicate malicious activity.
   - **Defense-in-Depth**: Combine SIEM solutions, endpoint detection and response (EDR), and regular security audits.
