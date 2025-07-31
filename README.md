# ThreatHunting-Foothold
ThreatHunting: Foothold - analyzing Initial Access, Execution, Defense Evasion, Persistence, and C2 tactics using ELK and MITRE ATT&amp;CK.

By Ramyar Daneshgar 

---

This writeup details my step-by-step threat-hunting process in detecting and analyzing adversarial activities across the **cyber kill chain**. Using Kibana and the Elastic Stack (ELK), I investigated logs to identify and mitigate Indicators of Compromise (IoCs). Each phase follows structured cybersecurity methodologies to uncover malicious behaviors while emphasizing how attackers bypass defenses.

---

## **Environment Setup**
The lab setup included:

1. **Host Systems:**
   - **JUMPHOST**: Ubuntu bastion server facilitating internal network access.
   - **WEB01**: Publicly accessible Ubuntu web server.
   - **WKSTN-1** and **WKSTN-2**: Employee Windows 10 workstations.
   - **DC01**: Windows Server 2019 domain controller.

2. **ELK Stack:**
   - Indices:
     - `filebeat-*`: Logs from Linux hosts.
     - `winlogbeat-*`: Windows event logs.
     - `packetbeat-*`: Network traffic logs.

3. **Credentials for Analysis**:
   - URL: `http://<MACHINE_IP>`
   - Username: `elastic`
   - Password: `elastic`

---

## **Investigation Breakdown by MITRE Tactics**

---

### **1. Initial Access (MITRE: TA0001)**

#### **Objective:** Identify the adversary's methods of gaining entry into the network.

#### **Scenario 1: Brute-Force via SSH**
1. **Reconnaissance**: Using the `filebeat-*` index, I analyzed authentication logs on the **JUMPHOST** server:
   ```kql
   host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Failed
   ```
   - **Finding**: Over 500 failed SSH login attempts from two IP addresses.

2. **Successful Authentication**: Narrowing the query to find a successful login:
   ```kql
   host.name: jumphost AND event.category: authentication AND system.auth.ssh.event: Accepted AND source.ip: (167.71.198.43 OR 218.92.0.115)
   ```
   - **Outcome**: The attacker successfully accessed the **JUMPHOST** server on **Jul 3, 2023 @ 14:14:09.000**, using the **dev** account.

---

#### **Scenario 2: Remote Code Execution on WEB01**
1. **Network Analysis**: Using the `packetbeat-*` index, I monitored HTTP traffic to the **WEB01** server:
   ```kql
   host.name: web01 AND network.protocol: http AND destination.port: 80
   ```
   - **Finding**: The attacker conducted directory enumeration using **Gobuster**, generating multiple 404 responses.

2. **Exploit Discovery**: Querying for valid HTTP responses:
   ```kql
   host.name: web01 AND network.protocol: http AND destination.port: 80 AND http.response.status_code: (200 OR 301 OR 302)
   ```
   - **Outcome**: After identifying the `/gila` directory, the attacker injected PHP code via the **User-Agent** header to execute remote commands and accessed sensitive files, including `config.php`.

---

### **2. Execution (MITRE: TA0002)**

#### **Objective:** Uncover how malicious commands were executed post-initial access.

#### **Scenario 1: Abuse of Command-Line Tools**
1. **Process Investigation**: Using the `winlogbeat-*` index, I focused on `powershell.exe` and `cmd.exe` executions:
   ```kql
   host.name: WKSTN-* AND winlog.event_id: 1 AND process.name: (cmd.exe OR powershell.exe)
   ```
   - **Finding**: 
     - `cmd.exe` was spawned by `C:\Windows\Temp\installer.exe`.
     - The first command executed was `whoami /priv`.

#### **Scenario 2: Living Off the Land (LOLBAS)**
1. **LOLBAS Investigation**: Examined suspicious binaries (`certutil.exe`, `mshta.exe`, `regsvr32.exe`):
   ```kql
   host.name: WKSTN-* AND winlog.event_id: (1 OR 3) AND process.name: (mshta.exe OR certutil.exe OR regsvr32.exe)
   ```
   - **Finding**: 
     - `certutil.exe` downloaded the payload `installer.exe`.
     - `mshta.exe` executed encoded PowerShell commands.

---

### **3. Defense Evasion (MITRE: TA0005)**

#### **Objective:** Analyze techniques used to avoid detection.

#### **Scenario 1: Disabling Security Software**
1. **Defender Tampering**: Searched for commands disabling Windows Defender:
   ```kql
   host.name: WKSTN-* AND (*DisableRealtimeMonitoring* OR *RemoveDefinitions*)
   ```
   - **Finding**: 
     - `Set-MpPreference` disabled real-time monitoring.
     - `MpCmdRun.exe` removed Defender definitions.

#### **Scenario 2: Log Deletion**
1. **Log Analysis**: Queried for event logs cleared:
   ```kql
   host.name: WKSTN-* AND winlog.event_id: 1102
   ```
   - **Outcome**: Logs on **WKSTN-1** were cleared to hinder detection.

---

### **4. Persistence (MITRE: TA0003)**

#### **Objective:** Identify mechanisms ensuring continued adversary access.

#### **Scenario 1: Scheduled Tasks**
1. **Task Investigation**: Queried for scheduled task creation:
   ```kql
   host.name: WKSTN-* AND winlog.event_id: 4698
   ```
   - **Finding**: A malicious task named **Windows Update** was scheduled to execute PowerShell commands every minute.

#### **Scenario 2: Registry Modifications**
1. **Registry Analysis**: Focused on autorun registry keys:
   ```kql
   host.name: WKSTN-* AND winlog.event_id: 13 AND registry.path: (*CurrentVersion\\Run* OR *CurrentVersion\\Explorer\\Shell*)
   ```
   - **Outcome**: A registry key was created to execute `C:\Windows\Temp\installer.exe` on startup.

---

### **5. Command and Control (MITRE: TA0011)**

#### **Objective:** Uncover methods used for ongoing communication with compromised hosts.

#### **Scenario 1: DNS-Based C2**
1. **DNS Query Analysis**:
   ```kql
   network.protocol: dns AND NOT dns.question.name: *arpa
   ```
   - **Finding**: Over 2000 DNS queries to **golge.xyz** from `167.71.198.43`, using subdomains for data exchange.

#### **Scenario 2: Discord C2**
1. **Cloud Application Traffic**:
   ```kql
   host.name: WKSTN-1* AND *discord.gg*
   ```
   - **Finding**: `installer.exe` communicated with Discord for C2.

#### **Scenario 3: Encrypted HTTP Traffic**
1. **HTTP Traffic Analysis**:
   ```kql
   network.protocol: http AND network.direction: egress
   ```
   - **Outcome**: Frequent GET requests to **cdn.golge.xyz** indicated a custom C2 server.

---

### **Lessons Learned**
1. **Key Indicators**:
   - Brute-force attempts and directory enumeration highlight the importance of intrusion detection systems.
   - Misuse of built-in tools like PowerShell and certutil underscores the need for monitoring LOLBAS.

2. **Defensive Measures**:
   - Enable endpoint detection and response (EDR) for command-line activities.
   - Implement DNS filtering to detect suspicious subdomains.
   - Regularly audit scheduled tasks and registry keys for unauthorized changes.

3. **Proactive Threat Hunting**:
   - Leverage SIEM tools like ELK for log correlation.
   - Prioritize high-value systems (JUMPHOST, DC01) for anomaly detection.
   - Adopt a defense-in-depth strategy to minimize attack vectors.
