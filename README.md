# Table of Contents

- [**🚀 1. Introduction and Preparation**](#1-introduction-and-preparation)
- [**📊 2. Data Collection**](#2-data-collection)
- [**⏳ 3. Timeline Summary and Findings**](#3-timeline-summary-and-findings)
  - [3.1 Initial Detection of Failed Connection Requests](#31-initial-detection-of-failed-connection-requests)
  - [3.2 Confirmation of Port Scanning Activity](#32-confirmation-of-port-scanning-activity)
  - [3.3 Investigation of Process Events](#33-investigation-of-process-events)
  - [3.4 Response and Mitigation](#34-response-and-mitigation)
- [**🕵️‍♂️ 4. Investigation Conclusion**](#4-investigation-conclusion)
- [**🛡️ 5. Summary of MITRE ATT&CK Techniques**](#5-summary-of-mitre-attck-techniques)

# 1. Introduction and Preparation

**Goal:** The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

**Activity:** All traffic originating from within the local network is by default allowed by all hosts. There is also unrestricted use of PowerShell and other applications in the environment. It’s possible someone is either downloading large files or doing some kind of port scanning against hosts in the local network.

---

# 2. Data Collection

**Goal:** Gather relevant data from logs, network traffic, and endpoints.

**Activity:** Ensure data is available from all key sources for analysis.

<img src="https://i.imgur.com/DI5aV2j.png" alt="None">

**KQL Query Used:**

```
DeviceNetworkEvents
| order by Timestamp desc
| take 10
DeviceFileEvents
| order by Timestamp desc
| take 10
DeviceProcessEvents
| order by Timestamp desc
| take 10
```

# 3. Timeline Summary and Findings

## 3.1 Initial Detection of Failed Connection Requests

‘lab-test’ machine was observed failing multiple connection requests.

<img src="https://i.imgur.com/v7lxgGE.png">

**KQL Query Used:**

```
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount
```

## 3.2 Confirmation of Port Scanning Activity

After observing failed connection requests from a suspected host (10.0.0.133) in chronological order, I noticed a port scan was taking place due to the sequential order of the ports. There were several port scans being conducted.

<img src="https://i.imgur.com/tF5DXty.png">

**KQL Query Used:**

```
let IPInQuestion = "10.0.0.133";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```

Additionally, it's important to note that the ports being scanned are all common ones—such as 21 (FTP), 22 (SSH), 23 (Telnet), and 80 (HTTP)—which further supports the theory of a port scan in progress.


## 3.3 Investigation of Process Events

I switched to the DeviceProcessEvents table to look for any unusual activity that might correlate with the start of the port scan.

I will accomplish this by copying the timestamp value of the first port scan activity observed and running the following KQL query to identify any process events that were initiated 10 minutes before and after that timestamp.

**KQL Query Used:**

```
let VMName = "lab-test";
let specificTime = datetime(2025-04-10T04:38:12.8844267Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```

<img src="https://i.imgur.com/VgSUufh.png">

This revealed that a PowerShell script named portscan.ps1 was executed at 2025-04-10T04:37:37.1050094Z (04:37 AM on 10 April 2025).

## 3.4 Response and Mitigation

I observed that the port scan script was launched by the SYSTEM account, which is unusual and not something configured by the administrators. As a precaution, I isolated the device and ran a malware scan. Although the scan came back clean, I decided to keep the device isolated and raised a ticket to have it re-imaged.

<img src="https://i.imgur.com/bqmkw4L.png">

**KQL Query Used:**

```
let VMName = "lab-test";
let specificTime = datetime(2025-04-10T04:38:12.8844267Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```

---

# 4. Investigation Conclusion

This lab investigated network performance degradation on devices within the 10.0.0.0/16 network, suspected to be due to internal activity. Initial data collection involved querying DeviceNetworkEvents, DeviceFileEvents, and DeviceProcessEvents to gather logs. Analysis revealed that the lab-test machine (IP 10.0.0.133) was conducting a port scan, identified by multiple failed connection requests to common ports (e.g., 21, 22, 80). A PowerShell script, portscan.ps1, initiated the scan at 04:37:37 on 10 April 2025, executed by the SYSTEM account—an unauthorised action. The unrestricted use of PowerShell in the environment likely enabled this network performance degradation. The device was isolated, a malware scan (which returned clean) was conducted, and a ticket was raised for re-imaging to mitigate risks. This incident highlights the need for stricter internal network controls and application restrictions.

---

# 5. Summary of MITRE ATT&CK Techniques

| Tactic                        | Technique                                | Sub-Technique                           | Description                                                                 |
|-------------------------------|------------------------------------------|-----------------------------------------|-----------------------------------------------------------------------------|
| Reconnaissance               | T1595 - Active Scanning                 | T1595.002 - Scanning IP Blocks          | Port scanning of common ports (21, 22, 80) to identify services on target hosts. |
| Execution                    | T1059 - Command and Scripting Interpreter| T1059.001 - PowerShell                  | Execution of portscan.ps1 via PowerShell to perform the port scan.          |
| Privilege Escalation / Initial Access | T1078 - Valid Accounts                  | T1078.002 - Domain Accounts (SYSTEM)    | Misuse of the SYSTEM account to execute the script, indicating potential compromise. |
| Command and Control          | T1046 - Network Service Discovery        | None                                    | Scanning to discover network services on target hosts.                      |
| Persistence / Defence Evasion| T1053 - Scheduled Task/Job              | None                                    | Potential use of a scheduled task to execute the script (requires confirmation). |
| Impact                       | T1499 - Endpoint Denial of Service       | T1499.004 - Application or System Exploitation | Network performance degradation due to scanning activity.                   |
