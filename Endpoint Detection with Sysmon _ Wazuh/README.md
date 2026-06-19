
# 🛡️ Endpoint Detection with Sysmon + Wazuh

<div align="center">

![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-blue?style=for-the-badge)
![Sysmon](https://img.shields.io/badge/Sysmon-Endpoint%20Monitoring-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-yellow?style=for-the-badge&logo=python)
![Linux](https://img.shields.io/badge/Linux-Ubuntu%2020.04-orange?style=for-the-badge&logo=linux)
![OpenSearch](https://img.shields.io/badge/OpenSearch-Indexer-green?style=for-the-badge)
![Dashboard](https://img.shields.io/badge/Wazuh-Dashboard-purple?style=for-the-badge)
![XML](https://img.shields.io/badge/XML-Event%20Logs-darkred?style=for-the-badge)
![JSON](https://img.shields.io/badge/JSON-Log%20Analysis-lightgrey?style=for-the-badge)

# 🚨 Endpoint Detection & Response with Wazuh SIEM

### 🔍 Threat Detection • 🛡️ Endpoint Monitoring • 📊 SIEM Analytics • ⚡ Security Automation

</div>

---

# 📖 Overview

This hands-on cybersecurity lab introduces students to **Endpoint Detection and Response (EDR)** using **Wazuh SIEM** and **Sysmon Event Analysis**.

Students will deploy a complete SIEM infrastructure, simulate Sysmon endpoint telemetry, create custom detection rules and decoders, and build Python-based automation tools for threat detection and log analysis.

The lab demonstrates how modern Security Operations Centers (SOCs) detect malicious activity through endpoint monitoring and SIEM correlation.

---

# 🎯 Learning Objectives

By the end of this lab, students will be able to:

✅ Install and configure Wazuh SIEM

✅ Deploy Wazuh Manager, Indexer, and Dashboard

✅ Simulate Sysmon event logging on Linux

✅ Create custom Wazuh decoders

✅ Build custom Wazuh detection rules

✅ Develop Python log parsing tools

✅ Generate custom security alerts

✅ Implement threat detection workflows

✅ Perform endpoint threat analysis

---

# 🧰 Technology Stack

| Category | Technologies |
|-----------|-------------|
| SIEM Platform | Wazuh |
| Endpoint Monitoring | Sysmon |
| Search Engine | OpenSearch |
| Dashboard | Wazuh Dashboard |
| Programming | Python 3.x |
| Log Format | XML |
| Alert Format | JSON |
| Operating System | Ubuntu 20.04 |
| Security Monitoring | Endpoint Detection |
| Threat Analytics | Wazuh Rules Engine |

---

# 📚 Prerequisites

Before beginning this lab, ensure you have:

### 💻 Linux Knowledge

- Linux command-line proficiency
- File permissions
- Service management

### 📊 SIEM Fundamentals

- Log collection concepts
- Event correlation
- Threat detection workflows

### 📄 Data Formats

- XML structure
- JSON parsing

### 🐍 Programming Skills

- Python fundamentals
- Functions and classes
- File handling

### 🔐 Security Knowledge

- Windows Event Logging
- Endpoint monitoring
- Threat detection basics

---

# 🖥️ Lab Environment

## ☁️ Al Nafi Cloud Machine

### Environment Specifications

| Resource | Configuration |
|-----------|--------------|
| Operating System | Ubuntu 20.04 LTS |
| RAM | 4 GB |
| Storage | 20 GB |
| Access | Root Privileges |
| Network | Internet Enabled |

---

# 🚀 Task 1: Install and Configure Wazuh SIEM

---

## ⚙️ Step 1.1: Install Wazuh Manager

```bash
# Create lab directory structure
mkdir -p ~/endpoint-lab/{logs,scripts,configs}

cd ~/endpoint-lab

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
gpg --no-default-keyring \
--keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
--import

sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" \
| sudo tee /etc/apt/sources.list.d/wazuh.list

# Install Manager
sudo apt update

sudo apt install -y wazuh-manager

# Start Service
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

sudo systemctl status wazuh-manager
```

### 🎯 Purpose

Install the central Wazuh Manager responsible for event processing and alert generation.

---

## 🔍 Step 1.2: Install Wazuh Indexer

```bash
sudo apt install -y wazuh-indexer

sudo tee /etc/wazuh-indexer/opensearch.yml > /dev/null <<EOF
network.host: 127.0.0.1
node.name: node-1
cluster.initial_master_nodes: ["node-1"]
cluster.name: wazuh-cluster
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer
EOF

sudo systemctl enable wazuh-indexer
sudo systemctl start wazuh-indexer
```

### 🎯 Purpose

Deploy OpenSearch-based indexing services for event storage and searching.

---

## 📊 Step 1.3: Install Wazuh Dashboard

```bash
sudo apt install -y wazuh-dashboard

sudo tee /etc/wazuh-dashboard/opensearch_dashboards.yml > /dev/null <<EOF
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: ["http://127.0.0.1:9200"]
opensearch.ssl.verificationMode: none
EOF

sudo systemctl enable wazuh-dashboard
sudo systemctl start wazuh-dashboard
```

Access Dashboard:

```text
http://YOUR_IP:5601
```

---

## 🖥️ Step 1.4: Configure Local Wazuh Agent

```bash
sudo apt install -y wazuh-agent

sudo sed -i \
's|<address>.*</address>|<address>127.0.0.1</address>|' \
/var/ossec/etc/ossec.conf

sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

sudo /var/ossec/bin/agent_control -l
```

---

# 🚀 Task 2: Simulate Sysmon Events

---

## 📄 Step 2.1: Create Sysmon Event Simulator

### File: `~/endpoint-lab/logs/sysmon-events.xml`

```xml
<Events>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon"/>
<EventID>1</EventID>
<TimeCreated SystemTime="2024-01-15T10:30:45.123Z"/>
<Computer>LAB-ENDPOINT-01</Computer>
<EventRecordID>12345</EventRecordID>
</System>

<EventData>
<Data Name="Image">C:\Windows\System32\cmd.exe</Data>
<Data Name="CommandLine">cmd.exe /c whoami</Data>
<Data Name="User">LAB\Administrator</Data>
<Data Name="ProcessId">4567</Data>
<Data Name="ParentImage">C:\Windows\explorer.exe</Data>
</EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon"/>
<EventID>3</EventID>
<TimeCreated SystemTime="2024-01-15T10:31:12.456Z"/>
<Computer>LAB-ENDPOINT-01</Computer>
<EventRecordID>12346</EventRecordID>
</System>

<EventData>
<Data Name="Image">C:\Windows\System32\powershell.exe</Data>
<Data Name="DestinationIp">192.168.1.100</Data>
<Data Name="DestinationPort">4444</Data>
<Data Name="Protocol">tcp</Data>
</EventData>
</Event>

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon"/>
<EventID>11</EventID>
<TimeCreated SystemTime="2024-01-15T10:32:30.789Z"/>
<Computer>LAB-ENDPOINT-01</Computer>
<EventRecordID>12347</EventRecordID>
</System>

<EventData>
<Data Name="Image">C:\Windows\System32\cmd.exe</Data>
<Data Name="TargetFilename">
C:\Users\Admin\AppData\Local\Temp\malware.exe
</Data>
</EventData>
</Event>

</Events>
```

---

## 📥 Step 2.2: Configure Log Collection

```bash
sudo tee -a /var/ossec/etc/ossec.conf > /dev/null <<EOF

<localfile>
  <log_format>syslog</log_format>
  <location>/home/$(whoami)/endpoint-lab/logs/sysmon-events.xml</location>
</localfile>

EOF

sudo systemctl restart wazuh-manager
```

---

# 🚀 Task 3: Create Custom Wazuh Rules and Decoders

---

## 🔎 Step 3.1: Create Sysmon Decoders

### File: `/var/ossec/etc/decoders/local_sysmon_decoders.xml`

```xml
<decoder name="sysmon-base">
  <prematch>EventID</prematch>
</decoder>

<decoder name="sysmon-event-id">
  <parent>sysmon-base</parent>
  <regex offset="after_prematch">(\d+)</regex>
  <order>sysmon.event_id</order>
</decoder>

<decoder name="sysmon-image">
  <parent>sysmon-base</parent>
  <regex>Image>([^<]+)</regex>
  <order>sysmon.image</order>
</decoder>

<decoder name="sysmon-commandline">
  <parent>sysmon-base</parent>
  <regex>CommandLine>([^<]+)</regex>
  <order>sysmon.commandline</order>
</decoder>

<decoder name="sysmon-network">
  <parent>sysmon-base</parent>
  <regex>DestinationIp>(\S+)</regex>
  <order>sysmon.dst_ip</order>
</decoder>

<decoder name="sysmon-port">
  <parent>sysmon-base</parent>
  <regex>DestinationPort>(\d+)</regex>
  <order>sysmon.dst_port</order>
</decoder>
```

---

## 🚨 Step 3.2: Create Custom Detection Rules

### File: `/var/ossec/etc/rules/local_sysmon_rules.xml`

```xml
<group name="sysmon,endpoint_detection,">

<rule id="100001" level="3">
<decoded_as>sysmon-base</decoded_as>
<description>Sysmon event detected</description>
</rule>

<rule id="100002" level="5">
<if_sid>100001</if_sid>
<field name="sysmon.event_id">1</field>
<description>Process creation detected</description>
<group>process_creation,</group>
</rule>

<rule id="100003" level="10">
<if_sid>100002</if_sid>
<field name="sysmon.image">
cmd.exe|powershell.exe|wscript.exe
</field>
<description>Suspicious process execution</description>
<group>suspicious_process,</group>
</rule>

<rule id="100005" level="12">
<if_sid>100004</if_sid>
<field name="sysmon.dst_port">
4444|5555|6666|7777
</field>
<description>
Connection to suspicious port
</description>
<group>suspicious_network,</group>
</rule>

</group>
```

Restart:

```bash
sudo systemctl restart wazuh-manager
```

---

## 🧪 Step 3.3: Test Rule Detection

```bash
cat >> ~/endpoint-lab/logs/sysmon-events.xml <<'EOF'

<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon"/>
<EventID>3</EventID>
<TimeCreated SystemTime="2024-01-15T11:00:00.000Z"/>
<Computer>LAB-ENDPOINT-01</Computer>
</System>

<EventData>
<Data Name="Image">C:\Windows\System32\powershell.exe</Data>
<Data Name="DestinationIp">10.0.0.50</Data>
<Data Name="DestinationPort">4444</Data>
</EventData>

</Event>

EOF
```

Monitor alerts:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
```

---

# 🚀 Task 4: Develop Python Log Parser

---

## 🐍 Step 4.1: Create Sysmon Parser

### File: `~/endpoint-lab/scripts/sysmon_parser.py`

```python
#!/usr/bin/env python3

"""
Sysmon Log Parser for Wazuh Integration

Students Complete TODO Sections
"""

import xml.etree.ElementTree as ET
import json
import sys
from datetime import datetime

class SysmonParser:

    def __init__(self, log_file):

        self.log_file = log_file
        self.events = []
        self.alerts = []

    def parse_events(self):

        # TODO:
        # Parse XML Events

        pass

    def extract_event_data(self, event_element):

        event_data = {

            "event_id": None,
            "timestamp": None,
            "computer": None,
            "data": {}

        }

        # TODO:
        # Extract event details

        return event_data

    def analyze_process_creation(self, event):

        alerts = []

        # TODO:
        # Detect suspicious processes

        return alerts

    def analyze_network_connection(self, event):

        alerts = []

        suspicious_ports = [
            4444,
            5555,
            6666,
            7777,
            8888
        ]

        # TODO:
        # Detect suspicious ports

        return alerts

    def analyze_file_creation(self, event):

        alerts = []

        # TODO:
        # Detect suspicious files

        return alerts

    def generate_report(self):

        report = {

            "timestamp":
            datetime.now().isoformat(),

            "events":
            self.events,

            "alerts":
            self.alerts

        }

        return report
```

Make executable:

```bash
chmod +x ~/endpoint-lab/scripts/sysmon_parser.py
```

---

## 🚨 Step 4.2: Create Wazuh Alert Generator

### File: `~/endpoint-lab/scripts/wazuh_alert_sender.py`

```python
#!/usr/bin/env python3

"""
Wazuh Alert Generator

Students Complete TODO Sections
"""

import json
import socket

class WazuhAlertSender:

    def __init__(
        self,
        manager_ip='127.0.0.1',
        manager_port=1514
    ):

        self.manager_ip = manager_ip
        self.manager_port = manager_port

    def create_alert(
        self,
        rule_id,
        level,
        description,
        data
    ):

        alert = {

            "rule_id": rule_id,
            "level": level,
            "description": description,
            "data": data

        }

        # TODO:
        # Format alert

        return json.dumps(alert)

    def send_alert(self, alert):

        # TODO:
        # Send alert to manager

        pass

def main():

    sender = WazuhAlertSender()

    # TODO:
    # Create sample alert

if __name__ == "__main__":
    main()
```

---

## 🧪 Step 4.3: Test Parser

```bash
python3 \
~/endpoint-lab/scripts/sysmon_parser.py \
~/endpoint-lab/logs/sysmon-events.xml \
~/endpoint-lab/logs/analysis-report.json
```

View results:

```bash
cat \
~/endpoint-lab/logs/analysis-report.json \
| jq '.'
```

---

# 🏆 Expected Outcomes

After completing this lab, you should have:

✅ Functional Wazuh Manager

✅ Running Wazuh Indexer

✅ Operational Wazuh Dashboard

✅ Working Sysmon Event Simulation

✅ Custom Wazuh Rules

✅ Custom Decoders

✅ Python Log Analysis Tool

✅ Alert Generation Workflow

✅ Endpoint Threat Detection Dashboard

---

# 🔧 Verification Steps

### Verify Services

```bash
sudo systemctl status \
wazuh-manager \
wazuh-indexer \
wazuh-dashboard
```

### View Alerts

```bash
sudo tail -f \
/var/ossec/logs/alerts/alerts.log
```

### Dashboard

```text
http://YOUR_IP:5601
```

### Test Custom Rules

Append additional events and monitor generated alerts.

---

# 🛠️ Troubleshooting Guide

---

## ❌ Wazuh Manager Not Starting

```bash
sudo tail -f /var/ossec/logs/ossec.log
```

```bash
sudo /var/ossec/bin/wazuh-control info
```

```bash
df -h
```

---

## ❌ Rules Not Triggering

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Check:

```bash
ls -la ~/endpoint-lab/logs/
```

Restart:

```bash
sudo systemctl restart wazuh-manager
```

---

## ❌ Dashboard Not Accessible

```bash
sudo ufw status
```

```bash
sudo systemctl status wazuh-dashboard
```

```bash
sudo netstat -tlnp | grep 5601
```

---

## ❌ Python Script Errors

Verify Version:

```bash
python3 --version
```

Expected:

```text
Python 3.6+
```

Install Missing Packages:

```bash
pip3 install <module_name>
```

---

# 🎓 Skills Gained

By completing this lab you learned how to:

🛡️ Deploy Enterprise SIEM Infrastructure

🔍 Simulate Sysmon Endpoint Telemetry

📊 Create Wazuh Detection Rules

⚡ Build Security Decoders

🐍 Develop Log Analysis Tools

🚨 Generate Custom Security Alerts

📈 Visualize Endpoint Threats

🔐 Implement Threat Detection Workflows

---

# 🚀 Next Steps

### Advanced Challenges

- 🔥 Add Additional Sysmon Event IDs
- 🔥 Integrate Threat Intelligence Feeds
- 🔥 Create Automated Response Actions
- 🔥 Build SOC Dashboards
- 🔥 Add MITRE ATT&CK Mapping
- 🔥 Create Detection Playbooks
- 🔥 Implement Threat Scoring
- 🔥 Build Custom Correlation Rules

---

# 📚 Additional Resources

### Wazuh Documentation

https://documentation.wazuh.com

### Sysmon Configuration

https://github.com/SwiftOnSecurity/sysmon-config

### MITRE ATT&CK Framework

https://attack.mitre.org

---

# 📜 Conclusion

This lab provided hands-on experience with Endpoint Detection and Response using Wazuh SIEM and simulated Sysmon telemetry. Students learned how to deploy a complete SIEM stack, create custom detection logic, analyze endpoint events, and automate security monitoring workflows.

The skills developed in this lab mirror real-world SOC analyst, detection engineer, and security operations responsibilities.

---

<div align="center">

### 🛡️ Monitor • Detect • Analyze • Respond

# 🚨 Endpoint Detection with Sysmon + Wazuh

⭐ Happy Threat Hunting! ⭐

</div>
````
