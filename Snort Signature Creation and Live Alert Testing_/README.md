# 🛡️ Snort Signature Creation & Live Alert Testing

<div align="center">

![Snort](https://img.shields.io/badge/Snort-3.x-red?style=for-the-badge&logo=securityscorecard)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Generation-green?style=for-the-badge)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04-orange?style=for-the-badge&logo=ubuntu)
![Linux](https://img.shields.io/badge/Linux-Security-black?style=for-the-badge&logo=linux)
![Networking](https://img.shields.io/badge/Network-Intrusion%20Detection-purple?style=for-the-badge)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-IDS%20Engineering-darkred?style=for-the-badge)

# 🚨 Advanced Threat Detection with Snort IDS

### 🎯 Custom Signature Development • 📡 Live Traffic Analysis • 🧪 Automated Alert Testing

</div>

---

# 📖 Overview

This hands-on cybersecurity lab introduces students to the fundamentals of **Intrusion Detection System (IDS) engineering** using **Snort 3.x**. Participants will design custom detection signatures, generate attack traffic using Python and Scapy, analyze generated alerts, and validate the effectiveness of security monitoring rules.

The lab simulates real-world Security Operations Center (SOC) workflows where security analysts continuously develop, test, tune, and validate detection mechanisms against evolving threats.

---

# 🎯 Learning Objectives

By the end of this lab, students will be able to:

✅ Understand Snort rule syntax and structure

✅ Create custom Snort signatures for detecting network threats

✅ Configure Snort for real-time intrusion detection

✅ Generate attack traffic using Scapy

✅ Analyze Snort alert logs

✅ Validate detection effectiveness

✅ Optimize IDS signatures for performance and accuracy

✅ Automate testing and analysis workflows using Python

---

# 🧰 Technology Stack

| Category | Technologies |
|-----------|-------------|
| IDS Engine | Snort 3.x |
| Operating System | Ubuntu 22.04 |
| Programming Language | Python 3.x |
| Packet Crafting | Scapy |
| Network Analysis | TCP/IP |
| Security Monitoring | IDS Detection |
| Traffic Testing | Curl, Nmap |
| Logging & Analysis | Snort Alert Logs |
| Scripting | Bash |
| Regex Processing | Python Regex |

---

# 📚 Prerequisites

Before beginning this lab, ensure you have:

### 🌐 Networking Knowledge
- TCP/IP fundamentals
- Common protocols (HTTP, DNS, TCP, UDP)

### 💻 Linux Skills
- Basic command-line navigation
- File editing
- Service management

### 🔐 Security Fundamentals
- SQL Injection
- Cross-Site Scripting (XSS)
- Port Scanning
- Command Injection

### 🐍 Programming Knowledge
- Basic Python programming
- Functions and loops
- File handling
- Regular expressions

---

# 🖥️ Lab Environment

## ☁️ Al Nafi Cloud Machine

Your environment comes preconfigured with:

### ✅ Installed Components

- Snort 3.x
- Python 3.x
- Scapy Library
- Root Access
- Ubuntu 22.04

---

# 🚀 Task 1: Create Custom Snort Signatures

---

## 🛠️ Step 1: Create Custom Rules Directory

```bash
# Create custom rules directory
sudo mkdir -p /etc/snort/rules/custom
sudo chmod 755 /etc/snort/rules/custom

# Create custom rules file
sudo nano /etc/snort/rules/custom/lab9_custom.rules
```

### 🎯 Purpose

Create a dedicated location for custom IDS signatures.

---

## 📖 Step 2: Understand Snort Rule Structure

```snort
# Snort Rule Structure:
# action protocol src_ip src_port direction dst_ip dst_port (rule options)

# Actions:
# alert, log, pass, drop, reject

# Protocols:
# tcp, udp, icmp, ip

# Directions:
# ->  (unidirectional)
# <>  (bidirectional)

# Example Rule
alert tcp any any -> any 80 (msg:"HTTP Traffic Detected"; sid:1000001; rev:1;)
```

### 🔍 Rule Components

| Component | Description |
|------------|------------|
| alert | Action to perform |
| tcp | Protocol |
| any any | Source IP/Port |
| -> | Traffic direction |
| any 80 | Destination IP/Port |
| msg | Alert message |
| sid | Signature ID |
| rev | Rule revision |

---

## 🕵️ Step 3: Create Web Attack Signatures

### 💉 SQL Injection Detection

```snort
alert tcp any any -> any 80 (msg:"SQL Injection - UNION SELECT"; content:"union select"; nocase; sid:1000002; rev:1; classtype:web-application-attack;)

alert tcp any any -> any 80 (msg:"SQL Injection - OR 1=1"; content:"or 1=1"; nocase; sid:1000003; rev:1; classtype:web-application-attack;)
```

---

### 🎭 Cross-Site Scripting (XSS)

```snort
alert tcp any any -> any 80 (msg:"XSS - Script Tag"; content:"<script"; nocase; sid:1000004; rev:1; classtype:web-application-attack;)

alert tcp any any -> any 80 (msg:"XSS - JavaScript Alert"; content:"javascript:alert"; nocase; sid:1000005; rev:1; classtype:web-application-attack;)
```

---

### 💀 Command Injection Detection

```snort
alert tcp any any -> any any (msg:"Command Injection - Cat"; content:"|3B|cat"; sid:1000006; rev:1; classtype:web-application-attack;)

alert tcp any any -> any any (msg:"Command Injection - Wget"; content:"wget"; nocase; sid:1000007; rev:1; classtype:trojan-activity;)
```

---

## 🌐 Step 4: Create Network Reconnaissance Signatures

### 🔍 Port Scan Detection

```snort
alert tcp any any -> any any (msg:"Possible Port Scan"; flags:S; threshold:type both, track by_src, count 10, seconds 60; sid:1000008; rev:1; classtype:attempted-recon;)
```

### 📡 Nmap Detection

```snort
alert tcp any any -> any any (msg:"Nmap TCP Scan"; flags:S; window:1024; sid:1000009; rev:1; classtype:attempted-recon;)
```

### 🌍 Suspicious DNS Activity

```snort
alert udp any any -> any 53 (msg:"Large DNS Query"; dsize:>100; sid:1000010; rev:1; classtype:policy-violation;)
```

---

## 🔥 Step 5: Create Advanced Detection Rules

### 🕵️ Suspicious User-Agent

```snort
alert tcp any any -> any 80 (msg:"Suspicious User-Agent - Wget"; content:"User-Agent|3A| Wget"; nocase; sid:1000011; rev:1; classtype:policy-violation;)
```

### 📦 Large Data Transfer

```snort
alert tcp any any -> any any (msg:"Large Data Transfer"; dsize:>10000; threshold:type both, track by_src, count 5, seconds 60; sid:1000012; rev:1; classtype:policy-violation;)
```

### 💳 Credit Card Detection

```snort
alert tcp any any -> any 80 (msg:"Credit Card Pattern"; pcre:"/\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}/"; sid:1000013; rev:1; classtype:policy-violation;)
```

---

## ⚙️ Step 6: Configure Snort

```bash
sudo nano /etc/snort/snort.conf
```

Add:

```snort
include /etc/snort/rules/custom/lab9_custom.rules
```

---

# 🚀 Task 2: Test Signatures with Automated Packet Generation

---

## 🐍 Step 1: Create Scapy Packet Generator

### 📄 File: `packet_generator.py`

```python
#!/usr/bin/env python3

from scapy.all import *
import time
import random

class SnortTestGenerator:

    def __init__(self, target_ip="127.0.0.1", interface="lo"):
        self.target_ip = target_ip
        self.interface = interface
        self.src_ip = "192.168.1.100"

    def generate_sql_injection(self):
        """
        Generate SQL injection packets.
        """
        pass

    def generate_xss_attacks(self):
        """
        Generate XSS packets.
        """
        pass

    def generate_port_scan(self):
        """
        Generate SYN scan packets.
        """
        pass

    def generate_suspicious_dns(self):
        """
        Generate DNS attack traffic.
        """
        pass

    def run_all_tests(self):
        """
        Execute all tests.
        """
        pass

def main():
    pass

if __name__ == "__main__":
    main()
```

---

## 📊 Step 2: Create Alert Analysis Tool

### 📄 File: `analyze_alerts.py`

```python
#!/usr/bin/env python3

import re
from collections import defaultdict

def parse_snort_alerts(alert_file):

    alerts = []

    # TODO:
    # Parse timestamps
    # Extract SIDs
    # Extract source/destination IPs

    return alerts

def analyze_alerts(alerts):

    # TODO:
    # Count detections
    # Identify top sources
    # Generate statistics

    pass

def main():

    alert_file = "/var/log/snort/alert"

    pass

if __name__ == "__main__":
    main()
```

---

## ▶️ Step 3: Run Detection Tests

### Terminal 1

```bash
sudo snort -A console -q \
-c /etc/snort/snort.conf \
-i lo \
-l /var/log/snort
```

---

### Terminal 2

```bash
sudo python3 ~/packet_generator.py
```

---

### Terminal 3

```bash
sudo tail -f /var/log/snort/alert
```

---

## 📈 Step 4: Analyze Results

```bash
python3 ~/analyze_alerts.py
```

```bash
sudo cat /var/log/snort/alert | less
```

---

# 🚀 Task 3: Validate & Optimize Signatures

---

## 🎯 Step 1: Test Individual Rules

### 📄 File: `test_single_rule.sh`

```bash
#!/bin/bash

TEST_TYPE=$1

case $TEST_TYPE in

sql)
curl "http://127.0.0.1:8080/search?id=' OR 1=1--"
;;

xss)
curl "http://127.0.0.1:8080/comment?msg=<script>alert('XSS')</script>"
;;

scan)
nmap -sS 127.0.0.1 -p 1-100
;;

*)
echo "Usage: $0 {sql|xss|scan}"
;;

esac
```

---

## 📏 Step 2: Measure Detection Rates

### 📄 File: `measure_detection.py`

```python
#!/usr/bin/env python3

def count_alerts_by_sid(alert_file, sid):

    # TODO:
    # Parse alert file
    # Count SID occurrences

    pass

def calculate_detection_rate(expected, detected):

    # TODO:
    # Calculate percentage
    # Handle divide-by-zero

    pass
```

---

## ⚡ Step 3: Optimize Performance

### Check Overlapping Rules

```bash
sudo snort -c /etc/snort/snort.conf \
--rule-to-text | grep "sid:1000"
```

### Validate Configuration

```bash
sudo snort -T -c /etc/snort/snort.conf
```

### Benchmark Rules

```bash
sudo snort -c /etc/snort/snort.conf \
--pcap-dir /path/to/pcaps \
--pcap-show
```

---

# 🏆 Expected Outcomes

After completing this lab you should have:

✅ 10+ Custom Snort Signatures

✅ SQL Injection Detection Rules

✅ XSS Detection Rules

✅ Port Scan Detection Rules

✅ Automated Traffic Generation Tool

✅ Alert Analysis Framework

✅ Detection Rate Measurements

✅ Rule Validation Experience

✅ IDS Tuning Skills

---

# 🔧 Troubleshooting Guide

---

## ❌ Snort Won't Start

```bash
sudo snort -T -c /etc/snort/snort.conf
```

### Verify

- Configuration syntax
- File permissions
- Duplicate SIDs

---

## ❌ No Alerts Generated

### Verify

- Correct interface
- Rules included
- Matching traffic patterns

### Check Traffic

```bash
tcpdump -i lo
```

---

## ❌ Scapy Permission Errors

### Fix

```bash
sudo python3 packet_generator.py
```

Verify:

- Interface name
- Firewall settings

---

## ❌ Empty Alert File

Verify:

- Log directory exists
- Correct Snort output configuration
- Available disk space

---

# 🎓 Skills Gained

By completing this lab you learned how to:

🛡️ Create custom IDS signatures

📡 Detect real-world network attacks

🐍 Automate attack simulation using Python

🔍 Analyze and validate alerts

⚡ Optimize detection performance

📊 Measure rule effectiveness

🚨 Build practical intrusion detection workflows

---

# 🚀 Next Steps

### Advanced Challenges

- 🔥 Implement Flowbits
- 🔥 Use Byte_Jump Detection
- 🔥 Analyze Public PCAP Datasets
- 🔥 Reduce False Positives
- 🔥 Integrate Snort with SIEM Platforms
- 🔥 Create Threat-Hunting Rules
- 🔥 Build SOC Detection Pipelines

---

# 📜 Conclusion

This lab provided practical experience in **Intrusion Detection System (IDS) Engineering** using Snort. Through custom rule creation, attack simulation, alert analysis, and performance optimization, students gained real-world defensive security skills used by SOC analysts, threat hunters, and blue-team engineers.

The ability to design, test, and validate detection logic is a critical capability for modern cybersecurity professionals and forms the foundation for advanced threat detection and security monitoring operations.

---

<div align="center">

### 🛡️ Detect • Analyze • Validate • Defend

**Snort Signature Creation & Live Alert Testing Lab**

⭐ Happy Hunting! ⭐

</div>
