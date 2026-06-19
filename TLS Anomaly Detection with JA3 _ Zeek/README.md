# 🔐 TLS Anomaly Detection with JA3 + Zeek

<div align="center">

![JA3](https://img.shields.io/badge/JA3-TLS%20Fingerprinting-blue?style=for-the-badge)
![Zeek](https://img.shields.io/badge/Zeek-Network%20Security%20Monitor-green?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.x-yellow?style=for-the-badge&logo=python)
![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04-orange?style=for-the-badge&logo=ubuntu)
![TLS](https://img.shields.io/badge/TLS-Traffic%20Analysis-red?style=for-the-badge)
![Network Security](https://img.shields.io/badge/Network-Security-purple?style=for-the-badge)
![Threat Detection](https://img.shields.io/badge/Threat-Detection-darkred?style=for-the-badge)

# 🛡️ TLS Fingerprinting & Anomaly Detection Engineering

### 🔍 JA3 Analysis • 📡 Zeek Monitoring • 🚨 Automated Alerting

</div>

---

# 📖 Overview

This hands-on cybersecurity lab introduces students to **TLS anomaly detection using JA3 fingerprinting and Zeek Network Security Monitoring**. Participants will learn how to generate JA3 fingerprints, establish baseline TLS behavior, identify anomalous encrypted traffic, and automate detection and alerting workflows using Python.

The lab simulates real-world security monitoring operations where analysts identify suspicious encrypted communications, malware command-and-control (C2) channels, and abnormal TLS activity within enterprise networks.

---

# 🎯 Learning Objectives

By the end of this lab, students will be able to:

✅ Understand JA3 fingerprinting fundamentals

✅ Configure Zeek for TLS monitoring

✅ Implement JA3-based anomaly detection

✅ Create automated Python alerting systems

✅ Analyze TLS traffic patterns

✅ Detect suspicious encrypted communications

✅ Build baseline TLS fingerprints

✅ Generate real-time anomaly alerts

✅ Investigate TLS security threats

---

# 🧰 Technology Stack

| Category | Technologies |
|-----------|-------------|
| Network Monitoring | Zeek |
| TLS Analysis | JA3 Fingerprinting |
| Programming | Python 3.x |
| Operating System | Ubuntu 20.04 LTS |
| Data Analysis | Pandas |
| Numerical Processing | NumPy |
| HTTP Testing | Requests |
| Alerting | JSON Logs |
| Automation | Python Scripts |
| Threat Detection | Anomaly Detection |
| Network Security | TLS Monitoring |
| Logging | Zeek Logs |

---

# 📚 Prerequisites

Before beginning this lab, ensure you have:

### 🌐 Network Security Knowledge

- TLS/SSL fundamentals
- Network monitoring concepts
- Security analysis techniques

### 💻 Linux Skills

- Linux command line proficiency
- File management
- Process monitoring

### 🐍 Programming Knowledge

- Python fundamentals
- Classes and functions
- JSON processing
- File handling

### 📊 Analysis Skills

- Log analysis
- Pattern recognition
- Security event investigation

---

# 🖥️ Lab Environment

## ☁️ Al Nafi Cloud Machine

This lab uses a pre-configured Ubuntu environment with:

### ✅ Resources

- Ubuntu 20.04 LTS
- 4GB RAM
- 20GB Storage
- Root Access
- Internet Connectivity

### ✅ Tools Available

- Python 3.x
- Linux Utilities
- Development Packages

---

# 🚀 Task 1: Implement JA3 Fingerprint Generation

---

## ⚙️ Step 1.1: Install Dependencies & Setup Environment

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install packages
sudo apt install -y python3 python3-pip git curl build-essential

# Install Python libraries
pip3 install pandas numpy requests

# Create working directory
mkdir -p ~/tls-anomaly-lab
cd ~/tls-anomaly-lab
```

### 🎯 Purpose

Prepare the environment for TLS fingerprinting and anomaly detection development.

---

## 🔑 Step 1.2: Create JA3 Generator Class

### 📄 File: `ja3_generator.py`

```python
#!/usr/bin/env python3

import hashlib
import json
from collections import defaultdict

class JA3Generator:

    def __init__(self):
        self.ja3_database = {}
        self.anomaly_threshold = 0.1

    def generate_ja3(
        self,
        tls_version,
        cipher_suites,
        extensions,
        elliptic_curves,
        ec_point_formats
    ):
        """
        Generate JA3 fingerprint.
        """

        # TODO:
        # Convert lists to strings
        # Build JA3 string
        # Generate MD5 hash

        pass

    def load_baseline_ja3(self, baseline_file):
        """
        Load baseline fingerprints.
        """

        # TODO:
        # Load JSON database
        # Handle file errors

        pass

    def update_baseline(self, ja3_hash, metadata):
        """
        Update baseline.
        """

        # TODO:
        # Track fingerprints
        # Update counts

        pass

    def detect_anomaly(self, ja3_hash, metadata):
        """
        Detect anomalies.
        """

        # TODO:
        # Check frequency
        # Compare threshold

        pass

    def save_baseline(self, baseline_file):
        """
        Save baseline.
        """

        # TODO:
        # Export JSON

        pass

if __name__ == "__main__":

    generator = JA3Generator()

    test_tls = {
        'tls_version': 771,
        'cipher_suites': [49195, 49199, 52393, 52392],
        'extensions': [0, 23, 65281, 10, 11],
        'elliptic_curves': [29, 23, 24],
        'ec_point_formats': [0]
    }

    # TODO:
    # Test JA3 generation
```

---

## 🧪 Step 1.3: Test JA3 Implementation

### Make Executable

```bash
chmod +x ~/tls-anomaly-lab/ja3_generator.py
```

### Run Tests

```bash
python3 ja3_generator.py
```

### Verify Baseline

```bash
cat ja3_baseline.json | python3 -m json.tool
```

---

# 🚀 Task 2: Configure Zeek for TLS Monitoring

---

## 📡 Step 2.1: Install Zeek Network Monitor

### Install Dependencies

```bash
sudo apt install -y \
cmake make gcc g++ flex bison \
libpcap-dev libssl-dev \
python3-dev swig zlib1g-dev
```

### Download Zeek

```bash
cd ~/tls-anomaly-lab

wget https://download.zeek.org/zeek-4.2.1.tar.gz

tar -xzf zeek-4.2.1.tar.gz

cd zeek-4.2.1
```

### Build and Install

```bash
./configure --prefix=/opt/zeek

make -j$(nproc)

sudo make install
```

### Configure PATH

```bash
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc

source ~/.bashrc
```

### Verify Installation

```bash
zeek --version
```

---

## 🛠️ Step 2.2: Create Zeek TLS Monitoring Script

### 📄 File: `tls-anomaly.zeek`

```zeek
##! TLS Anomaly Detection with JA3 Integration

@load base/protocols/ssl

module TLSAnomaly;

export {

    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        ja3: string &log &optional;
        server_name: string &log &optional;
        anomaly_type: string &log &optional;
        anomaly_score: double &log &optional;
    };

    const anomaly_threshold = 0.1;

    global ja3_database: table[string] of count &default=0;

    global total_connections = 0;
}

event zeek_init()
{
    Log::create_stream(
        TLSAnomaly::LOG,
        [$columns=Info, $path="tls-anomaly"]
    );
}

function generate_ja3(
    c: connection,
    ssl: SSL::Info
): string
{
    # TODO:
    # Build JA3 string
    # Generate fingerprint

    return "";
}

function detect_anomaly(
    ja3: string
): tuple[bool, string, double]
{
    # TODO:
    # Detect anomalies

    return [F, "normal", 0.0];
}

event ssl_established(c: connection)
{
    # TODO:
    # Process TLS connections
}

event zeek_done()
{
    # TODO:
    # Print statistics
}
```

---

## ⚙️ Step 2.3: Configure Zeek

### Create Configuration Directory

```bash
mkdir -p ~/tls-anomaly-lab/zeek-config
```

---

### 📄 local.zeek

```bash
cat > ~/tls-anomaly-lab/zeek-config/local.zeek << 'EOF'

@load base/protocols/ssl
@load base/protocols/http
@load ../zeek-scripts/tls-anomaly.zeek

redef SSL::log_server_cert_hash = T;

EOF
```

---

### 📄 networks.cfg

```bash
cat > ~/tls-anomaly-lab/zeek-config/networks.cfg << 'EOF'

192.168.0.0/16    Private
10.0.0.0/8        Private
172.16.0.0/12     Private

EOF
```

---

### 📄 node.cfg

```bash
cat > ~/tls-anomaly-lab/zeek-config/node.cfg << 'EOF'

[zeek]
type=standalone
host=localhost
interface=lo

EOF
```

---

## 🌐 Step 2.4: Generate Test TLS Traffic

### 📄 File: `generate_tls_traffic.py`

```python
#!/usr/bin/env python3

import requests
import time
import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)

class TLSTrafficGenerator:

    def __init__(self):

        self.target_sites = [
            "https://www.google.com",
            "https://www.github.com",
            "https://httpbin.org/get"
        ]

        self.user_agents = [
            "Mozilla/5.0",
            "curl/7.68.0",
            "python-requests/2.25.1"
        ]

    def make_request(
        self,
        url,
        user_agent
    ):
        """
        Make HTTPS request.
        """

        # TODO:
        # Build headers
        # Send request

        pass

    def generate_normal_traffic(
        self,
        duration=60
    ):
        """
        Generate normal traffic.
        """

        pass

    def generate_anomalous_traffic(
        self,
        duration=30
    ):
        """
        Generate anomalous traffic.
        """

        pass

if __name__ == "__main__":

    generator = TLSTrafficGenerator()

    # TODO:
    # Generate traffic
```

---

# 🚀 Task 3: Automate Anomaly Detection & Alerting

---

## 🚨 Step 3.1: Create Real-Time Log Monitor

### 📄 File: `tls_anomaly_monitor.py`

```python
#!/usr/bin/env python3

import os
import time
import json
import logging

from datetime import datetime
from collections import defaultdict, deque

class TLSAnomalyMonitor:

    def __init__(
        self,
        log_directory="/tmp/zeek-logs",
        alert_threshold=0.8
    ):

        self.log_directory = log_directory
        self.alert_threshold = alert_threshold

        self.anomaly_buffer = deque(maxlen=1000)

        self.alert_history = defaultdict(int)

        self.setup_logging()

    def setup_logging(self):
        """
        Configure logging.
        """

        # TODO:
        # Setup file logging
        # Setup console logging

        pass

    def parse_zeek_log_line(
        self,
        line
    ):
        """
        Parse log line.
        """

        pass

    def analyze_anomaly(
        self,
        record
    ):
        """
        Analyze anomaly.
        """

        pass

    def generate_alert(
        self,
        alert_data
    ):
        """
        Generate alert.
        """

        pass

    def send_notification(
        self,
        alert_data
    ):
        """
        Send notification.
        """

        pass

    def process_log_file(
        self,
        file_path
    ):
        """
        Process logs.
        """

        pass

    def monitor_directory(self):
        """
        Watch logs.
        """

        pass

    def generate_summary_report(self):
        """
        Create report.
        """

        pass

if __name__ == "__main__":

    monitor = TLSAnomalyMonitor()

    # TODO:
    # Start monitoring
```

---

## ⚙️ Step 3.2: Create Alert Configuration

### 📄 File: `alert_config.json`

```json
{
  "alert_thresholds": {
    "critical": 0.9,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4
  },
  "notification_settings": {
    "email_enabled": false,
    "email_recipients": [
      "admin@example.com"
    ],
    "slack_enabled": false,
    "slack_webhook":
      "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  },
  "rate_limiting": {
    "max_alerts_per_ja3": 5,
    "time_window_seconds": 3600
  },
  "suspicious_patterns": {
    "user_agents": [
      "bot",
      "malware",
      "scanner"
    ],
    "domains": [
      "bit.ly",
      "tinyurl.com",
      "pastebin.com"
    ]
  }
}
```

---

## ▶️ Step 3.3: Run Complete Detection Pipeline

### Terminal 1

```bash
cd ~/tls-anomaly-lab

zeek -C -i lo zeek-config/local.zeek
```

---

### Terminal 2

```bash
python3 generate_tls_traffic.py
```

---

### Terminal 3

```bash
python3 tls_anomaly_monitor.py
```

---

### View Alerts

```bash
cat alerts_*.json | python3 -m json.tool
```

---

# 🏆 Expected Outcomes

After completing this lab you should have:

✅ Working JA3 Fingerprint Generator

✅ TLS Baseline Database

✅ Zeek Monitoring Configuration

✅ TLS Traffic Analysis Pipeline

✅ Automated Anomaly Detection

✅ Real-Time Alerting System

✅ Security Monitoring Dashboard Data

✅ JA3 Threat Intelligence Knowledge

✅ Detection Logs and Reports

---

# 🔧 Troubleshooting Guide

---

## ❌ Zeek Not Capturing Traffic

### Verify Interface

```bash
ip addr show
```

### Verify Zeek Process

```bash
ps aux | grep zeek
```

### Review Logs

```bash
cat /opt/zeek/logs/current/stderr.log
```

---

## ❌ No Anomalies Detected

### Lower Threshold

Edit:

```json
"alert_threshold": 0.1
```

### Verify Traffic

```bash
python3 generate_tls_traffic.py
```

### Review Logs

```bash
cat tls-anomaly.log
```

---

## ❌ Python Import Errors

Reinstall Dependencies

```bash
pip3 install --upgrade pandas numpy requests
```

Verify Version

```bash
python3 --version
```

Expected:

```text
Python 3.6+
```

---

# 🎓 Skills Gained

By completing this lab you learned how to:

🔐 Generate JA3 TLS Fingerprints

📡 Monitor Encrypted Traffic

🚨 Detect TLS-Based Threats

🛡️ Build Security Monitoring Systems

📊 Analyze Network Behavior

⚡ Automate Alerting Workflows

🔍 Investigate Anomalous TLS Activity

🌐 Monitor Enterprise Network Security

---

# 🚀 Next Steps

### Advanced Challenges

- 🔥 Analyze Real PCAP Files
- 🔥 Integrate Threat Intelligence Feeds
- 🔥 Detect TLS C2 Channels
- 🔥 Deploy Zeek Sensors
- 🔥 Create SIEM Integrations
- 🔥 Tune Detection Thresholds
- 🔥 Develop Behavioral Analytics
- 🔥 Monitor Enterprise TLS Ecosystems

---

# 📜 Conclusion

This lab demonstrated how to perform **TLS anomaly detection using JA3 fingerprinting and Zeek Network Security Monitoring**. By implementing fingerprint generation, building anomaly detection workflows, creating automated alerting systems, and monitoring encrypted traffic, students gained practical blue-team skills used by SOC analysts, threat hunters, incident responders, and network defenders.

Understanding JA3 fingerprinting and TLS monitoring is essential for identifying malicious encrypted communications, detecting malware activity, and protecting modern enterprise environments where most network traffic is encrypted.

---

<div align="center">

### 🔐 Fingerprint • Monitor • Detect • Defend

**TLS Anomaly Detection with JA3 + Zeek Lab**

⭐ Happy Threat Hunting! ⭐

</div>
