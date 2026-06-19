# 📡 Network Beacon Detection with Zeek Logs

<div align="center">

![Zeek](https://img.shields.io/badge/Zeek-Network%20Security%20Monitor-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge&logo=python)
![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04-orange?style=for-the-badge&logo=ubuntu)
![Network Analysis](https://img.shields.io/badge/Network-Traffic%20Analysis-green?style=for-the-badge)
![Threat Hunting](https://img.shields.io/badge/Threat-Hunting-red?style=for-the-badge)
![Beacon Detection](https://img.shields.io/badge/Beacon-Detection-purple?style=for-the-badge)
![SOC](https://img.shields.io/badge/SOC-Monitoring-darkred?style=for-the-badge)

# 🛡️ Advanced Network Beacon Detection & Threat Hunting

### 📊 Statistical Analysis • 🚨 Alerting • 📡 Traffic Monitoring • 🔍 Threat Detection

</div>

---

# 📖 Overview

This hands-on cybersecurity lab introduces students to **Network Beacon Detection using Zeek and Python-based statistical analysis**. Participants will deploy Zeek for network monitoring, identify command-and-control (C2) beaconing patterns, automate detection workflows, create visualizations, and implement alerting mechanisms for suspicious communications.

The lab simulates real-world Security Operations Center (SOC) activities where analysts continuously hunt for malware beaconing, persistence mechanisms, and command-and-control traffic hidden within normal network activity.

---

# 🎯 Learning Objectives

By the end of this lab, students will be able to:

✅ Deploy and configure Zeek Network Security Monitor

✅ Analyze network traffic using Zeek logs

✅ Detect network beaconing using statistical methods

✅ Develop Python scripts for automated detection

✅ Create visualizations for security monitoring

✅ Generate alerts for suspicious network behavior

✅ Investigate command-and-control communications

✅ Build repeatable threat hunting workflows

---

# 🧰 Technology Stack

| Category | Technologies |
|-----------|-------------|
| Network Monitoring | Zeek |
| Programming | Python 3.8+ |
| Operating System | Ubuntu 20.04 LTS |
| Data Analysis | Pandas |
| Scientific Computing | NumPy |
| Statistics | SciPy |
| Visualization | Matplotlib |
| Dashboarding | Seaborn |
| Threat Hunting | Beacon Detection |
| Logging | Zeek Logs |
| Alerting | Python Automation |
| Security Monitoring | SOC Analytics |

---

# 📚 Prerequisites

Before beginning this lab, ensure you have:

### 🌐 Networking Knowledge

- TCP/IP fundamentals
- Network protocols
- Client-server communication

### 💻 Linux Skills

- Linux command line proficiency
- Process management
- File operations

### 🐍 Programming Knowledge

- Python basics
- Functions and classes
- Data structures

### 📊 Statistical Concepts

- Mean
- Standard Deviation
- Variance
- Coefficient of Variation (CV)

### 🔍 Security Knowledge

- Log analysis
- Threat hunting concepts
- Beaconing fundamentals

---

# 🖥️ Lab Environment

## ☁️ Al Nafi Cloud Machine

Your pre-configured environment includes:

### ✅ Operating System

- Ubuntu 20.04 LTS

### ✅ Development Tools

- Python 3.8+
- Pip Package Manager
- Network Capture Capabilities

### ✅ Security Monitoring

- Zeek Compatible Environment
- Administrative Access

---

# 🚀 Task 1: Install and Configure Zeek

---

## ⚙️ Step 1.1: Install Zeek from Package Repository

### Add Repository

```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
```

### Install Zeek

```bash
sudo apt update

sudo apt install -y zeek
```

### Add Zeek to PATH

```bash
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc

source ~/.bashrc
```

---

## 🌐 Step 1.2: Configure Network Interface

### Identify Interface

```bash
ip addr show
```

### Configure Zeek Node

```bash
sudo tee /opt/zeek/etc/node.cfg << 'EOF'

[zeek]
type=standalone
host=localhost
interface=eth0

EOF
```

### Configure Networks

```bash
sudo tee /opt/zeek/etc/networks.cfg << 'EOF'

10.0.0.0/8          Private IP space
172.16.0.0/12       Private IP space
192.168.0.0/16      Private IP space

EOF
```

---

## 🔍 Step 1.3: Create Custom Beacon Detection Script

### 📄 File: `/opt/zeek/share/zeek/site/beacon-detect.zeek`

```zeek
# TODO: Load required base scripts

module BeaconDetect;

export {

    # TODO:
    # Define thresholds

    # TODO:
    # Create log stream

    # TODO:
    # Define Info record type
}

# TODO:
# Global tracking table

event zeek_init()
{
    # TODO:
    # Initialize log stream
}

event connection_established(c: connection)
{
    # TODO:
    # Extract source/destination data
    # Store timestamps
}

function analyze_intervals(
    timestamps: vector of time
): double
{
    # TODO:
    # Calculate intervals
    # Compute mean
    # Compute variance
    # Calculate CV

    return 0.0;
}

function check_beacon_pattern(
    c: connection,
    times: vector of time
)
{
    # TODO:
    # Calculate score
    # Generate alerts
}
```

### Load Script

Add to:

```bash
/opt/zeek/share/zeek/site/local.zeek
```

```zeek
@load ./beacon-detect.zeek
```

---

## 🚀 Step 1.4: Start Zeek and Verify Operation

### Deploy Configuration

```bash
sudo zeekctl deploy
```

### Verify Status

```bash
sudo zeekctl status
```

### View Logs

```bash
ls -lh /opt/zeek/logs/current/
```

### Monitor Connections

```bash
tail -f /opt/zeek/logs/current/conn.log
```

---

# 🚀 Task 2: Develop Python Beacon Detection Scripts

---

## 🐍 Step 2.1: Setup Python Environment

### Create Project Directory

```bash
mkdir -p ~/beacon-detection

cd ~/beacon-detection
```

### Create Virtual Environment

```bash
python3 -m venv venv

source venv/bin/activate
```

### Install Dependencies

```bash
pip install pandas numpy scipy matplotlib seaborn
```

---

## 📄 Step 2.2: Create Zeek Log Parser

### File: `zeek_parser.py`

```python
#!/usr/bin/env python3

import pandas as pd
import logging
from pathlib import Path

class ZeekLogParser:

    def __init__(
        self,
        log_dir="/opt/zeek/logs/current"
    ):
        self.log_dir = Path(log_dir)
        self.logger = self._setup_logging()

    def _setup_logging(self):

        # TODO:
        # Configure logger

        pass

    def parse_log(
        self,
        log_name
    ) -> pd.DataFrame:

        """
        Parse Zeek log.
        """

        # TODO:
        # Load file
        # Parse fields
        # Convert timestamps

        pass

    def get_connections(self):

        return self.parse_log(
            "conn.log"
        )

    def get_http_requests(self):

        return self.parse_log(
            "http.log"
        )

    def get_dns_queries(self):

        return self.parse_log(
            "dns.log"
        )

if __name__ == "__main__":

    parser = ZeekLogParser()

    conn_df = parser.get_connections()

    print(
        f"Loaded {len(conn_df)} connections"
    )
```

---

## 📊 Step 2.3: Implement Beacon Detection Algorithm

### File: `beacon_detector.py`

```python
#!/usr/bin/env python3

import pandas as pd
import numpy as np

from scipy import stats

from zeek_parser import ZeekLogParser

class BeaconDetector:

    def __init__(
        self,
        min_connections=10,
        max_cv=0.3
    ):

        self.parser = ZeekLogParser()

        self.min_connections = min_connections

        self.max_cv = max_cv

    def calculate_intervals(
        self,
        timestamps
    ):

        """
        Calculate intervals.
        """

        # TODO:
        # Sort timestamps
        # Calculate deltas

        pass

    def calculate_beacon_score(
        self,
        intervals
    ):

        """
        Generate statistics.
        """

        # TODO:
        # Mean
        # Std Dev
        # CV
        # Beacon Score

        pass

    def detect_connection_beacons(
        self,
        df
    ):

        """
        Detect beaconing.
        """

        # TODO:
        # Group connections
        # Calculate scores

        pass

    def detect_http_beacons(self):

        # TODO:
        # Analyze HTTP traffic

        pass

    def detect_dns_beacons(self):

        # TODO:
        # Analyze DNS traffic

        pass

    def generate_report(self):

        # TODO:
        # Build report

        pass

if __name__ == "__main__":

    detector = BeaconDetector()

    report = detector.generate_report()

    print(
        "=== Beacon Detection Report ==="
    )
```

---

## 📈 Step 2.4: Create Visualization Module

### File: `visualizer.py`

```python
#!/usr/bin/env python3

import matplotlib.pyplot as plt

import seaborn as sns

import pandas as pd

class BeaconVisualizer:

    def __init__(self):

        sns.set_style(
            "whitegrid"
        )

    def plot_beacon_scores(
        self,
        beacon_df,
        output_file
    ):

        # TODO:
        # Histogram

        pass

    def plot_interval_distribution(
        self,
        intervals,
        title,
        output_file
    ):

        # TODO:
        # Distribution plot

        pass

    def plot_beacon_timeline(
        self,
        timestamps,
        output_file
    ):

        # TODO:
        # Timeline plot

        pass

    def create_dashboard(
        self,
        report,
        output_dir
    ):

        # TODO:
        # Dashboard

        pass
```

---

# 🚀 Task 3: Generate Test Traffic and Analyze Results

---

## 🌐 Step 3.1: Create Traffic Generator

### File: `traffic_generator.py`

```python
#!/usr/bin/env python3

import requests
import time
import random
import socket

from datetime import datetime

class TrafficGenerator:

    def generate_http_beacon(
        self,
        url,
        interval,
        jitter,
        count
    ):

        # TODO:
        # Generate beacon traffic

        pass

    def generate_dns_beacon(
        self,
        domain,
        interval,
        count
    ):

        # TODO:
        # DNS beaconing

        pass

    def generate_normal_traffic(
        self,
        duration
    ):

        # TODO:
        # Random traffic

        pass

if __name__ == "__main__":

    gen = TrafficGenerator()

    print(
        "Generating HTTP beacon..."
    )

    gen.generate_http_beacon(
        "http://httpbin.org/get",
        60,
        0.1,
        20
    )

    print(
        "Generating DNS beacon..."
    )

    gen.generate_dns_beacon(
        "example.com",
        30,
        20
    )
```

---

## ▶️ Step 3.2: Run Detection Analysis

### Start Zeek

```bash
sudo zeekctl start
```

### Generate Test Traffic

```bash
python3 traffic_generator.py &
```

### Wait for Traffic

```bash
sleep 600
```

### Run Detection

```bash
python3 beacon_detector.py > detection_report.txt
```

### View Results

```bash
cat detection_report.txt
```

---

## ⚙️ Step 3.3: Create Automated Analysis Script

### File: `analyze.sh`

```bash
#!/bin/bash

echo "Starting beacon detection analysis..."

sudo zeekctl status

python3 beacon_detector.py --output results.json

python3 visualizer.py \
--input results.json \
--output-dir ./plots

python3 -c "
import json

with open('results.json') as f:
    data = json.load(f)

    print(
        f'Total beacons detected: {data[\"summary\"][\"total_beacons\"]}'
    )

    print(
        f'High confidence: {data[\"summary\"][\"high_confidence_count\"]}'
    )
"

echo "Analysis complete."
```

---

# 🚀 Task 4: Implement Basic Alerting

---

## 🚨 Step 4.1: Create Alert Generator

### File: `alerting.py`

```python
#!/usr/bin/env python3

import json
import smtplib

from email.mime.text import MIMEText

from datetime import datetime

class AlertManager:

    def __init__(
        self,
        alert_threshold=0.8
    ):
        self.alert_threshold = alert_threshold

    def check_alert_conditions(
        self,
        beacon_data
    ):

        # TODO:
        # Alert logic

        pass

    def format_alert_message(
        self,
        beacon_data
    ):

        # TODO:
        # Format alert

        pass

    def write_alert_log(
        self,
        alert_message,
        log_file="alerts.log"
    ):

        # TODO:
        # Save alert

        pass

    def send_email_alert(
        self,
        alert_message,
        recipient
    ):

        # TODO:
        # SMTP notification

        pass

    def process_detection_results(
        self,
        results
    ):

        # TODO:
        # Process detections

        pass
```

---

## 🔗 Step 4.2: Integrate Alerting with Detection

### Update `beacon_detector.py`

```python
from alerting import AlertManager

def main():

    detector = BeaconDetector()

    alert_mgr = AlertManager(
        alert_threshold=0.8
    )

    report = detector.generate_report()

    alert_mgr.process_detection_results(
        report
    )

    print(
        f"Detected {report['summary']['total_beacons']} beacons"
    )

    print(
        f"Generated {report['summary']['alerts_sent']} alerts"
    )

if __name__ == "__main__":
    main()
```

---

# 🏆 Expected Outcomes

After completing this lab you should have:

✅ Functional Zeek Deployment

✅ Custom Beacon Detection Script

✅ Automated Python Detection Toolkit

✅ Statistical Analysis Engine

✅ Traffic Visualization Dashboard

✅ Alert Generation System

✅ Threat Hunting Workflow

✅ Network Monitoring Experience

✅ Beacon Detection Expertise

---

# 🔧 Troubleshooting Guide

---

## ❌ Zeek Not Capturing Traffic

### Verify Interface

```bash
ip link show
```

### Check Zeek Status

```bash
sudo zeekctl status
```

### Review Logs

```bash
tail /opt/zeek/logs/current/reporter.log
```

---

## ❌ No Beacons Detected

### Generate More Traffic

```bash
python3 traffic_generator.py
```

### Lower Thresholds

Increase:

```python
max_cv = 0.5
```

### Verify Parsing

```bash
python3 zeek_parser.py
```

---

## ❌ Python Import Errors

Activate Environment

```bash
source venv/bin/activate
```

Reinstall Packages

```bash
pip install pandas numpy scipy matplotlib seaborn
```

Verify Version

```bash
python3 --version
```

Expected:

```text
Python 3.7+
```

---

# 🎓 Skills Gained

By completing this lab you learned how to:

📡 Deploy Zeek Monitoring

🔍 Detect Network Beaconing

📊 Apply Statistical Analysis

🐍 Automate Threat Detection

🚨 Generate Security Alerts

📈 Visualize Network Activity

🛡️ Hunt Command-and-Control Traffic

⚡ Build SOC Detection Pipelines

---

# 🚀 Next Steps

### Advanced Challenges

- 🔥 Integrate Splunk
- 🔥 Integrate ELK Stack
- 🔥 Add Machine Learning Detection
- 🔥 Analyze Real PCAP Files
- 🔥 Create Threat Intelligence Enrichment
- 🔥 Build Detection Dashboards
- 🔥 Deploy Enterprise Monitoring
- 🔥 Perform Advanced Threat Hunting

---

# 📜 Conclusion

This lab introduced **Network Beacon Detection using Zeek and Python-based statistical analysis**. Through traffic monitoring, beacon pattern identification, automated detection, visualization, and alert generation, students gained practical experience identifying command-and-control communications and suspicious network activity.

These techniques form the foundation of modern threat hunting, SOC monitoring, incident response, and network security operations.

---

<div align="center">

### 📡 Monitor • Detect • Analyze • Defend

**Network Beacon Detection with Zeek Logs Lab**

⭐ Happy Threat Hunting! ⭐

</div>
