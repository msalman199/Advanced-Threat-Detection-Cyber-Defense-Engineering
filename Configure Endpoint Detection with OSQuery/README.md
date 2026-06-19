# 🛡️ Configure Endpoint Detection with OSQuery

<div align="center">

# 🔍 Endpoint Detection & Response with OSQuery

### 🚀 Security Monitoring • Threat Detection • Endpoint Visibility • SIEM Integration

![OSQuery](https://img.shields.io/badge/OSQuery-Endpoint%20Monitoring-blue?style=for-the-badge&logo=linux)
![Python](https://img.shields.io/badge/Python-Automation-yellow?style=for-the-badge&logo=python)
![Linux](https://img.shields.io/badge/Linux-Ubuntu%2020.04-orange?style=for-the-badge&logo=ubuntu)
![SQL](https://img.shields.io/badge/SQL-Endpoint%20Queries-green?style=for-the-badge&logo=mysql)
![JSON](https://img.shields.io/badge/JSON-Telemetry-red?style=for-the-badge&logo=json)
![SIEM](https://img.shields.io/badge/SIEM-Integration-purple?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Threat%20Detection-darkgreen?style=for-the-badge)

</div>

---

# 📖 Overview

This lab provides hands-on experience with **OSQuery Endpoint Detection and Response (EDR)** technologies. Students will learn how to deploy and configure OSQuery, create automated security monitoring solutions, develop Python-based threat detection systems, and integrate endpoint telemetry into centralized security monitoring workflows.

---

# 🎯 Objectives

By the end of this lab, students will be able to:

✅ Install and configure OSQuery for endpoint monitoring on Linux systems

✅ Write custom SQL queries to extract security-relevant endpoint data

✅ Develop Python scripts to automate OSQuery data collection and analysis

✅ Implement threat detection logic using OSQuery telemetry

✅ Integrate OSQuery with centralized logging systems for security monitoring

---

# 📚 Prerequisites

Before starting this lab, ensure you have:

🔹 Basic Linux command line proficiency

🔹 Understanding of SQL query syntax

🔹 Python programming fundamentals

🔹 Familiarity with JSON data structures

🔹 Basic security monitoring concepts

---

# 🖥️ Lab Environment

### ☁️ Cloud Machine Specifications

| Component | Details |
|------------|----------|
| Operating System | Ubuntu 20.04 LTS |
| Python | Python 3.8+ |
| Access | Root / Sudo |
| Network | Internet Connectivity |
| Tools | Pre-configured Development Environment |

🚀 Click **Start Lab** to access your dedicated environment.

---

# 🧩 Task 1: Install and Configure OSQuery

---

## 🔹 Step 1.1: Install OSQuery Package

```bash
# Update system and install dependencies
sudo apt update && sudo apt install -y curl gnupg2

# Add OSQuery repository
curl -L https://pkg.osquery.io/deb/pubkey.gpg | sudo apt-key add -
sudo add-apt-repository 'deb [arch=amd64] https://pkg.osquery.io/deb deb main'

# Install OSQuery
sudo apt update && sudo apt install -y osquery

# Verify installation
osqueryi --version
```

✅ Expected Result: OSQuery installed successfully.

---

## 🔹 Step 1.2: Create Basic Configuration

```bash
# Create configuration directory
sudo mkdir -p /etc/osquery

# Create main configuration file
sudo nano /etc/osquery/osquery.conf
```

Add:

```json
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10",
    "database_path": "/var/osquery/osquery.db"
  },
  "schedule": {
    "system_info": {
      "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
      "interval": 3600
    },
    "network_connections": {
      "query": "SELECT pid, local_address, local_port, remote_address, remote_port FROM process_open_sockets;",
      "interval": 300
    },
    "running_processes": {
      "query": "SELECT name, path, pid, cmdline FROM processes;",
      "interval": 600
    }
  }
}
```

---

## 🔹 Step 1.3: Configure File Integrity Monitoring

```bash
sudo nano /etc/osquery/fim.conf
```

Add:

```json
{
  "file_paths": {
    "binaries": ["/usr/bin/%%", "/usr/sbin/%%"],
    "configuration": ["/etc/%%"],
    "ssh_keys": ["/home/%%/.ssh/%%"]
  }
}
```

---

## 🔹 Step 1.4: Start OSQuery Service

```bash
sudo mkdir -p /var/log/osquery /var/osquery
sudo chown osquery:osquery /var/log/osquery /var/osquery

sudo systemctl start osqueryd
sudo systemctl enable osqueryd
sudo systemctl status osqueryd

sudo tail -f /var/log/osquery/osqueryd.results.log
```

✅ Expected Result: OSQuery daemon running and generating logs.

---

## 🔹 Step 1.5: Test Interactive Queries

```bash
sudo osqueryi
```

Run:

```sql
SELECT * FROM system_info;
SELECT * FROM users;
SELECT * FROM listening_ports;
SELECT name, path FROM processes WHERE name LIKE '%ssh%';
.quit
```

---

# 🐍 Task 2: Develop Python Data Collection Scripts

---

## 🔹 Step 2.1: Setup Python Environment

```bash
mkdir -p ~/osquery-lab && cd ~/osquery-lab

pip3 install --user psutil requests
```

---

## 🔹 Step 2.2: Create OSQuery Interface Module

📄 Create:

```bash
nano osquery_interface.py
```

### 🧠 Student TODO Areas

Implement:

- ✅ Logging configuration
- ✅ OSQuery execution wrapper
- ✅ System information collection
- ✅ Running process collection
- ✅ Network connection enumeration
- ✅ Logged-in user collection
- ✅ JSON export functionality

Core methods:

```python
class OSQueryInterface:
    def execute_query(self, query):
        pass

    def get_system_info(self):
        pass

    def get_running_processes(self):
        pass

    def get_network_connections(self):
        pass

    def get_logged_in_users(self):
        pass

    def collect_all_data(self):
        pass

    def save_to_file(self, data):
        pass
```

---

## 🔹 Step 2.3: Create Threat Detection Module

📄 Create:

```bash
nano threat_detector.py
```

### 🎯 Detection Categories

#### 🚨 Suspicious Process Detection

Examples:

```text
nc -l
bash -i
/dev/tcp/
wget | sh
```

#### 🌐 Suspicious Network Detection

Monitor ports:

```text
4444
1234
31337
8080
```

#### 🔐 Privilege Escalation Detection

Identify:

- Root processes
- Unexpected parent-child relationships
- Unauthorized privilege changes

---

### Core Functions

```python
class ThreatDetector:

    def detect_suspicious_processes(self):
        pass

    def detect_suspicious_network(self):
        pass

    def detect_privilege_escalation(self):
        pass

    def run_full_scan(self):
        pass

    def generate_report(self):
        pass

    def save_report(self):
        pass
```

---

## 🔹 Step 2.4: Create Continuous Monitoring Script

📄 Create:

```bash
nano continuous_monitor.py
```

### 🎯 Monitoring Features

✅ Continuous telemetry collection

✅ Automated threat scanning

✅ Multi-threaded monitoring

✅ Scheduled reporting

✅ Alert generation

### Core Functions

```python
class ContinuousMonitor:

    def collect_data_worker(self):
        pass

    def threat_scan_worker(self):
        pass

    def start_monitoring(self):
        pass
```

---

# 📡 Task 3: Integrate with Centralized Logging

---

## 🔹 Step 3.1: Configure Log Forwarding

📄 Create:

```bash
nano log_forwarder.py
```

### 🎯 Features

- UDP Syslog forwarding
- JSON event formatting
- Threat alert prioritization
- Error handling

Core methods:

```python
class LogForwarder:

    def forward_log(self, log_data):
        pass

    def forward_threat_alert(self, threat):
        pass
```

---

## 🔹 Step 3.2: Create SIEM Integration Module

📄 Create:

```bash
nano siem_integration.py
```

### 🎯 Responsibilities

✅ Collect OSQuery telemetry

✅ Run threat detection

✅ Normalize event fields

✅ Forward logs to SIEM

✅ Generate threat alerts

Core methods:

```python
class SIEMIntegration:

    def collect_and_forward(self):
        pass

    def format_for_siem(self, data):
        pass
```

---

# 🧪 Task 4: Test and Validate Detection

---

## 🔹 Step 4.1: Generate Test Events

### Suspicious Process Test

```bash
bash -c 'sleep 30' &
```

---

### Network Monitoring Test

```bash
nc -l 4444 &
sleep 5
killall nc
```

---

### File Activity Test

```bash
touch /tmp/test_file.sh
echo "#!/bin/bash" > /tmp/test_file.sh
rm /tmp/test_file.sh
```

---

## 🔹 Step 4.2: Run Detection Scripts

```bash
cd ~/osquery-lab

python3 threat_detector.py
```

Review results:

```bash
cat /tmp/threat_report_*.json | jq '.'
```

Run continuous monitoring:

```bash
python3 continuous_monitor.py
```

---

## 🔹 Step 4.3: Validate Data Collection

### Review OSQuery Logs

```bash
sudo tail -50 /var/log/osquery/osqueryd.results.log | jq '.'
```

### View Collected Data

```bash
ls -lh /tmp/osquery_data_*.json

cat /tmp/osquery_data_*.json | jq '.system_info'
```

### Review Threat Reports

```bash
ls -lh /tmp/threat_report_*.json

cat /tmp/threat_report_*.json | jq '.threat_summary'
```

---

# 🎉 Expected Outcomes

After completing this lab, students should have:

✅ Functional OSQuery installation

✅ Scheduled endpoint monitoring queries

✅ Automated Python data collection scripts

✅ Threat detection framework

✅ Continuous monitoring solution

✅ SIEM integration workflow

✅ Endpoint visibility and telemetry analysis skills

---

# ✔️ Validation Checklist

| Check | Status |
|---------|---------|
| OSQuery Service Running | ✅ |
| Scheduled Queries Executing | ✅ |
| Python Collection Scripts Working | ✅ |
| Threat Detection Operational | ✅ |
| JSON Data Generated | ✅ |
| Continuous Monitoring Active | ✅ |
| SIEM Integration Functional | ✅ |

---

# 🛠️ Troubleshooting Tips

## ❌ OSQuery Service Fails

```bash
sudo osqueryd --config_check
sudo journalctl -u osqueryd -n 50
```

Verify permissions:

```bash
ls -ld /var/log/osquery
ls -ld /var/osquery
```

---

## ❌ Python Scripts Return Empty Results

Check service:

```bash
sudo systemctl status osqueryd
```

Verify queries:

```bash
sudo osqueryi
```

Test manually:

```sql
SELECT * FROM system_info;
```

---

## ❌ No Threats Detected

Verify test process:

```bash
ps aux | grep nc
```

Check detection regex:

```python
re.match(pattern, cmdline)
```

Review thresholds and logic.

---

## ❌ Log Forwarding Not Working

Verify connectivity:

```bash
netstat -anu | grep 514
```

Test UDP:

```bash
logger "OSQuery Test Event"
```

---

# 📊 Skills Gained

Throughout this lab you practiced:

🔹 Endpoint Detection & Response (EDR)

🔹 Security Monitoring

🔹 Threat Hunting

🔹 SQL-Based Endpoint Visibility

🔹 Python Security Automation

🔹 Continuous Monitoring

🔹 SIEM Integration

🔹 Log Analysis

🔹 Incident Detection

🔹 Security Operations (SOC)

---

# 🏆 Conclusion

This lab provided hands-on experience with **OSQuery Endpoint Detection and Response (EDR)**. Students learned how to deploy OSQuery, collect endpoint telemetry, automate security monitoring using Python, detect suspicious activities, and integrate endpoint data with centralized monitoring platforms.

### 🔑 Key Takeaways

✅ OSQuery provides powerful SQL-based endpoint visibility

✅ Endpoint telemetry enables proactive threat hunting

✅ Python automation reduces manual investigation effort

✅ Threat detection can be implemented using behavioral indicators

✅ SIEM integration centralizes monitoring and incident response

✅ Continuous monitoring strengthens organizational security posture

---

# 🚀 Next Steps

🔹 Expand threat detection coverage

🔹 Integrate threat intelligence feeds

🔹 Build custom OSQuery packs

🔹 Implement anomaly detection with machine learning

🔹 Create SOC dashboards

🔹 Automate incident response workflows

🔹 Deploy OSQuery across multiple endpoints

🔹 Integrate with enterprise SIEM platforms

---

# 📖 Additional Resources

### 📚 Official Documentation

- OSQuery Documentation: https://osquery.readthedocs.io
- OSQuery GitHub: https://github.com/osquery/osquery
- MITRE ATT&CK: https://attack.mitre.org
- Sigma Rules: https://github.com/SigmaHQ/sigma
- Elastic Security: https://www.elastic.co/security

---

<div align="center">

## 🛡️ Endpoint Detection with OSQuery Complete

### ⭐ Build Visibility • Detect Threats • Automate Response ⭐

**Happy Threat Hunting! 🚀**

</div>
