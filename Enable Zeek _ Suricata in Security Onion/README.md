# 🔍 Enable Zeek & Suricata in Security Onion

> **A hands-on network security monitoring lab configuring Zeek and Suricata inside Security Onion to detect threats, analyze traffic logs, and automate anomaly detection and response.**

---

![Security Onion](https://img.shields.io/badge/Security_Onion-NSM_Platform-005F87?style=for-the-badge&logo=linux&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-Network_Analysis-2980B9?style=for-the-badge&logo=zeek&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-IDS/IPS-EF3B2D?style=for-the-badge&logo=suricata&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-Dashboards-E8478B?style=for-the-badge&logo=kibana&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-Log_Store-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04_LTS-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![iptables](https://img.shields.io/badge/iptables-Firewall_Response-4EAA25?style=for-the-badge&logo=linux&logoColor=white)

---

## 🎯 Lab Objectives

By the end of this lab, you will be able to:

- 🛡️ Install and configure **Security Onion** with Zeek and Suricata for network monitoring
- 📏 Configure **custom detection rules** for both Zeek and Suricata
- 📊 Analyze **network traffic logs** using command-line tools and Kibana
- 🐍 Develop **Python scripts** for automated anomaly detection
- ⚡ Implement **automated response mechanisms** for security threats

---

## ✅ Prerequisites

| Skill | Level |
|---|---|
| 🐧 Linux command-line | Proficient |
| 🌐 TCP/IP networking fundamentals | Understanding |
| 🔒 Network security concepts | Familiar |
| 🐍 Python programming | Basic |
| 🗂️ JSON data structures | Knowledge |

---

## 🖥️ Lab Environment

> **Ready-to-Use Cloud Machines:** Al Nafi provides pre-configured **Ubuntu 20.04 LTS** machines with **8GB RAM** and **100GB storage**. Click **Start Lab** to access your environment with Security Onion pre-installed.

---

---

# 🔧 Task 1 — Configure Zeek and Suricata

---

## 🩺 Step 1.1 — Verify Security Onion Installation

> Confirm all core services are running before making any configuration changes.

```bash
# 🛡️ Check Security Onion status
sudo so-status

# 🔍 Verify Zeek service
sudo systemctl status zeek

# ⚔️ Verify Suricata service
sudo systemctl status suricata

# 🌐 Check monitored interfaces
sudo so-interface-status
```

---

## 📝 Step 1.2 — Create Custom Zeek Policy

![Zeek](https://img.shields.io/badge/File-custom--detection.zeek-2980B9?style=flat-square&logoColor=white)

> Navigate to the Zeek policy directory and create a custom detection script.

```bash
cd /opt/so/saltstack/local/salt/zeek/policy
sudo nano custom-detection.zeek
```

**📄 File:** `/opt/so/saltstack/local/salt/zeek/policy/custom-detection.zeek`

```zeek
# 🔍 Custom Zeek policy for traffic analysis
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http

# ⏰ Configure log rotation
redef Log::default_rotation_interval = 1hr;

# TODO: Add event handler for connection_established
# Monitor and log all established connections

# TODO: Add event handler for dns_request
# Detect suspicious DNS queries (malware, phishing domains)

# TODO: Add event handler for http_request
# Identify suspicious HTTP patterns (executable downloads, SQL injection)
```

> 💡 **Event Handlers to Implement:**
> - `connection_established` — Log all new TCP/UDP connections
> - `dns_request` — Flag queries matching suspicious domain patterns
> - `http_request` — Detect downloads of executables or SQL injection strings

---

## 📏 Step 1.3 — Configure Suricata Custom Rules

![Suricata](https://img.shields.io/badge/File-custom--detection.rules-EF3B2D?style=flat-square&logoColor=white)

> Create custom Suricata detection rules to catch known threat patterns.

```bash
cd /etc/suricata/rules
sudo nano custom-detection.rules
```

**📄 File:** `/etc/suricata/rules/custom-detection.rules`

```suricata
# 🤖 Suspicious HTTP User-Agent detection
alert tcp any any -> any 80 (msg:"Suspicious Bot User-Agent"; content:"User-Agent:"; http_header; content:"bot"; http_header; nocase; sid:1000001; rev:1;)

# 🌐 DNS query to suspicious domain
alert dns any any -> any 53 (msg:"Potential Malware DNS Query"; content:"|01 00 00 01|"; offset:2; depth:4; content:"malware"; nocase; sid:1000002; rev:1;)

# 📤 Large data exfiltration attempt
alert tcp any any -> any any (msg:"Large Data Transfer Detected"; dsize:>1000000; sid:1000003; rev:1;)

# 📡 ICMP ping sweep detection
alert icmp any any -> any any (msg:"ICMP Ping Sweep"; itype:8; detection_filter:track by_src, count 10, seconds 5; sid:1000004; rev:1;)

# TODO: Add rule for detecting port scanning activity
# TODO: Add rule for detecting SQL injection attempts
```

> 📊 **Rules Overview:**

| SID | Threat | Protocol | Severity |
|---|---|---|---|
| 1000001 | Bot User-Agent | TCP/HTTP | Medium |
| 1000002 | Malware DNS Query | DNS | High |
| 1000003 | Data Exfiltration | TCP | High |
| 1000004 | ICMP Ping Sweep | ICMP | Medium |

---

## ♻️ Step 1.4 — Apply Configuration Changes

> Update rules and restart services to activate all configuration changes.

```bash
# 🔄 Update Suricata rules
sudo suricata-update

# ♻️ Restart services
sudo systemctl restart zeek
sudo systemctl restart suricata

# ✅ Verify configuration
sudo so-zeek-logs
sudo so-suricata-logs
```

---

---

# 📊 Task 2 — Analyze Network Traffic Logs

---

## 🚦 Step 2.1 — Generate Test Traffic

![Python](https://img.shields.io/badge/File-generate__traffic.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Create a traffic generation script to produce sample HTTP, DNS, and port scan data.

```bash
nano generate_traffic.py
chmod +x generate_traffic.py
```

**📄 File:** `~/generate_traffic.py`

```python
#!/usr/bin/env python3
import requests
import socket
import time
import random

def generate_http_traffic():
    """
    Generate HTTP requests to various endpoints.
    
    TODO: Implement HTTP GET requests to test URLs
    TODO: Add error handling for failed requests
    TODO: Include random delays between requests
    """
    urls = [
        'http://httpbin.org/get',
        'http://example.com',
        'http://httpbin.org/status/404'
    ]
    # TODO: Complete implementation
    pass

def generate_dns_queries():
    """
    Generate DNS lookups for testing.
    
    TODO: Implement DNS queries for various domains
    TODO: Include both legitimate and test suspicious domains
    TODO: Add exception handling
    """
    domains = ['google.com', 'github.com', 'test-malware.com']
    # TODO: Complete implementation
    pass

def simulate_port_scan():
    """
    Simulate port scanning activity.
    
    TODO: Implement connection attempts to multiple ports
    TODO: Use socket library to test port connectivity
    TODO: Add timeout handling
    """
    target = '127.0.0.1'
    ports = [22, 80, 443, 8080, 3389]
    # TODO: Complete implementation
    pass

if __name__ == "__main__":
    # TODO: Execute traffic generation functions
    # TODO: Use threading for parallel execution
    pass
```

> 💡 **Traffic Types to Generate:**
> - 🌐 HTTP GET requests to multiple endpoints (including 404s)
> - 🔍 DNS lookups for legitimate and suspicious domains
> - 📡 Port scan simulation against `127.0.0.1`

---

## 🖥️ Step 2.2 — Access Kibana Dashboard

![Kibana](https://img.shields.io/badge/Interface-Kibana_Web_UI-E8478B?style=flat-square&logo=kibana&logoColor=white)

> Access the Kibana web interface to create index patterns and explore log data visually.

```bash
# 🔍 Get Kibana URL
sudo so-status | grep -i kibana

# 🌐 Access at: https://your-machine-ip/kibana
# 🔐 Use credentials set during Security Onion installation
```

**Kibana Setup Steps:**

1. Navigate to **Management → Index Patterns**
2. Create index patterns: `logstash-zeek-*` and `logstash-suricata-*`
3. Go to **Discover** to view live logs
4. Create visualizations under **Visualize**

---

## 🔎 Step 2.3 — Analyze Zeek Logs via Command Line

![Zeek](https://img.shields.io/badge/Logs-Zeek_NSM-2980B9?style=flat-square&logoColor=white)
![Python](https://img.shields.io/badge/File-analyze__zeek__logs.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Tail live Zeek log files, then build a Python parser for deeper analysis.

```bash
# 📋 View current connection logs
sudo tail -f /nsm/zeek/logs/current/conn.log

# 🌐 Analyze DNS logs
sudo tail -f /nsm/zeek/logs/current/dns.log

# 🔗 View HTTP traffic
sudo tail -f /nsm/zeek/logs/current/http.log
```

**📄 File:** `~/analyze_zeek_logs.py`

```bash
nano analyze_zeek_logs.py
```

```python
#!/usr/bin/env python3
import json
from collections import defaultdict

def parse_zeek_conn_log(log_file):
    """
    Parse Zeek connection logs and extract key information.
    
    Args:
        log_file: Path to Zeek conn.log file
    
    Returns:
        Dictionary with connection statistics
    
    TODO: Read and parse log file (skip comments starting with #)
    TODO: Split each line by tab delimiter
    TODO: Extract source IP, destination IP, port, protocol
    TODO: Count connections per source IP
    """
    pass

def identify_suspicious_connections(connections):
    """
    Identify potentially suspicious connection patterns.
    
    Args:
        connections: Dictionary of connection data
    
    Returns:
        List of suspicious connections
    
    TODO: Check for connections to uncommon ports (23, 3389, 1433)
    TODO: Identify sources with excessive connection counts
    TODO: Flag connections with unusual protocols
    """
    pass

def generate_report(suspicious_connections):
    """
    Generate analysis report.
    
    TODO: Format and display suspicious connections
    TODO: Include timestamps and connection details
    TODO: Calculate risk scores
    """
    pass

if __name__ == "__main__":
    log_file = '/nsm/zeek/logs/current/conn.log'
    # TODO: Call parsing and analysis functions
    # TODO: Display results
    pass
```

> 💡 **Key Functions to Implement:**
> - `parse_zeek_conn_log()` — Tab-delimited parser skipping `#` comment lines
> - `identify_suspicious_connections()` — Flag uncommon ports (23, 3389, 1433) and high-volume sources
> - `generate_report()` — Format findings with timestamps and risk scores

---

## 🚨 Step 2.4 — Analyze Suricata Alerts

![Suricata](https://img.shields.io/badge/Logs-Suricata_EVE_JSON-EF3B2D?style=flat-square&logoColor=white)

> Parse Suricata's EVE JSON output to review triggered detection alerts.

```bash
# 📋 View Suricata alerts (live stream)
sudo tail -f /nsm/suricata/eve.json

# 🔍 Parse alerts with jq
sudo tail -100 /nsm/suricata/eve.json | jq 'select(.event_type=="alert")'
```

---

---

# 🤖 Task 3 — Implement Automated Anomaly Detection

---

## 🧠 Step 3.1 — Create Anomaly Detection System

![Python](https://img.shields.io/badge/File-anomaly__detector.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Build a class-based anomaly detector that hunts for connection floods, suspicious DNS, and port scans.

```bash
nano anomaly_detector.py
```

**📄 File:** `~/anomaly_detector.py`

```python
#!/usr/bin/env python3
import json
import time
from datetime import datetime
from collections import defaultdict

class AnomalyDetector:
    def __init__(self):
        self.connection_baseline = defaultdict(int)
        self.alert_threshold = 10
        self.alerts = []
    
    def load_zeek_logs(self, log_type='conn'):
        """
        Load and parse Zeek logs.
        
        Args:
            log_type: Type of log to load (conn, dns, http)
        
        Returns:
            List of parsed log entries
        
        TODO: Construct log file path based on log_type
        TODO: Read log file and filter out comments
        TODO: Return list of log lines
        """
        pass
    
    def detect_connection_anomalies(self):
        """
        Detect anomalous connection patterns.
        
        Returns:
            List of detected anomalies
        
        TODO: Load connection logs
        TODO: Count connections per source IP
        TODO: Compare against baseline
        TODO: Flag connections exceeding threshold
        """
        pass
    
    def detect_dns_anomalies(self):
        """
        Detect suspicious DNS queries.
        
        Returns:
            List of suspicious DNS queries
        
        TODO: Load DNS logs
        TODO: Check for DGA patterns (long hex strings)
        TODO: Match against known malicious keywords
        TODO: Identify IP-like domain names
        """
        pass
    
    def detect_port_scan(self):
        """
        Detect port scanning activity.
        
        Returns:
            List of potential port scans
        
        TODO: Track unique ports accessed per source IP
        TODO: Flag sources accessing >10 different ports
        TODO: Calculate scan rate
        """
        pass
    
    def generate_alert(self, anomaly):
        """
        Generate and log security alert.
        
        Args:
            anomaly: Dictionary containing anomaly details
        
        TODO: Assign severity level
        TODO: Create alert structure with timestamp
        TODO: Write to alert log file
        TODO: Display alert to console
        """
        pass
    
    def run_detection_cycle(self):
        """
        Execute one complete detection cycle.
        
        TODO: Run all detection methods
        TODO: Collect all anomalies
        TODO: Generate alerts for each anomaly
        TODO: Return summary statistics
        """
        pass
    
    def start_monitoring(self, interval=60):
        """
        Start continuous monitoring loop.
        
        Args:
            interval: Seconds between detection cycles
        
        TODO: Implement infinite loop with sleep interval
        TODO: Call run_detection_cycle periodically
        TODO: Handle KeyboardInterrupt for graceful exit
        """
        pass

if __name__ == "__main__":
    detector = AnomalyDetector()
    # TODO: Implement menu system
    # TODO: Allow single cycle or continuous monitoring
    # TODO: Provide option to view recent alerts
    pass
```

> 💡 **Detection Methods to Implement:**
> - `detect_connection_anomalies()` — Compare per-IP connection counts to baseline threshold
> - `detect_dns_anomalies()` — Hunt DGA patterns, hex strings, and malicious keywords
> - `detect_port_scan()` — Flag sources hitting more than 10 distinct ports
> - `start_monitoring()` — Infinite loop with configurable interval and graceful `Ctrl+C` exit

---

## ⚡ Step 3.2 — Implement Automated Response System

![Python](https://img.shields.io/badge/File-automated__response.py-3776AB?style=flat-square&logo=python&logoColor=white)
![iptables](https://img.shields.io/badge/Engine-iptables-4EAA25?style=flat-square&logo=linux&logoColor=white)

> Build a response system that automatically blocks IPs, rate-limits connections, and blacklists domains.

```bash
nano automated_response.py
```

**📄 File:** `~/automated_response.py`

```python
#!/usr/bin/env python3
import subprocess
import json
from datetime import datetime

class AutomatedResponseSystem:
    def __init__(self):
        self.blocked_ips = set()
        self.response_log = '/tmp/automated_responses.log'
    
    def block_ip_address(self, ip_address):
        """
        Block IP address using iptables.
        
        Args:
            ip_address: IP to block
        
        TODO: Construct iptables DROP rule
        TODO: Execute command using subprocess
        TODO: Add IP to blocked_ips set
        TODO: Log the action
        """
        pass
    
    def rate_limit_connection(self, ip_address, limit='10/min'):
        """
        Apply rate limiting to IP address.
        
        Args:
            ip_address: IP to rate limit
            limit: Rate limit string (e.g., '10/min')
        
        TODO: Create iptables rate limit rule
        TODO: Execute using subprocess
        TODO: Log the action
        """
        pass
    
    def block_dns_domain(self, domain):
        """
        Add domain to DNS blacklist.
        
        Args:
            domain: Domain name to block
        
        TODO: Append domain to /etc/hosts or DNS blacklist
        TODO: Point domain to 127.0.0.1
        TODO: Log the action
        """
        pass
    
    def log_response_action(self, action_type, target, details):
        """
        Log automated response action.
        
        Args:
            action_type: Type of response taken
            target: Target of the action (IP, domain, etc.)
            details: Additional details
        
        TODO: Create log entry dictionary
        TODO: Write to response log file in JSON format
        TODO: Include timestamp
        """
        pass
    
    def process_alert(self, alert):
        """
        Process security alert and take appropriate action.
        
        Args:
            alert: Alert dictionary from anomaly detector
        
        TODO: Determine alert severity
        TODO: Select appropriate response action
        TODO: Execute response
        TODO: Log the response
        """
        pass
    
    def unblock_ip(self, ip_address):
        """
        Remove IP from block list.
        
        Args:
            ip_address: IP to unblock
        
        TODO: Remove iptables rule
        TODO: Remove from blocked_ips set
        TODO: Log the action
        """
        pass
    
    def show_blocked_ips(self):
        """
        Display currently blocked IPs.
        
        TODO: Iterate through blocked_ips set
        TODO: Format and display each IP
        """
        pass

if __name__ == "__main__":
    response_system = AutomatedResponseSystem()
    # TODO: Implement command-line interface
    # TODO: Options: process alerts, show blocks, unblock IP
    pass
```

> 💡 **Response Actions to Implement:**
> - `block_ip_address()` — `iptables -A INPUT -s <ip> -j DROP`
> - `rate_limit_connection()` — iptables `--limit` rate throttling
> - `block_dns_domain()` — Append `127.0.0.1 <domain>` to `/etc/hosts`
> - `unblock_ip()` — `iptables -D` to remove existing block rules

---

## 📊 Step 3.3 — Create Monitoring Dashboard Script

![Python](https://img.shields.io/badge/File-monitoring__dashboard.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Build a terminal dashboard that aggregates alert stats, top threats, and response metrics.

```bash
nano monitoring_dashboard.py
```

**📄 File:** `~/monitoring_dashboard.py`

```python
#!/usr/bin/env python3
import json
import os
from datetime import datetime, timedelta

class MonitoringDashboard:
    def __init__(self):
        self.alerts_file = '/tmp/security_alerts.log'
        self.responses_file = '/tmp/automated_responses.log'
    
    def get_alert_statistics(self):
        """
        Calculate alert statistics.
        
        Returns:
            Dictionary with alert counts by type and severity
        
        TODO: Read alerts from log file
        TODO: Count alerts by type
        TODO: Count alerts by severity
        TODO: Calculate alerts in last hour/day
        """
        pass
    
    def get_top_threats(self, limit=10):
        """
        Identify top threat sources.
        
        Args:
            limit: Number of top threats to return
        
        Returns:
            List of top threat sources
        
        TODO: Parse alerts and extract source IPs
        TODO: Count alerts per source
        TODO: Sort and return top sources
        """
        pass
    
    def get_response_statistics(self):
        """
        Calculate automated response statistics.
        
        Returns:
            Dictionary with response action counts
        
        TODO: Read response log file
        TODO: Count actions by type
        TODO: Calculate success rate
        """
        pass
    
    def display_dashboard(self):
        """
        Display comprehensive monitoring dashboard.
        
        TODO: Get and display alert statistics
        TODO: Show top threats
        TODO: Display response statistics
        TODO: Show system health metrics
        TODO: Format output in readable table format
        """
        pass
    
    def export_report(self, output_file):
        """
        Export monitoring report to file.
        
        Args:
            output_file: Path to output file
        
        TODO: Gather all statistics
        TODO: Format as JSON or CSV
        TODO: Write to output file
        """
        pass

if __name__ == "__main__":
    dashboard = MonitoringDashboard()
    # TODO: Implement dashboard display
    # TODO: Add refresh capability
    # TODO: Allow report export
    pass
```

> 💡 **Dashboard Sections to Build:**
> - `get_alert_statistics()` — Counts by type and severity, last-hour and last-day totals
> - `get_top_threats()` — Ranked list of top 10 source IPs by alert volume
> - `get_response_statistics()` — Action type counts and success rate
> - `display_dashboard()` — Formatted table output with system health metrics

---

---

# ✅ Expected Outcomes

After completing this lab, you should have:

| ✅ | Deliverable |
|---|---|
| 🛡️ | Functional Security Onion installation with Zeek and Suricata |
| 📏 | Custom detection rules for both monitoring tools |
| 🐍 | Working Python scripts for anomaly detection |
| ⚡ | Automated response system for threat mitigation |
| 🧠 | Understanding of network traffic analysis workflows |
| 🔍 | Ability to identify and respond to security threats |

---

---

# 🔧 Troubleshooting Guide

---

### ❌ Issue: Security Onion Services Not Starting

![Security Onion](https://img.shields.io/badge/Service-Security_Onion-005F87?style=flat-square&logo=linux&logoColor=white)

```bash
# 💾 Check system resources (RAM, disk space)
free -h
df -h

# 🩺 Identify failed services
sudo so-status

# 📋 Review system logs
sudo tail -f /var/log/syslog
```

---

### ❌ Issue: No Logs Appearing in Kibana

![Kibana](https://img.shields.io/badge/Service-Kibana-E8478B?style=flat-square&logo=kibana&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Service-Elasticsearch-005571?style=flat-square&logo=elasticsearch&logoColor=white)

```bash
# 🔍 Verify Elasticsearch is running
sudo systemctl status elasticsearch

# ✅ Check index patterns are correctly configured
# → logstash-zeek-* and logstash-suricata-*

# 🌐 Ensure network interface is properly monitored
sudo so-interface-status
```

---

### ❌ Issue: Python Scripts Cannot Read Log Files

![Python](https://img.shields.io/badge/Tool-Python-3776AB?style=flat-square&logo=python&logoColor=white)

```bash
# 🔐 Run scripts with sudo or adjust file permissions
sudo python3 analyze_zeek_logs.py

# 📂 Verify log file paths exist
ls -la /nsm/zeek/logs/current/

# ⚙️ Check Security Onion log rotation settings
sudo so-zeek-logs
```

---

---

# 🎓 Conclusion

This lab provided hands-on experience with **Security Onion's network security monitoring** capabilities using Zeek and Suricata. You configured custom detection rules, analyzed network traffic logs, and developed automated anomaly detection and response systems — skills essential for **Security Operations Centers (SOCs)** and network defense teams.

---

## 💡 Key Takeaways

| 🔑 | Insight |
|---|---|
| 🔍 | **Zeek** provides rich protocol-level visibility through event-driven scripting |
| ⚔️ | **Suricata** delivers signature-based detection with high-performance rule matching |
| 🐍 | **Python automation** bridges log analysis and incident response workflows |
| ⚡ | **Automated response** with iptables reduces mean time to contain (MTTC) |
| 📊 | **Kibana dashboards** turn raw log data into actionable security intelligence |

---

## 🚀 Next Steps

- 📡 Analyze different network traffic patterns and refine detection rules
- 📏 Create additional Suricata rules based on emerging threat signatures
- 🔗 Integrate anomaly detector output with the automated response system
- 📊 Build Kibana dashboards for real-time SOC visualization
- 🤖 Explore machine learning-based anomaly detection techniques

---

> 📚 *Continue practicing by analyzing different traffic patterns and refining your detection rules based on emerging threats.*

---

<div align="center">

**Built for Al Nafi Cybersecurity Training**

![Security](https://img.shields.io/badge/Category-Network_Security-2980B9?style=for-the-badge&logo=shield&logoColor=white)
![Level](https://img.shields.io/badge/Level-Intermediate-orange?style=for-the-badge)
![Tasks](https://img.shields.io/badge/Tasks-3_Completed-green?style=for-the-badge)

</div>
