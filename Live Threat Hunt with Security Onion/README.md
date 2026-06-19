
# 🛡️ Live Threat Hunt with Security Onion + ELK

<div align="center">

![Security Onion](https://img.shields.io/badge/Security%20Onion-Network%20Monitoring-purple?style=for-the-badge)
![ELK Stack](https://img.shields.io/badge/ELK-Log%20Analytics-green?style=for-the-badge&logo=elastic)
![Suricata](https://img.shields.io/badge/Suricata-IDS-red?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Containerized-blue?style=for-the-badge&logo=docker)
![Python](https://img.shields.io/badge/Python-3.x-yellow?style=for-the-badge&logo=python)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-Search%20Engine-darkgreen?style=for-the-badge)
![Kibana](https://img.shields.io/badge/Kibana-Visualization-orange?style=for-the-badge)
![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04-orange?style=for-the-badge&logo=ubuntu)

# 🚨 Enterprise Threat Hunting with Security Onion & ELK

### 🔍 Live Monitoring • 📊 Threat Analytics • 🚨 Detection Engineering • 🛡️ Incident Response

</div>

---

# 📖 Overview

This hands-on cybersecurity lab introduces students to **Enterprise Security Monitoring and Threat Hunting** using **Security Onion**, **Suricata IDS**, and the **ELK Stack (Elasticsearch, Logstash, Kibana)**.

Students will deploy a complete security monitoring platform, ingest security telemetry, build automated threat hunting tools, generate dashboards, and perform live threat investigations.

The lab simulates real-world SOC operations where analysts continuously monitor, investigate, and respond to security events.

---

# 🎯 Learning Objectives

By the end of this lab, students will be able to:

✅ Deploy Security Onion components using Docker

✅ Configure Suricata IDS for threat detection

✅ Integrate ELK Stack for centralized logging

✅ Create custom intrusion detection rules

✅ Perform live threat hunting

✅ Develop automated threat detection scripts

✅ Generate security dashboards and reports

✅ Build continuous monitoring workflows

✅ Investigate security incidents using Elasticsearch

---

# 🧰 Technology Stack

| Category | Technologies |
|-----------|-------------|
| Security Monitoring | Security Onion |
| IDS | Suricata |
| Search Engine | Elasticsearch |
| Visualization | Kibana |
| Log Processing | Logstash |
| Containerization | Docker |
| Programming | Python 3.x |
| Data Analysis | Pandas |
| Operating System | Ubuntu 20.04 |
| Threat Hunting | ELK Stack |
| Automation | Python Scripts |
| Incident Response | Security Analytics |

---

# 📚 Prerequisites

Before beginning this lab, ensure you have:

### 💻 Linux Skills

- Linux command-line proficiency
- File management
- Process management

### 🌐 Networking Knowledge

- TCP/IP fundamentals
- Ports and protocols
- Network communication

### 🔍 Security Knowledge

- Log analysis concepts
- Security monitoring basics
- Intrusion detection fundamentals

### 🐍 Programming Skills

- Basic Python programming
- Functions and loops
- JSON fundamentals

---

# 🖥️ Lab Environment

## ☁️ Al Nafi Cloud Machine

### Environment Specifications

| Resource | Configuration |
|-----------|--------------|
| Operating System | Ubuntu 20.04 LTS |
| RAM | 8 GB |
| Storage | 100 GB |
| Access | Root Privileges |
| Network | Internet Enabled |

### ✅ Preconfigured Resources

- Ubuntu 20.04 LTS
- Internet Connectivity
- Root Access
- Security Monitoring Environment

---

# 🚀 Task 1: Deploy Security Onion Components with Docker

---

## ⚙️ Step 1.1: Install Docker and Docker Compose

```bash
# Update system and install prerequisites
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git vim net-tools

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" \
-o /usr/local/bin/docker-compose

sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

### 🎯 Purpose

Install Docker components required for Security Onion deployment.

---

## 📂 Step 1.2: Create Security Onion Directory Structure

```bash
sudo mkdir -p /opt/so/{conf,logs,rules}

cd /opt/so

sudo chown -R $USER:$USER /opt/so
```

### 🎯 Purpose

Prepare directories for configurations, logs, and detection rules.

---

## 🐳 Step 1.3: Configure Docker Compose Security Stack

### 📄 File: `/opt/so/docker-compose.yml`

```yaml
version: '3.8'

services:

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.0
    container_name: so-elasticsearch
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
    volumes:
      - es_data:/usr/share/elasticsearch/data
    networks:
      - so-net

  kibana:
    image: docker.elastic.co/kibana/kibana:7.17.0
    container_name: so-kibana
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch
    networks:
      - so-net

  logstash:
    image: docker.elastic.co/logstash/logstash:7.17.0
    container_name: so-logstash
    ports:
      - "5044:5044"
    volumes:
      - ./conf/logstash.conf:/usr/share/logstash/pipeline/logstash.conf
      - ./logs:/var/log/security
    depends_on:
      - elasticsearch
    networks:
      - so-net

  suricata:
    image: jasonish/suricata:latest
    container_name: so-suricata
    network_mode: host
    cap_add:
      - NET_ADMIN
      - SYS_NICE
    volumes:
      - ./conf/suricata.yaml:/etc/suricata/suricata.yaml
      - ./rules/suricata.rules:/etc/suricata/rules/suricata.rules
      - ./logs:/var/log/suricata
    command: suricata -c /etc/suricata/suricata.yaml -i lo

volumes:
  es_data:

networks:
  so-net:
    driver: bridge
```

---

## 🛡️ Step 1.4: Configure Suricata IDS

### 📄 File: `/opt/so/conf/suricata.yaml`

```yaml
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

default-log-dir: /var/log/suricata/

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            packet: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - ssh
        - flow

rule-files:
  - /etc/suricata/rules/suricata.rules
```

---

## 🚨 Step 1.5: Create Custom Detection Rules

### 📄 File: `/opt/so/rules/suricata.rules`

```suricata
# SSH Brute Force Detection
alert tcp any any -> $HOME_NET 22 (
msg:"Potential SSH Brute Force";
flow:to_server,established;
content:"SSH";
threshold:type both, track by_src, count 5, seconds 60;
sid:1000001;
rev:1;
)

# Directory Traversal
alert tcp any any -> $HOME_NET 80 (
msg:"Directory Traversal Attempt";
flow:to_server,established;
content:"../";
sid:1000002;
rev:1;
)

# Port Scan Detection
alert tcp any any -> $HOME_NET any (
msg:"Potential Port Scan";
flags:S;
threshold:type threshold, track by_src, count 10, seconds 60;
sid:1000003;
rev:1;
)

# SQL Injection
alert http any any -> $HOME_NET any (
msg:"SQL Injection Attempt";
content:"UNION";
nocase;
content:"SELECT";
nocase;
distance:0;
sid:1000004;
rev:1;
)

# Suspicious Scanner
alert http any any -> $HOME_NET any (
msg:"Suspicious Scanner User Agent";
content:"User-Agent|3a| sqlmap";
sid:1000005;
rev:1;
)
```

---

# 🚀 Task 2: Configure ELK Stack for Security Log Analysis

---

## 📊 Step 2.1: Configure Logstash Pipeline

### 📄 File: `/opt/so/conf/logstash.conf`

```ruby
input {
  file {
    path => "/var/log/security/eve.json"
    start_position => "beginning"
    codec => "json"
    type => "suricata"
  }
}

filter {

  if [type] == "suricata" {

    if [event_type] == "alert" {
      mutate {
        add_tag => ["threat"]
      }
    }

    date {
      match => [ "timestamp", "ISO8601" ]
    }

  }

}

output {

  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "security-logs-%{+YYYY.MM.dd}"
  }

}
```

---

## ▶️ Step 2.2: Start Security Stack

```bash
cd /opt/so

docker-compose up -d

sleep 60

docker-compose ps
```

---

## 🧪 Step 2.3: Generate Test Security Events

### 📄 File: `/tmp/generate_events.sh`

```bash
#!/bin/bash

for i in {1..15}
do
logger -t sshd \
"Failed password for invalid user test$i from 192.168.1.100 port 22 ssh2"

sleep 1
done

for i in {1..5}
do
curl -s "http://localhost/../etc/passwd" > /dev/null 2>&1
sleep 2
done

echo "Test security events generated"
```

Run:

```bash
chmod +x /tmp/generate_events.sh

/tmp/generate_events.sh
```

---

## 🔍 Step 2.4: Verify Data Ingestion

```bash
curl -s \
"http://localhost:9200/_cat/indices?v" \
| grep security-logs
```

### Query Threat Events

```bash
curl -s -X GET \
"http://localhost:9200/security-logs-*/_search?pretty" \
-H 'Content-Type: application/json' \
-d'
{
  "query": {
    "match": {
      "tags": "threat"
    }
  },
  "size": 5
}'
```

---

## 📈 Step 2.5: Configure Kibana

```bash
until curl -s http://localhost:5601/api/status \
| grep -q "available"
do
  echo "Waiting for Kibana..."
  sleep 5
done
```

Create Index Pattern:

```bash
curl -X POST \
"localhost:5601/api/saved_objects/index-pattern/security-logs" \
-H "Content-Type: application/json" \
-H "kbn-xsrf: true" \
-d '{
  "attributes": {
    "title": "security-logs-*",
    "timeFieldName": "@timestamp"
  }
}'
```

---

# 🚀 Task 3: Develop Automated Threat Detection Scripts

---

## 🐍 Step 3.1: Install Python Dependencies

```bash
pip3 install elasticsearch requests pandas matplotlib
```

---

## 🔍 Step 3.2: Create Threat Hunter

### 📄 File: `/opt/so/threat_hunter.py`

```python
#!/usr/bin/env python3

"""
Automated Threat Hunter
Students Complete TODO Sections
"""

from elasticsearch import Elasticsearch
from datetime import datetime

class ThreatHunter:

    def __init__(
        self,
        es_host='localhost',
        es_port=9200
    ):

        # TODO:
        # Create Elasticsearch connection
        pass

    def search_threats(
        self,
        hours_back=24
    ):

        # TODO:
        # Query threat events
        pass

    def detect_brute_force(
        self,
        threshold=5
    ):

        # TODO:
        # Detect brute force
        pass

    def detect_port_scans(self):

        # TODO:
        # Detect port scans
        pass

    def analyze_dns_queries(self):

        # TODO:
        # Analyze DNS anomalies
        pass

    def generate_threat_report(self):

        print("=" * 60)
        print("SECURITY THREAT HUNT REPORT")
        print("=" * 60)

        # TODO:
        # Build report
        pass

def main():

    hunter = ThreatHunter()

    hunter.generate_threat_report()

if __name__ == "__main__":
    main()
```

---

## 🚨 Step 3.3: Create Continuous Monitor

### 📄 File: `/opt/so/continuous_monitor.py`

```python
#!/usr/bin/env python3

import time

from elasticsearch import Elasticsearch

class ContinuousMonitor:

    def __init__(self):

        # TODO:
        # Elasticsearch connection
        pass

    def check_real_time_threats(self):

        alerts = []

        # TODO:
        # Check recent threats

        return alerts

    def log_alert(self, alert):

        # TODO:
        # Write JSON alerts
        pass

    def send_notification(self, alerts):

        # TODO:
        # Display alerts
        pass

    def run_monitor(self, interval=60):

        print(
            f"Monitoring every {interval} seconds..."
        )

        # TODO:
        # Monitoring loop
        pass
```

---

## 📊 Step 3.4: Create Security Dashboard Generator

### 📄 File: `/opt/so/security_dashboard.py`

```python
#!/usr/bin/env python3

import matplotlib.pyplot as plt

from elasticsearch import Elasticsearch

class SecurityDashboard:

    def __init__(self):

        # TODO:
        # Elasticsearch connection
        pass

    def get_threat_timeline(self):

        # TODO:
        # Timeline aggregation
        pass

    def get_top_threat_sources(self):

        # TODO:
        # Source aggregation
        pass

    def create_threat_timeline_chart(self):

        # TODO:
        # Generate chart
        pass

    def create_threat_sources_chart(self):

        # TODO:
        # Generate chart
        pass

    def generate_executive_summary(self):

        print("=" * 70)
        print("EXECUTIVE SECURITY SUMMARY")
        print("=" * 70)

        # TODO:
        # Generate report
        pass

def main():

    dashboard = SecurityDashboard()

    dashboard.generate_executive_summary()

    dashboard.create_threat_timeline_chart()

    dashboard.create_threat_sources_chart()

if __name__ == "__main__":
    main()
```

---

# 🏆 Expected Outcomes

After completing this lab you should have:

✅ Fully Functional Security Onion Environment

✅ Working ELK Stack Deployment

✅ Operational Suricata IDS

✅ Custom Threat Detection Rules

✅ Automated Threat Hunting Scripts

✅ Real-Time Monitoring System

✅ Security Dashboards and Visualizations

✅ Incident Response Reporting Capabilities

✅ Enterprise Security Monitoring Experience

---

# 🔧 Troubleshooting Guide

---

## ❌ Docker Containers Fail to Start

Check Memory:

```bash
free -h
```

Verify Docker:

```bash
sudo systemctl status docker
```

View Logs:

```bash
docker-compose logs
```

---

## ❌ Elasticsearch Connection Refused

Verify Service:

```bash
curl http://localhost:9200
```

View Logs:

```bash
docker logs so-elasticsearch
```

Wait:

```bash
sleep 90
```

---

## ❌ No Data Appearing in Kibana

Check Indices:

```bash
curl http://localhost:9200/_cat/indices
```

Check Logstash:

```bash
docker logs so-logstash
```

Verify Events:

```bash
cat /var/log/auth.log | grep Failed
```

---

## ❌ Python Import Errors

Install Missing Packages:

```bash
pip3 install elasticsearch requests pandas matplotlib
```

Verify Version:

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

🛡️ Deploy Security Onion

📊 Analyze Logs with ELK

🚨 Configure Suricata IDS

🔍 Perform Live Threat Hunting

🐍 Automate Detection Workflows

📈 Build Security Dashboards

⚡ Create Continuous Monitoring Pipelines

🛠️ Investigate Security Incidents

---

# 🚀 Next Steps

### Advanced Challenges

- 🔥 Create Additional Suricata Rules
- 🔥 Integrate Threat Intelligence Feeds
- 🔥 Build Custom Kibana Dashboards
- 🔥 Add Email Alerting
- 🔥 Implement Machine Learning Detection
- 🔥 Integrate Sigma Rules
- 🔥 Expand DNS Threat Analytics
- 🔥 Deploy Multi-Node ELK Clusters

---

# 📜 Conclusion

This lab provided practical experience with enterprise-grade security monitoring using **Security Onion**, **Suricata IDS**, and the **ELK Stack**. Through deploying containerized security infrastructure, configuring intrusion detection, building automated threat hunting tools, and visualizing security events, students gained real-world SOC analyst and security engineering skills.

The techniques learned in this lab form the foundation of modern threat detection, incident response, security monitoring, and cybersecurity operations.

---

<div align="center">

### 🛡️ Monitor • Detect • Hunt • Respond

## 🚨 Live Threat Hunt with Security Onion + ELK

⭐ Happy Threat Hunting! ⭐

</div>
````
