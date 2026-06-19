# 🛡️ Deploy Wazuh SIEM in AWS for Log Collection and Alerting

> **A hands-on cybersecurity lab deploying Wazuh SIEM on AWS to collect, analyze, and alert on cloud security logs using Terraform, custom rules, and Python automation.**

---

![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-005F87?style=for-the-badge&logo=wazuh&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Cloud-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Terraform](https://img.shields.io/badge/Terraform-IaC-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Containers-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![CloudTrail](https://img.shields.io/badge/AWS-CloudTrail-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![GuardDuty](https://img.shields.io/badge/AWS-GuardDuty-DD344C?style=for-the-badge&logo=amazonaws&logoColor=white)
![EC2](https://img.shields.io/badge/AWS-EC2-FF9900?style=for-the-badge&logo=amazonec2&logoColor=white)

---

## 🎯 Objectives

By the end of this lab, you will be able to:

- ☁️ Deploy **Wazuh SIEM platform on AWS** using infrastructure as code
- 📋 Configure Wazuh to **collect and process AWS security logs**
- 🐍 Implement **Python automation** for log analysis and alert generation
- 📏 Create **custom rules and decoders** for threat detection
- 📊 Generate **security intelligence reports** from collected logs

---

## ✅ Prerequisites

| Skill | Level |
|---|---|
| 🐧 Linux command line | Basic |
| ☁️ AWS services (EC2, VPC, CloudTrail) | Understanding |
| 🐍 Python programming | Fundamentals |
| 📊 SIEM concepts & log analysis | Familiar |

---

## 🖥️ Lab Environment

> Al Nafi provides **pre-configured cloud machines** with all necessary tools. Click **Start Lab** to access your environment. No additional setup required.

| Component | Role |
|---|---|
| 🏗️ Terraform | Infrastructure as Code deployment |
| ☁️ AWS CLI | Cloud resource management |
| 🐍 Python 3.x + pip | Automation & analysis scripts |
| 🐳 Docker & Docker Compose | Wazuh container orchestration |
| ✏️ Text editors (nano, vim) | Configuration editing |
| 🌐 Network utilities | Connectivity verification |

---

---

# 🔧 Task 1 — Deploy Wazuh Infrastructure on AWS

---

## 🔑 Step 1.1 — Configure AWS Credentials

> Set up your AWS access credentials before provisioning any resources.

```bash
# 📂 Create project directory
mkdir ~/wazuh-lab && cd ~/wazuh-lab

# 🔐 Configure AWS credentials
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = YOUR_ACCESS_KEY_HERE
aws_secret_access_key = YOUR_SECRET_KEY_HERE
EOF

cat > ~/.aws/config << EOF
[default]
region = us-east-1
output = json
EOF
```

> ⚠️ **Security Note:** Never commit AWS credentials to version control. Use IAM roles or environment variables in production environments.

---

## 🏗️ Step 1.2 — Create Terraform Configuration

![Terraform](https://img.shields.io/badge/File-main.tf-7B42BC?style=flat-square&logo=terraform&logoColor=white)

> Create the main infrastructure definition file for VPC, subnet, security group, and EC2 instance.

**📄 File:** `~/wazuh-lab/main.tf`

```hcl
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "us-east-1"
}

variable "instance_type" {
  default = "t3.medium"
}

# 🌐 VPC and Networking
resource "aws_vpc" "wazuh_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = { Name = "wazuh-vpc" }
}

resource "aws_internet_gateway" "wazuh_igw" {
  vpc_id = aws_vpc.wazuh_vpc.id
  tags = { Name = "wazuh-igw" }
}

resource "aws_subnet" "wazuh_subnet" {
  vpc_id                  = aws_vpc.wazuh_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  tags = { Name = "wazuh-subnet" }
}

resource "aws_route_table" "wazuh_rt" {
  vpc_id = aws_vpc.wazuh_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.wazuh_igw.id
  }
  tags = { Name = "wazuh-rt" }
}

resource "aws_route_table_association" "wazuh_rta" {
  subnet_id      = aws_subnet.wazuh_subnet.id
  route_table_id = aws_route_table.wazuh_rt.id
}

# 🔐 Security Group
resource "aws_security_group" "wazuh_sg" {
  name        = "wazuh-sg"
  description = "Wazuh security group"
  vpc_id      = aws_vpc.wazuh_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 1514
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "wazuh-sg" }
}

# 🔑 SSH Key
resource "aws_key_pair" "wazuh_key" {
  key_name   = "wazuh-key"
  public_key = file("~/.ssh/id_rsa.pub")
}

# 🖥️ Wazuh Manager Instance
resource "aws_instance" "wazuh_manager" {
  ami                    = "ami-0c02fb55956c7d316"
  instance_type          = var.instance_type
  key_name              = aws_key_pair.wazuh_key.key_name
  vpc_security_group_ids = [aws_security_group.wazuh_sg.id]
  subnet_id             = aws_subnet.wazuh_subnet.id

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = file("${path.module}/install-wazuh.sh")

  tags = {
    Name = "wazuh-manager"
    Type = "SIEM"
  }
}

output "wazuh_public_ip" {
  value = aws_instance.wazuh_manager.public_ip
}

output "wazuh_dashboard" {
  value = "https://${aws_instance.wazuh_manager.public_ip}"
}
```

> 📌 **Resources Provisioned:**
> - 🌐 VPC with public subnet and internet gateway
> - 🔐 Security group allowing SSH (22), HTTPS (443), and agent ports (1514–1515)
> - 🖥️ EC2 `t3.medium` instance with 30GB gp3 storage

---

## 📜 Step 1.3 — Create Installation Script

![Bash](https://img.shields.io/badge/File-install--wazuh.sh-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Docker](https://img.shields.io/badge/Runtime-Docker_Compose-2496ED?style=flat-square&logo=docker&logoColor=white)

> Create the user-data shell script that bootstraps Wazuh via Docker on the EC2 instance.

**📄 File:** `~/wazuh-lab/install-wazuh.sh`

```bash
#!/bin/bash
set -e

# 🔄 Update system
yum update -y

# 🐳 Install Docker
yum install -y docker
systemctl start docker
systemctl enable docker

# 📦 Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# 📂 Create Wazuh directory
mkdir -p /opt/wazuh
cd /opt/wazuh

# ⬇️ Download Wazuh Docker Compose
curl -so docker-compose.yml \
    https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.7.0/single-node/docker-compose.yml

# 🚀 Start Wazuh
docker-compose up -d

# 📁 Create log directories
mkdir -p /var/log/aws-logs /opt/wazuh-config
chown -R 1000:1000 /var/log/aws-logs /opt/wazuh-config

echo "Wazuh installation completed" > /var/log/wazuh-install.log
```

```bash
# 🔐 Make script executable
chmod +x install-wazuh.sh
```

---

## 🚀 Step 1.4 — Deploy Infrastructure

> Generate SSH keys and apply the Terraform plan to provision all AWS resources.

```bash
# 🔑 Generate SSH key if needed
[ ! -f ~/.ssh/id_rsa ] && ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ""

# ⚙️ Initialize and apply Terraform
terraform init
terraform validate
terraform plan
terraform apply -auto-approve

# 💾 Save the public IP
export WAZUH_IP=$(terraform output -raw wazuh_public_ip)
echo "Wazuh IP: $WAZUH_IP"
```

---

## ✅ Step 1.5 — Verify Deployment

> Wait approximately 5 minutes for the installation to complete, then verify services.

```bash
# ⏳ Wait for instance readiness
sleep 300

# 🔌 Test SSH connection
ssh -i ~/.ssh/id_rsa -o StrictHostKeyChecking=no ec2-user@$WAZUH_IP "sudo docker ps"

# 🩺 Check Wazuh services
ssh -i ~/.ssh/id_rsa ec2-user@$WAZUH_IP \
    "sudo docker-compose -f /opt/wazuh/docker-compose.yml ps"
```

---

---

# 📋 Task 2 — Configure AWS Log Collection

---

## 🔍 Step 2.1 — Create Custom Decoders

![XML](https://img.shields.io/badge/File-aws--decoders.xml-F16529?style=flat-square&logoColor=white)
![Wazuh](https://img.shields.io/badge/Target-Wazuh_Manager-005F87?style=flat-square&logoColor=white)

> SSH into the Wazuh manager and create custom decoders for CloudTrail and GuardDuty log formats.

```bash
ssh -i ~/.ssh/id_rsa ec2-user@$WAZUH_IP

# 📂 Create decoder directory
sudo mkdir -p /opt/wazuh-config/decoders
```

**📄 File:** `/opt/wazuh-config/decoders/aws-decoders.xml`

```bash
sudo tee /opt/wazuh-config/decoders/aws-decoders.xml << 'EOF'
<decoder name="aws-cloudtrail">
  <parent>json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

<decoder name="aws-cloudtrail-event">
  <parent>aws-cloudtrail</parent>
  <regex>^.*"eventName":"(\w+)".*"sourceIPAddress":"([^"]+)"</regex>
  <order>aws.eventName,aws.sourceIP</order>
</decoder>

<decoder name="aws-guardduty">
  <parent>json</parent>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
EOF
```

> 📌 **Decoders Created:**
> - `aws-cloudtrail` — Base JSON decoder for CloudTrail events
> - `aws-cloudtrail-event` — Extracts `eventName` and `sourceIPAddress` via regex
> - `aws-guardduty` — Base JSON decoder for GuardDuty findings

---

## 📏 Step 2.2 — Create Custom Rules

![XML](https://img.shields.io/badge/File-aws--rules.xml-F16529?style=flat-square&logoColor=white)

> Create detection rules that trigger alerts on high-risk AWS events and GuardDuty findings.

**📄 File:** `/opt/wazuh-config/rules/aws-rules.xml`

```bash
sudo tee /opt/wazuh-config/rules/aws-rules.xml << 'EOF'
<group name="aws,">

  <!-- ℹ️ Level 3: Base CloudTrail event -->
  <rule id="80200" level="3">
    <decoded_as>aws-cloudtrail</decoded_as>
    <description>AWS CloudTrail event detected</description>
    <group>aws,cloudtrail,</group>
  </rule>

  <!-- ⚠️ Level 5: Console login -->
  <rule id="80201" level="5">
    <if_sid>80200</if_sid>
    <field name="aws.eventName">ConsoleLogin</field>
    <description>AWS Console login detected</description>
    <group>aws,authentication,</group>
  </rule>

  <!-- 🔴 Level 10: Critical IAM operations -->
  <rule id="80202" level="10">
    <if_sid>80200</if_sid>
    <field name="aws.eventName">^(CreateUser|DeleteUser|AttachUserPolicy)$</field>
    <description>AWS IAM critical operation: $(aws.eventName)</description>
    <group>aws,iam,critical,</group>
  </rule>

  <!-- 🌐 Level 8: External IP login -->
  <rule id="80203" level="8">
    <if_sid>80201</if_sid>
    <field name="aws.sourceIP">!^10\.|!^192\.168\.</field>
    <description>AWS login from external IP: $(aws.sourceIP)</description>
    <group>aws,external_access,</group>
  </rule>

  <!-- ⚠️ Level 7: GuardDuty finding -->
  <rule id="80300" level="7">
    <decoded_as>aws-guardduty</decoded_as>
    <description>AWS GuardDuty finding</description>
    <group>aws,guardduty,</group>
  </rule>

  <!-- 🚨 Level 12: GuardDuty HIGH severity -->
  <rule id="80301" level="12">
    <if_sid>80300</if_sid>
    <field name="aws.severity">^[8-9]\.|^10\.</field>
    <description>GuardDuty HIGH severity: $(aws.title)</description>
    <group>aws,guardduty,high_severity,</group>
  </rule>

</group>
EOF
```

> 📊 **Rule Severity Levels:**

| Rule ID | Level | Trigger |
|---|---|---|
| 80200 | 3 — Info | Any CloudTrail event |
| 80201 | 5 — Warning | Console login |
| 80202 | 10 — Critical | IAM user/policy changes |
| 80203 | 8 — High | Login from external IP |
| 80300 | 7 — Medium | Any GuardDuty finding |
| 80301 | 12 — Critical | GuardDuty severity ≥ 8.0 |

---

## ⚙️ Step 2.3 — Configure Log Collection

![Config](https://img.shields.io/badge/File-ossec--aws.conf-005F87?style=flat-square&logoColor=white)

> Tell Wazuh which log files to monitor on the local filesystem.

**📄 File:** `/opt/wazuh-config/ossec-aws.conf`

```bash
sudo tee /opt/wazuh-config/ossec-aws.conf << 'EOF'
<ossec_config>

  <!-- 📋 CloudTrail JSON logs -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/aws-logs/cloudtrail.json</location>
  </localfile>

  <!-- 🛡️ GuardDuty findings -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/aws-logs/guardduty.json</location>
  </localfile>

  <!-- 🌐 VPC Flow Logs -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/aws-logs/vpc-flow.log</location>
  </localfile>

</ossec_config>
EOF
```

---

## 🧪 Step 2.4 — Create Sample AWS Logs

> Generate sample log files to test the decoders and rules before real data is available.

```bash
sudo mkdir -p /var/log/aws-logs

# 📋 CloudTrail sample — Console login from external IP
sudo tee /var/log/aws-logs/cloudtrail.json << 'EOF'
{"eventVersion":"1.05","userIdentity":{"type":"IAMUser","principalId":"AIDAI123456789","arn":"arn:aws:iam::123456789012:user/admin","accountId":"123456789012","userName":"admin"},"eventTime":"2024-01-15T10:30:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.45","userAgent":"Mozilla/5.0","responseElements":{"ConsoleLogin":"Success"}}
EOF

# 🛡️ GuardDuty sample — SSH brute force HIGH severity
sudo tee /var/log/aws-logs/guardduty.json << 'EOF'
{"schemaVersion":"2.0","accountId":"123456789012","region":"us-east-1","type":"UnauthorizedAccess:EC2/SSHBruteForce","severity":8.5,"title":"SSH brute force attack detected","description":"EC2 instance is performing SSH brute force attacks","createdAt":"2024-01-15T10:30:00Z"}
EOF

sudo chown -R 1000:1000 /var/log/aws-logs
```

---

---

# 🐍 Task 3 — Implement Python Log Analysis Automation

---

## 🤖 Step 3.1 — Create Python Analysis Framework

![Python](https://img.shields.io/badge/File-wazuh--log--analyzer.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Build the main log processor that reads AWS logs, scores risk, and generates alerts.

**📄 File:** `~/wazuh-log-analyzer.py`

```python
#!/usr/bin/env python3
"""
Wazuh AWS Log Analyzer
Students: Complete the TODO sections to implement full functionality
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# ⚙️ Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class WazuhLogAnalyzer:
    """Analyzes AWS logs and generates security alerts"""
    
    def __init__(self, log_directory: str):
        """
        Initialize the log analyzer
        
        Args:
            log_directory: Path to AWS logs directory
        """
        self.log_directory = log_directory
        self.alerts = []
        
    def load_logs(self, log_file: str) -> List[Dict]:
        """
        Load and parse JSON log files
        
        Args:
            log_file: Name of the log file
            
        Returns:
            List of parsed log entries
        """
        # TODO: Implement file reading
        # TODO: Parse JSON entries (handle multi-line JSON)
        # TODO: Return list of log dictionaries
        pass
    
    def analyze_cloudtrail_event(self, event: Dict) -> Dict:
        """
        Analyze a CloudTrail event for security risks
        
        Args:
            event: CloudTrail event dictionary
            
        Returns:
            Analysis results with risk score and alerts
        """
        analysis = {
            'event_name': event.get('eventName'),
            'source_ip': event.get('sourceIPAddress'),
            'user': event.get('userIdentity', {}).get('userName'),
            'timestamp': event.get('eventTime'),
            'risk_score': 0,
            'risk_factors': []
        }
        
        # TODO: Implement risk scoring logic
        # TODO: Check for external IP addresses (not 10.x, 192.168.x, 172.16-31.x)
        # TODO: Identify high-risk events (IAM changes, security group modifications)
        # TODO: Detect unusual timing (outside business hours)
        # TODO: Calculate total risk score
        
        return analysis
    
    def analyze_guardduty_finding(self, finding: Dict) -> Dict:
        """
        Analyze GuardDuty finding
        
        Args:
            finding: GuardDuty finding dictionary
            
        Returns:
            Analysis results
        """
        # TODO: Extract severity, type, and description
        # TODO: Categorize threat level
        # TODO: Generate recommendations
        pass
    
    def generate_alert(self, analysis: Dict) -> Optional[Dict]:
        """
        Generate alert if risk threshold exceeded
        
        Args:
            analysis: Event analysis results
            
        Returns:
            Alert dictionary or None
        """
        # TODO: Check if risk_score exceeds threshold (e.g., >= 7)
        # TODO: Create alert with severity, message, and recommendations
        # TODO: Return alert dictionary
        pass
    
    def create_threat_report(self, events: List[Dict]) -> Dict:
        """
        Generate comprehensive threat intelligence report
        
        Args:
            events: List of analyzed events
            
        Returns:
            Threat intelligence report
        """
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_events': len(events),
            'high_risk_count': 0,
            'unique_ips': set(),
            'event_types': {},
            'recommendations': []
        }
        
        # TODO: Count high-risk events (risk_score >= 7)
        # TODO: Track unique source IPs
        # TODO: Aggregate event types
        # TODO: Generate security recommendations
        # TODO: Convert sets to lists for JSON serialization
        
        return report
    
    def save_alerts(self, output_file: str):
        """
        Save generated alerts to file
        
        Args:
            output_file: Path to output file
        """
        # TODO: Write alerts to JSON file
        # TODO: Handle file I/O errors
        pass
    
    def run_analysis(self):
        """Execute complete analysis workflow"""
        logging.info("Starting log analysis")
        
        # TODO: Load CloudTrail logs
        # TODO: Load GuardDuty findings
        # TODO: Analyze each event
        # TODO: Generate alerts for high-risk events
        # TODO: Create threat intelligence report
        # TODO: Save results
        
        logging.info("Analysis complete")

def main():
    """Main execution function"""
    # TODO: Initialize analyzer
    # TODO: Run analysis
    # TODO: Display summary statistics
    pass

if __name__ == "__main__":
    main()
```

> 💡 **Key Methods to Implement:**
> - `load_logs()` — Read and parse JSON log files from disk
> - `analyze_cloudtrail_event()` — Risk-score each CloudTrail event
> - `analyze_guardduty_finding()` — Categorize GuardDuty severity
> - `generate_alert()` — Trigger alerts when score ≥ threshold
> - `create_threat_report()` — Aggregate stats into an intel report

---

## 📢 Step 3.2 — Create Alert Generator Module

![Python](https://img.shields.io/badge/File-alert__generator.py-3776AB?style=flat-square&logo=python&logoColor=white)
![SMTP](https://img.shields.io/badge/Notification-Email_SMTP-EA4335?style=flat-square&logo=gmail&logoColor=white)

> Build a module for formatting, logging, and optionally emailing security alerts.

**📄 File:** `~/alert-generator.py`

```python
#!/usr/bin/env python3
"""
Alert Generator Module
Students: Implement alert generation and notification logic
"""

import json
import smtplib
from email.mime.text import MIMEText
from typing import Dict, List

class AlertGenerator:
    """Generates and sends security alerts"""
    
    def __init__(self, config: Dict):
        """
        Initialize alert generator
        
        Args:
            config: Configuration dictionary with SMTP settings
        """
        self.config = config
        
    def create_alert_message(self, alert: Dict) -> str:
        """
        Format alert as human-readable message
        
        Args:
            alert: Alert dictionary
            
        Returns:
            Formatted alert message
        """
        # TODO: Create formatted alert message
        # TODO: Include severity, timestamp, description
        # TODO: Add recommendations
        pass
    
    def send_email_alert(self, alert: Dict, recipients: List[str]) -> bool:
        """
        Send alert via email
        
        Args:
            alert: Alert dictionary
            recipients: List of email addresses
            
        Returns:
            True if successful, False otherwise
        """
        # TODO: Create email message
        # TODO: Connect to SMTP server
        # TODO: Send email
        # TODO: Handle errors
        pass
    
    def log_alert(self, alert: Dict, log_file: str):
        """
        Write alert to log file
        
        Args:
            alert: Alert dictionary
            log_file: Path to log file
        """
        # TODO: Append alert to log file in JSON format
        pass
```

---

## ⚙️ Step 3.3 — Create Configuration File

![JSON](https://img.shields.io/badge/File-wazuh--config.json-000000?style=flat-square&logo=json&logoColor=white)

> Define all runtime settings for the analyzer in a single configuration file.

**📄 File:** `~/wazuh-config.json`

```bash
cat > ~/wazuh-config.json << 'EOF'
{
  "log_directory": "/var/log/aws-logs",
  "output_directory": "/var/log/wazuh-analysis",
  "risk_thresholds": {
    "low": 3,
    "medium": 5,
    "high": 7,
    "critical": 9
  },
  "high_risk_events": [
    "CreateUser",
    "DeleteUser",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "CreateAccessKey",
    "DeleteAccessKey",
    "PutUserPolicy",
    "CreateRole",
    "DeleteRole"
  ],
  "alert_settings": {
    "enabled": true,
    "email_notifications": false,
    "log_file": "/var/log/wazuh-alerts.json"
  }
}
EOF
```

> 📊 **Risk Score Thresholds:**

| Level | Score | Action |
|---|---|---|
| 🟢 Low | ≥ 3 | Log only |
| 🟡 Medium | ≥ 5 | Log + flag for review |
| 🔴 High | ≥ 7 | Generate alert |
| 🚨 Critical | ≥ 9 | Immediate alert + notify |

---

## ▶️ Step 3.4 — Test the Analysis Script

> Run the analyzer against the sample logs and review the output.

```bash
# 🔐 Make script executable
chmod +x ~/wazuh-log-analyzer.py

# 🚀 Run analysis
python3 ~/wazuh-log-analyzer.py

# 📋 View generated alerts
cat /var/log/wazuh-alerts.json | jq '.'
```

---

---

# 📊 Task 4 — Create Monitoring Dashboard

---

## 📈 Step 4.1 — Generate Summary Statistics

![Python](https://img.shields.io/badge/File-generate--statistics.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Build a statistics generator to summarize alert data by severity, event type, and source IP.

**📄 File:** `~/generate-statistics.py`

```python
#!/usr/bin/env python3
"""
Statistics Generator
Students: Complete the implementation
"""

import json
from collections import Counter
from datetime import datetime

def generate_statistics(alerts_file: str) -> Dict:
    """
    Generate statistics from alerts
    
    Args:
        alerts_file: Path to alerts JSON file
        
    Returns:
        Statistics dictionary
    """
    stats = {
        'total_alerts': 0,
        'severity_distribution': {},
        'top_event_types': [],
        'top_source_ips': [],
        'hourly_distribution': {}
    }
    
    # TODO: Load alerts from file
    # TODO: Count alerts by severity
    # TODO: Find most common event types
    # TODO: Identify top source IPs
    # TODO: Calculate hourly distribution
    
    return stats

def print_report(stats: Dict):
    """Print formatted statistics report"""
    # TODO: Format and print statistics
    pass

if __name__ == "__main__":
    stats = generate_statistics('/var/log/wazuh-alerts.json')
    print_report(stats)
```

> 💡 **Statistics to Implement:**
> - 📊 Alert count by severity (low / medium / high / critical)
> - 🔝 Top 10 most frequent event types
> - 🌐 Top source IP addresses
> - 🕐 Hourly alert distribution for trend analysis

---

## ⏰ Step 4.2 — Create Automated Monitoring Script

![Bash](https://img.shields.io/badge/File-monitor--wazuh.sh-4EAA25?style=flat-square&logo=gnubash&logoColor=white)

> Create a shell script that ties together analysis, statistics, and critical alert detection.

**📄 File:** `~/monitor-wazuh.sh`

```bash
cat > ~/monitor-wazuh.sh << 'EOF'
#!/bin/bash

LOG_DIR="/var/log/aws-logs"
ANALYSIS_SCRIPT="$HOME/wazuh-log-analyzer.py"
STATS_SCRIPT="$HOME/generate-statistics.py"

# 🔍 Run analysis
python3 $ANALYSIS_SCRIPT

# 📊 Generate statistics
python3 $STATS_SCRIPT

# 🚨 Check for critical alerts
CRITICAL_COUNT=$(jq '[.[] | select(.severity == "CRITICAL")] | length' /var/log/wazuh-alerts.json)

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    echo "⚠️  WARNING: $CRITICAL_COUNT critical alerts detected!"
    # TODO: Send notification
fi

echo "✅ Monitoring cycle completed at $(date)"
EOF

chmod +x ~/monitor-wazuh.sh
```

---

---

# ✅ Expected Outcomes

After completing this lab, you should have:

| ✅ | Deliverable |
|---|---|
| 🛡️ | Functional Wazuh SIEM deployment on AWS |
| 📏 | Custom decoders and rules for AWS log analysis |
| 🐍 | Python automation scripts for log processing |
| 🧠 | Understanding of threat detection and alert generation |
| 📊 | Experience with security monitoring workflows |

**Students should be able to:**
- 🔍 Identify security events in AWS logs
- 🧮 Calculate risk scores for different activities
- 📢 Generate actionable security alerts
- 📋 Create threat intelligence reports

---

---

# 🔧 Troubleshooting Guide

---

### ❌ Issue: Terraform Deployment Fails

![Terraform](https://img.shields.io/badge/Tool-Terraform-7B42BC?style=flat-square&logo=terraform&logoColor=white)
![AWS](https://img.shields.io/badge/Service-AWS_IAM-FF9900?style=flat-square&logo=amazonaws&logoColor=white)

```bash
# ✅ Verify AWS credentials are correct
cat ~/.aws/credentials

# 🔑 Check that SSH key exists
ls ~/.ssh/id_rsa.pub

# 🔐 Ensure sufficient AWS permissions (EC2, VPC creation)
aws iam get-user

# 📋 Review Terraform error messages for specific issues
terraform plan
```

---

### ❌ Issue: Cannot Access Wazuh Dashboard

![Docker](https://img.shields.io/badge/Service-Docker-2496ED?style=flat-square&logo=docker&logoColor=white)
![Wazuh](https://img.shields.io/badge/Service-Wazuh-005F87?style=flat-square&logoColor=white)

```bash
# ⏳ Wait 5-10 minutes for Docker containers to fully start

# 🔐 Check security group allows port 443
terraform show | grep ingress

# 🩺 Verify services are running
ssh ec2-user@$WAZUH_IP "sudo docker ps"

# 📋 Check instance logs
ssh ec2-user@$WAZUH_IP "sudo cat /var/log/wazuh-install.log"
```

---

### ❌ Issue: Python Script Cannot Read Logs

![Python](https://img.shields.io/badge/Tool-Python-3776AB?style=flat-square&logo=python&logoColor=white)

```bash
# 📂 Verify log files exist
ls -la /var/log/aws-logs/

# 🔐 Check file permissions
sudo chmod 644 /var/log/aws-logs/*.json

# ✅ Ensure JSON format is valid
cat /var/log/aws-logs/cloudtrail.json | jq '.'

# 📋 Review Python error messages for specific parsing issues
python3 ~/wazuh-log-analyzer.py 2>&1
```

---

---

# 🎓 Conclusion

This lab provided hands-on experience **deploying and configuring Wazuh SIEM** for AWS security monitoring. You learned to deploy infrastructure using Terraform, configure custom detection rules and decoders, implement automated log analysis with Python, and generate security alerts and threat intelligence.

---

## 💡 Key Takeaways

| 🔑 | Insight |
|---|---|
| 🏗️ | **Terraform** enables repeatable, version-controlled infrastructure deployments |
| 📏 | **Custom rules and decoders** extend Wazuh to handle any log format |
| 🐍 | **Python automation** accelerates log analysis at scale |
| 📢 | **Structured alerting** turns raw logs into actionable intelligence |
| ☁️ | **Cloud SIEM integration** is essential for modern security operations |

---

## 🚀 Next Steps

- ➕ Add more AWS log sources (VPC Flow Logs, AWS Config)
- 📏 Implement additional detection rules for new attack patterns
- ⚡ Create automated response actions (Lambda remediation)
- 🎫 Integrate with ticketing systems (Jira, ServiceNow)
- 🤖 Explore **Wazuh API** for advanced automation
- 📊 Create custom dashboards for security metrics
- 🔬 Practice incident response workflows

---

## 🧹 Cleanup

> ⚠️ To avoid unexpected AWS charges, destroy the infrastructure when you're done.

```bash
cd ~/wazuh-lab
terraform destroy -auto-approve
```

---

> 📚 *These skills are essential for security operations and cloud security monitoring roles. Continue practicing by expanding log sources, refining detection rules, and building automated response capabilities.*

---

<div align="center">

**Built for Al Nafi Cybersecurity Training**

![Security](https://img.shields.io/badge/Category-Cloud_Security-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Level](https://img.shields.io/badge/Level-Intermediate-orange?style=for-the-badge)
![Tasks](https://img.shields.io/badge/Tasks-4_Completed-green?style=for-the-badge)

</div>
