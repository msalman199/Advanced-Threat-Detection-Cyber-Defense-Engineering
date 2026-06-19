# 🔎 ScoutSuite AWS Security Posture Assessment

> **A hands-on cloud security lab using ScoutSuite to scan AWS infrastructure, analyze misconfigurations, and automate security reporting with Python.**

---

![ScoutSuite](https://img.shields.io/badge/ScoutSuite-Cloud_Auditor-8E44AD?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Cloud-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Boto3](https://img.shields.io/badge/Boto3-AWS_SDK-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![IAM](https://img.shields.io/badge/AWS-IAM-DD344C?style=for-the-badge&logo=amazonaws&logoColor=white)
![S3](https://img.shields.io/badge/AWS-S3-569A31?style=for-the-badge&logo=amazons3&logoColor=white)
![EC2](https://img.shields.io/badge/AWS-EC2-FF9900?style=for-the-badge&logo=amazonec2&logoColor=white)
![JSON](https://img.shields.io/badge/Reports-JSON_CSV_HTML-000000?style=for-the-badge&logo=json&logoColor=white)

---

## 🎯 Objectives

By the end of this lab, you will be able to:

- 🔧 Install and configure **ScoutSuite** for AWS security assessment
- 🔍 Execute **comprehensive security scans** of AWS infrastructure
- 📊 Analyze **security findings** and identify vulnerabilities
- 🐍 Create **automated Python scripts** for security reporting
- ⏰ Implement **scheduled security assessments** with alerting

---

## ✅ Prerequisites

| Skill | Level |
|---|---|
| ☁️ AWS services (EC2, S3, IAM, VPC) | Basic understanding |
| 🐧 Linux command line | Familiar |
| 🐍 Python programming | Basic |
| 🔐 AWS account with IAM permissions | Required |
| 🗂️ JSON data structures | Understanding |

---

## 🖥️ Lab Environment

> Al Nafi provides **Linux-based cloud machines** for this lab. Click **Start Lab** to access your pre-configured environment with **Python 3**, **pip**, and **AWS CLI** pre-installed.

---

---

# 🔧 Task 1 — Install and Configure ScoutSuite

---

## 🐍 Step 1.1 — Set Up Python Virtual Environment

> Create an isolated Python environment to avoid dependency conflicts.

```bash
# 📂 Create lab directory
mkdir ~/scoutsuite-lab && cd ~/scoutsuite-lab

# 🐍 Create and activate virtual environment
python3 -m venv scoutsuite-env
source scoutsuite-env/bin/activate

# ⬆️ Upgrade pip
pip install --upgrade pip
```

> 💡 **Why a virtual environment?** It keeps ScoutSuite's dependencies isolated from your system Python, preventing version conflicts with other tools.

---

## 📦 Step 1.2 — Install ScoutSuite

![pip](https://img.shields.io/badge/Package_Manager-pip-3776AB?style=flat-square&logo=python&logoColor=white)

> Install ScoutSuite and all required AWS dependencies.

```bash
# 🔎 Install ScoutSuite
pip install scoutsuite

# ☁️ Install AWS SDK
pip install boto3 botocore awscli

# ✅ Verify installation
scout --help
```

---

## 🔑 Step 1.3 — Configure AWS Credentials

![AWS CLI](https://img.shields.io/badge/File-setup__credentials.py-FF9900?style=flat-square&logo=amazonaws&logoColor=white)

> Set up AWS credentials so ScoutSuite can access and audit your cloud environment.

```bash
# 🔐 Configure AWS CLI interactively
aws configure
# Enter: Access Key ID, Secret Access Key, Region (us-east-1), Output format (json)

# ✅ Verify configuration
aws sts get-caller-identity
```

**📄 File:** `~/scoutsuite-lab/setup_credentials.py`

```python
#!/usr/bin/env python3
# setup_credentials.py

import os
import boto3

def verify_aws_credentials():
    """
    Verify AWS credentials are properly configured.
    
    TODO: Implement STS client creation
    TODO: Call get_caller_identity()
    TODO: Print account ID and ARN
    TODO: Handle exceptions and return True/False
    """
    pass

def setup_credentials():
    """
    Interactive AWS credentials setup.
    
    TODO: Prompt user for access key and secret key
    TODO: Create ~/.aws directory if not exists
    TODO: Write credentials to ~/.aws/credentials file
    TODO: Write config to ~/.aws/config file
    """
    pass

if __name__ == "__main__":
    setup_credentials()
    verify_aws_credentials()
```

> 💡 **Functions to Implement:**
> - `verify_aws_credentials()` — STS `get_caller_identity()` to confirm access
> - `setup_credentials()` — Write `~/.aws/credentials` and `~/.aws/config` interactively

---

---

# 🔍 Task 2 — Perform AWS Security Assessment

---

## 🚀 Step 2.1 — Execute ScoutSuite Scan

![ScoutSuite](https://img.shields.io/badge/Tool-ScoutSuite_Scanner-8E44AD?style=flat-square&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/Target-AWS_Infrastructure-FF9900?style=flat-square&logo=amazonaws&logoColor=white)

> Run a full security scan across all supported AWS services.

```bash
# 📂 Create results directory
mkdir ~/scoutsuite-lab/scan-results
cd ~/scoutsuite-lab/scan-results

# 🔍 Run ScoutSuite scan
scout aws --report-dir ./aws-report

# Scan will assess: IAM, EC2, S3, VPC, CloudTrail, RDS, Lambda, and more
```

> 📊 **Services Assessed by ScoutSuite:**

| Category | Services |
|---|---|
| 🔐 Identity | IAM users, roles, policies, MFA |
| 💻 Compute | EC2 instances, security groups, AMIs |
| 🗄️ Storage | S3 buckets, public access, encryption |
| 🌐 Networking | VPC, subnets, NACLs, flow logs |
| 📋 Audit | CloudTrail, Config, GuardDuty |
| 🗃️ Database | RDS instances, snapshots, encryption |
| ⚡ Serverless | Lambda functions, permissions |

---

## 📊 Step 2.2 — Analyze Scan Results

![Python](https://img.shields.io/badge/File-analyze__results.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Parse the ScoutSuite output file and build a structured analysis of all findings.

**📄 File:** `~/scoutsuite-lab/analyze_results.py`

```python
#!/usr/bin/env python3
# analyze_results.py

import json
import os
from collections import defaultdict

class ScoutSuiteAnalyzer:
    def __init__(self, report_dir):
        self.report_dir = report_dir
        self.results_file = os.path.join(report_dir, "scoutsuite-results", 
                                        "scoutsuite_results_aws.js")
        self.data = None
    
    def load_results(self):
        """
        Load ScoutSuite results from JavaScript file.
        
        TODO: Read the results file
        TODO: Extract JSON content (remove JS variable declaration)
        TODO: Parse JSON and store in self.data
        TODO: Handle file not found and JSON errors
        """
        pass
    
    def get_severity_summary(self):
        """
        Calculate findings by severity level.
        
        Returns:
            dict: Counts of danger, warning, and info findings
        
        TODO: Iterate through services in self.data
        TODO: Count findings by level (danger, warning, info)
        TODO: Return dictionary with severity counts
        """
        pass
    
    def get_service_findings(self):
        """
        Get findings count per AWS service.
        
        Returns:
            dict: Service names mapped to finding counts
        
        TODO: Extract services from self.data
        TODO: Count total findings per service
        TODO: Return sorted dictionary
        """
        pass
    
    def get_critical_findings(self, limit=10):
        """
        Extract top critical findings.
        
        Args:
            limit: Maximum number of findings to return
        
        Returns:
            list: Critical findings with details
        
        TODO: Filter findings with level='danger' or 'warning'
        TODO: Extract service, finding name, description, item count
        TODO: Sort by severity and count
        TODO: Return top N findings
        """
        pass
    
    def print_summary(self):
        """
        Print formatted summary report.
        
        TODO: Display scan timestamp
        TODO: Show severity breakdown
        TODO: List services with most findings
        TODO: Display top 5 critical issues
        """
        pass

if __name__ == "__main__":
    analyzer = ScoutSuiteAnalyzer("./aws-report")
    analyzer.load_results()
    analyzer.print_summary()
```

> 💡 **Key Methods to Implement:**
> - `load_results()` — Strip the JS variable wrapper and parse the JSON payload from `scoutsuite_results_aws.js`
> - `get_severity_summary()` — Count findings across `danger`, `warning`, and `info` levels
> - `get_service_findings()` — Map each AWS service to its total finding count
> - `get_critical_findings()` — Return top N findings sorted by severity and affected resource count

---

## 🌐 Step 2.3 — View Interactive HTML Report

![HTTP](https://img.shields.io/badge/Server-Python_HTTP-3776AB?style=flat-square&logo=python&logoColor=white)

> Serve the generated HTML report through a local web server for interactive exploration.

```bash
# 📂 Navigate to report directory
cd ~/scoutsuite-lab/scan-results/aws-report

# 🌐 Start HTTP server
python3 -m http.server 8080

# 🖥️ Access report at: http://localhost:8080
# ⛔ Press Ctrl+C to stop server when done
```

> ⚠️ **Note:** Use `http://` not `https://` — the local server does not have TLS configured.

---

---

# 🤖 Task 3 — Automate Security Reporting with Python

---

## ⚙️ Step 3.1 — Create Automated Scanner Script

![Python](https://img.shields.io/badge/File-automated__scanner.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Build a full end-to-end automation script that checks prerequisites, runs the scan, parses results, and exports reports.

**📄 File:** `~/scoutsuite-lab/automated_scanner.py`

```python
#!/usr/bin/env python3
# automated_scanner.py

import os
import sys
import json
import subprocess
from datetime import datetime
from pathlib import Path

class SecurityScanner:
    def __init__(self, output_dir="security-scans"):
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.scan_dir = self.output_dir / f"scan_{self.timestamp}"
    
    def check_prerequisites(self):
        """
        Verify required tools are installed.
        
        Returns:
            bool: True if all prerequisites met
        
        TODO: Check if 'scout' command exists
        TODO: Verify AWS credentials with 'aws sts get-caller-identity'
        TODO: Print status messages
        TODO: Return True/False
        """
        pass
    
    def run_scan(self):
        """
        Execute ScoutSuite scan.
        
        Returns:
            bool: True if scan successful
        
        TODO: Create scan directory
        TODO: Run subprocess: scout aws --report-dir <scan_dir>
        TODO: Capture output and handle errors
        TODO: Return success status
        """
        pass
    
    def parse_results(self):
        """
        Parse scan results and extract metrics.
        
        Returns:
            dict: Analysis results with metrics
        
        TODO: Load results file
        TODO: Extract services, findings, severity counts
        TODO: Calculate total findings
        TODO: Identify top issues
        TODO: Return analysis dictionary
        """
        pass
    
    def generate_executive_summary(self, analysis):
        """
        Create executive summary report.
        
        Args:
            analysis: Dictionary with scan analysis
        
        Returns:
            str: Formatted summary text
        
        TODO: Format scan timestamp and overview
        TODO: Display severity breakdown
        TODO: List top 10 services with findings
        TODO: Show critical issues
        TODO: Return formatted string
        """
        pass
    
    def export_reports(self, analysis):
        """
        Export reports in multiple formats.
        
        Args:
            analysis: Dictionary with scan analysis
        
        TODO: Save JSON report (security_analysis.json)
        TODO: Save text summary (executive_summary.txt)
        TODO: Save CSV of top issues (top_issues.csv)
        TODO: Print file paths
        """
        pass
    
    def run_assessment(self):
        """
        Execute complete assessment workflow.
        
        TODO: Check prerequisites
        TODO: Run scan
        TODO: Parse results
        TODO: Generate and export reports
        TODO: Display summary
        """
        pass

if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run_assessment()
```

> 💡 **Workflow Steps to Implement:**
> - `check_prerequisites()` — Verify `scout` binary exists and AWS credentials are valid
> - `run_scan()` — Use `subprocess` to call `scout aws --report-dir <scan_dir>`
> - `parse_results()` — Load and aggregate findings into a metrics dictionary
> - `export_reports()` — Write `security_analysis.json`, `executive_summary.txt`, and `top_issues.csv`

---

## ⏰ Step 3.2 — Create Scheduled Scanner with Notifications

![Python](https://img.shields.io/badge/File-scheduled__scanner.py-3776AB?style=flat-square&logo=python&logoColor=white)
![SMTP](https://img.shields.io/badge/Notification-Email_SMTP-EA4335?style=flat-square&logo=gmail&logoColor=white)

> Implement a scheduling system with scan history tracking, retention cleanup, threshold alerting, and email notifications.

**📄 File:** `~/scoutsuite-lab/scheduled_scanner.py`

```python
#!/usr/bin/env python3
# scheduled_scanner.py

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path

class ScheduledScanner:
    def __init__(self, config_file="scanner_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        self.setup_logging()
    
    def load_config(self):
        """
        Load scanner configuration.
        
        Returns:
            dict: Configuration settings
        
        TODO: Define default config (scan frequency, retention, thresholds)
        TODO: Load from file if exists
        TODO: Create default config file if not exists
        TODO: Return configuration dictionary
        """
        pass
    
    def setup_logging(self):
        """
        Configure logging system.
        
        TODO: Create logs directory
        TODO: Set up file and console handlers
        TODO: Configure log format and level
        """
        pass
    
    def should_run_scan(self):
        """
        Check if scan should run based on frequency.
        
        Returns:
            bool: True if scan should run
        
        TODO: Load scan history from file
        TODO: Compare last scan time with frequency setting
        TODO: Return True if enough time has passed
        """
        pass
    
    def update_scan_history(self, results):
        """
        Update scan history file.
        
        Args:
            results: Latest scan results
        
        TODO: Create history dictionary with timestamp and results
        TODO: Write to scan_history.json
        """
        pass
    
    def cleanup_old_scans(self):
        """
        Remove old scan directories based on retention policy.
        
        TODO: Get retention days from config
        TODO: Calculate cutoff date
        TODO: Iterate through scan directories
        TODO: Remove directories older than retention period
        """
        pass
    
    def check_thresholds(self, analysis):
        """
        Check if findings exceed alert thresholds.
        
        Args:
            analysis: Scan analysis results
        
        Returns:
            list: Alert messages if thresholds exceeded
        
        TODO: Get thresholds from config
        TODO: Compare critical and total findings
        TODO: Generate alert messages
        TODO: Return list of alerts
        """
        pass
    
    def send_notification(self, analysis):
        """
        Send email notification with results.
        
        Args:
            analysis: Scan analysis results
        
        TODO: Check if notifications enabled in config
        TODO: Create email message with summary
        TODO: Connect to SMTP server
        TODO: Send email to recipients
        TODO: Handle errors gracefully
        """
        pass
    
    def run_scheduled_scan(self):
        """
        Execute scheduled scan workflow.
        
        TODO: Check if scan should run
        TODO: Cleanup old scans
        TODO: Run security scanner
        TODO: Update history
        TODO: Check thresholds and send alerts
        """
        pass

if __name__ == "__main__":
    scanner = ScheduledScanner()
    scanner.run_scheduled_scan()
```

> 💡 **Scheduler Methods to Implement:**
> - `load_config()` — Load from `scanner_config.json` or create defaults
> - `should_run_scan()` — Compare `last_scan` timestamp in history against `scan_frequency_days`
> - `cleanup_old_scans()` — Delete scan dirs older than `retention_days`
> - `check_thresholds()` — Alert when critical findings exceed config thresholds
> - `send_notification()` — SMTP email summary to `recipient_emails`

---

## 📄 Step 3.3 — Create Configuration File

![JSON](https://img.shields.io/badge/File-scanner__config.json-000000?style=flat-square&logo=json&logoColor=white)

> Generate a configuration template for the scheduled scanner.

**📄 File:** `~/scoutsuite-lab/scanner_config.json`

```json
{
  "scan_frequency_days": 7,
  "retention_days": 30,
  "alert_thresholds": {
    "critical_findings": 5,
    "total_findings": 50
  },
  "email_notifications": {
    "enabled": false,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your-email@example.com",
    "sender_password": "your-app-password",
    "recipient_emails": ["security-team@example.com"]
  },
  "services_to_scan": ["iam", "ec2", "s3", "vpc", "cloudtrail", "rds"]
}
```

> 📊 **Configuration Fields:**

| Field | Default | Purpose |
|---|---|---|
| `scan_frequency_days` | 7 | Days between automated scans |
| `retention_days` | 30 | Days to keep old scan results |
| `critical_findings` threshold | 5 | Alert if critical findings exceed this |
| `total_findings` threshold | 50 | Alert if total findings exceed this |
| `email_notifications.enabled` | false | Toggle email alerting |
| `services_to_scan` | 6 services | AWS services to include in scan |

---

---

# ✅ Expected Outcomes

After completing this lab, you should have:

| ✅ | Deliverable |
|---|---|
| 🔎 | Functional ScoutSuite installation with AWS integration |
| 📊 | Comprehensive security scan results of your AWS environment |
| 🧠 | Understanding of common AWS security misconfigurations |
| 🐍 | Automated Python scripts for security assessment and reporting |
| ⏰ | Scheduled scanning system with alerting capabilities |
| 📋 | Multiple report formats (HTML, JSON, CSV, text) |

---

---

# 🔧 Troubleshooting Guide

---

### ❌ Issue: ScoutSuite Scan Fails with Permission Errors

![IAM](https://img.shields.io/badge/Service-AWS_IAM-DD344C?style=flat-square&logo=amazonaws&logoColor=white)

```bash
# ✅ Verify IAM user has SecurityAudit policy attached
aws iam list-attached-user-policies --user-name YOUR_USERNAME

# 🔑 Check AWS credentials are correctly configured
aws sts get-caller-identity

# 🔐 Ensure account has read permissions for all services
aws configure list
```

---

### ❌ Issue: Results File Not Found or Parsing Errors

![ScoutSuite](https://img.shields.io/badge/Tool-ScoutSuite-8E44AD?style=flat-square&logo=python&logoColor=white)

```bash
# ✅ Confirm scan completed successfully without errors
scout aws --report-dir ./aws-report

# 📂 Check report directory path is correct
ls -la ~/scoutsuite-lab/scan-results/aws-report/scoutsuite-results/

# 📄 Verify results file exists
ls -lh scoutsuite_results_aws.js
```

---

### ❌ Issue: Virtual Environment Activation Fails

![Python](https://img.shields.io/badge/Tool-Python_venv-3776AB?style=flat-square&logo=python&logoColor=white)

```bash
# ✅ Ensure Python 3.6+ is installed
python3 --version

# 🔗 Use full path to activate
source ~/scoutsuite-lab/scoutsuite-env/bin/activate

# 🪟 On Windows use:
scoutsuite-env\Scripts\activate
```

---

### ❌ Issue: HTML Report Not Accessible

![HTTP](https://img.shields.io/badge/Server-Python_HTTP-3776AB?style=flat-square&logo=python&logoColor=white)

```bash
# ✅ Verify HTTP server is running on correct port
python3 -m http.server 8080

# 🔥 Check firewall rules allow port 8080
sudo ufw status

# 🌐 Use http:// not https://
# → http://localhost:8080
```

---

---

# 🎓 Conclusion

This lab provided hands-on experience with **ScoutSuite for AWS security assessment**. You learned to install and configure the tool, execute comprehensive security scans, analyze findings across multiple AWS services, and automate the entire assessment process using Python.

---

## 💡 Key Takeaways

| 🔑 | Insight |
|---|---|
| 🔎 | ScoutSuite provides **automated security assessment** across 20+ AWS services |
| 📊 | Findings are categorized by **severity** (danger, warning, info) |
| ⏰ | Automation enables **regular security monitoring** and compliance tracking |
| 🐍 | Python scripting **extends ScoutSuite** capabilities for custom reporting |
| 🛡️ | Regular assessments help **identify and remediate** vulnerabilities before exploitation |

---

## 🚀 Next Steps

- ☁️ Scan **different AWS environments** and compare posture over time
- 🐍 Customize analysis scripts for **organization-specific compliance rules**
- 🔗 Integrate security assessments into **CI/CD pipelines**
- 📊 Build dashboards to track **security posture trends** across accounts
- 🤖 Explore **automated remediation** for common findings (e.g., enabling MFA, fixing public S3 buckets)

---

> 📚 *Continue practicing by scanning different AWS environments, customizing analysis scripts, and integrating security assessments into your CI/CD pipelines.*

---

<div align="center">

**Built for Al Nafi Cybersecurity Training**

![Security](https://img.shields.io/badge/Category-Cloud_Security-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Level](https://img.shields.io/badge/Level-Intermediate-orange?style=for-the-badge)
![Tasks](https://img.shields.io/badge/Tasks-3_Completed-green?style=for-the-badge)

</div>
