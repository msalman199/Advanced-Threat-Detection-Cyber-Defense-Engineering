# 🔐 Prowler AWS Security Posture Assessment

> **A hands-on cloud security lab using Prowler to scan AWS infrastructure for misconfigurations, analyze compliance posture, and automate professional security reporting with Python.**

---

![Prowler](https://img.shields.io/badge/Prowler-AWS_Auditor-FF6B35?style=for-the-badge&logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-Cloud-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04_LTS-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![CIS](https://img.shields.io/badge/Compliance-CIS_1.5_AWS-DD344C?style=for-the-badge&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data_Analysis-150458?style=for-the-badge&logo=pandas&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Matplotlib-Visualizations-11557C?style=for-the-badge&logo=python&logoColor=white)
![JSON](https://img.shields.io/badge/Reports-JSON_CSV_HTML-000000?style=for-the-badge&logo=json&logoColor=white)

---

## 🎯 Objectives

By the end of this lab, you will be able to:

- 🔧 Install and configure **Prowler** for AWS security assessments
- 🚀 Execute security scans using **Prowler CLI and Python automation**
- 📊 Analyze **security findings** and identify critical vulnerabilities
- 📋 Generate **professional security reports** with visualizations
- ⏰ Implement **automated scanning workflows** for continuous security monitoring

---

## ✅ Prerequisites

| Skill | Level |
|---|---|
| ☁️ AWS services (IAM, S3, EC2, RDS) | Basic understanding |
| 🐧 Linux command line operations | Familiar |
| 🐍 Python programming | Basic |
| 🔒 Cloud security concepts & compliance frameworks | Understanding |

---

## 🖥️ Lab Environment

> **Ready-to-Use Cloud Machines:** Al Nafi provides **Linux-based cloud machines** for this lab. Click **Start Lab** to access your pre-configured environment with:

| Component | Version |
|---|---|
| 🐧 Ubuntu | 22.04 LTS |
| 🐍 Python | 3.10+ |
| ☁️ AWS CLI | Pre-installed |
| 🛠️ Git & development tools | Pre-installed |

---

---

# 🔧 Task 1 — Install and Configure Prowler

---

## 🐍 Step 1 — Set Up Python Environment

> Install system dependencies, create an isolated virtual environment, and install Prowler.

```bash
# 🔄 Update system and install dependencies
sudo apt update && sudo apt install -y python3-pip python3-venv git

# 📂 Create lab directory and virtual environment
mkdir ~/prowler-lab && cd ~/prowler-lab
python3 -m venv prowler-env
source prowler-env/bin/activate

# 📦 Install Prowler
pip install prowler
prowler --version
```

> 💡 **Activate the virtual environment** (`source prowler-env/bin/activate`) every time you open a new terminal session before running any scripts.

---

## 🔑 Step 2 — Configure AWS Credentials

![AWS CLI](https://img.shields.io/badge/File-~/.aws/credentials-FF9900?style=flat-square&logo=amazonaws&logoColor=white)

> Set up AWS credential profiles for the lab environment.

```bash
# 📂 Create AWS credentials directory
mkdir -p ~/.aws

# 🔐 Create credentials file (simulated for lab)
cat > ~/.aws/credentials << 'EOF'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[security-audit]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = us-west-2
EOF

# ⚙️ Create config file
cat > ~/.aws/config << 'EOF'
[default]
region = us-east-1
output = json

[profile security-audit]
region = us-west-2
output = json
EOF
```

> ⚠️ **Lab Note:** The credentials above are simulated example values. In a real environment, replace them with valid IAM credentials that have `SecurityAudit` policy attached.

---

## 🔍 Step 3 — Explore Prowler Capabilities

> Familiarize yourself with all available Prowler options before executing any scans.

```bash
# 📋 Display help and available options
prowler --help

# ☁️ List available AWS services
prowler aws --list-services

# 📏 List compliance frameworks
prowler aws --list-compliance

# ✅ List available checks
prowler aws --list-checks
```

---

## ⚙️ Step 4 — Create Prowler Configuration

![YAML](https://img.shields.io/badge/File-config.yaml-CB171E?style=flat-square&logo=yaml&logoColor=white)

> Create a custom Prowler configuration to define which services, regions, and compliance frameworks to assess.

```bash
# 📂 Create configuration directory
mkdir -p ~/.prowler
```

**📄 File:** `~/.prowler/config.yaml`

```bash
cat > ~/.prowler/config.yaml << 'EOF'
aws:
  profile: default
  regions: []
  services:
    - iam
    - s3
    - ec2
    - rds
    - cloudtrail
  output:
    formats:
      - json
      - csv
      - html
    directory: "./reports"
  compliance:
    - cis_1.5_aws
    - aws_foundational_security_standard
EOF
```

> 📊 **Configuration Overview:**

| Setting | Value | Purpose |
|---|---|---|
| `profile` | default | AWS credentials profile to use |
| `services` | 5 services | Scope of the security scan |
| `output.formats` | JSON, CSV, HTML | Report output formats |
| `compliance` | CIS 1.5 + FSS | Compliance frameworks to evaluate |

---

---

# 🤖 Task 2 — Automate Security Scanning with Python

---

## 🚀 Step 1 — Create Basic Automation Script

![Python](https://img.shields.io/badge/File-prowler__automation.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Build a CLI-driven automation wrapper that runs basic, compliance, and service-specific Prowler scans.

**📄 File:** `~/prowler-lab/prowler_automation.py`

```python
#!/usr/bin/env python3
"""
Prowler AWS Security Assessment Automation
Students: Complete the TODO sections to implement full functionality
"""

import os
import sys
import json
import subprocess
import datetime
from pathlib import Path
import argparse
import logging

class ProwlerAutomation:
    def __init__(self, profile='default', regions=None, output_dir='./reports'):
        """
        Initialize Prowler automation
        
        Args:
            profile: AWS profile name
            regions: List of AWS regions to scan
            output_dir: Directory for scan results
        """
        self.profile = profile
        self.regions = regions or []
        self.output_dir = Path(output_dir)
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging for the automation script"""
        # TODO: Configure logging with both file and console handlers
        # TODO: Set appropriate log format with timestamp
        pass
        
    def create_output_directory(self):
        """
        Create timestamped output directory
        
        Returns:
            Path object for the created directory
        """
        # TODO: Generate timestamp in format YYYYMMDD_HHMMSS
        # TODO: Create directory path with timestamp
        # TODO: Create directory and return path
        pass
        
    def run_basic_scan(self, services=None):
        """
        Execute basic Prowler security scan
        
        Args:
            services: List of AWS services to scan
            
        Returns:
            Tuple of (scan_directory, output)
        """
        # TODO: Create output directory
        # TODO: Build prowler command with appropriate arguments
        # TODO: Add regions and services if specified
        # TODO: Execute command using subprocess
        # TODO: Handle errors and return results
        pass
        
    def run_compliance_scan(self, framework='cis_1.5_aws'):
        """
        Execute compliance-specific scan
        
        Args:
            framework: Compliance framework identifier
            
        Returns:
            Tuple of (scan_directory, output)
        """
        # TODO: Create output directory
        # TODO: Build prowler compliance command
        # TODO: Execute scan and capture results
        # TODO: Return scan directory and output
        pass
        
    def run_service_specific_scan(self, service):
        """
        Execute service-specific security scan
        
        Args:
            service: AWS service name (e.g., 's3', 'iam')
            
        Returns:
            Tuple of (scan_directory, output)
        """
        # TODO: Validate service name
        # TODO: Build service-specific scan command
        # TODO: Execute scan and handle results
        pass

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Prowler AWS Security Automation')
    parser.add_argument('--profile', default='default', help='AWS profile to use')
    parser.add_argument('--scan-type', choices=['basic', 'compliance', 'service'], 
                       default='basic', help='Type of scan to perform')
    parser.add_argument('--framework', default='cis_1.5_aws', 
                       help='Compliance framework')
    parser.add_argument('--service', help='Service name for service-specific scan')
    parser.add_argument('--regions', nargs='+', help='AWS regions to scan')
    parser.add_argument('--output-dir', default='./reports', help='Output directory')
    
    args = parser.parse_args()
    
    # TODO: Initialize ProwlerAutomation with parsed arguments
    # TODO: Execute appropriate scan based on scan_type
    # TODO: Display results and exit with appropriate status code
    pass

if __name__ == "__main__":
    main()
```

> 💡 **Methods to Implement:**
> - `setup_logging()` — File + console handlers with timestamp format
> - `create_output_directory()` — Timestamped folder under `output_dir`
> - `run_basic_scan()` — `subprocess` call to `prowler aws --profile ...`
> - `run_compliance_scan()` — Add `--compliance <framework>` flag
> - `run_service_specific_scan()` — Add `--service <name>` flag

---

## 📊 Step 2 — Create Advanced Scanner with Report Generation

![Python](https://img.shields.io/badge/File-advanced__scanner.py-3776AB?style=flat-square&logo=python&logoColor=white)
![Matplotlib](https://img.shields.io/badge/Output-Charts_&_Graphs-11557C?style=flat-square&logo=python&logoColor=white)

> Build a comprehensive scanner that runs all scan types, analyzes results, and generates visual reports and executive summaries.

**📄 File:** `~/prowler-lab/advanced_scanner.py`

```python
#!/usr/bin/env python3
"""
Advanced Prowler Scanner with Analysis and Reporting
Students: Implement the analysis and visualization functions
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
from pathlib import Path

class AdvancedProwlerScanner:
    def __init__(self, config_file=None):
        """
        Initialize advanced scanner
        
        Args:
            config_file: Path to configuration file
        """
        self.config = self.load_config(config_file)
        self.results = {}
        self.scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def load_config(self, config_file):
        """
        Load configuration from file or use defaults
        
        Args:
            config_file: Path to JSON/YAML config file
            
        Returns:
            Configuration dictionary
        """
        # TODO: Define default configuration
        # TODO: Load user configuration if file exists
        # TODO: Merge configurations and return
        pass
        
    def execute_comprehensive_scan(self):
        """
        Execute comprehensive security assessment across all services
        
        Returns:
            Path to output directory
        """
        # TODO: Create timestamped output directory
        # TODO: Iterate through configured services
        # TODO: Execute scan for each service
        # TODO: Execute compliance scans
        # TODO: Store results and return output directory
        pass
        
    def analyze_results(self, scan_dir):
        """
        Analyze scan results and generate insights
        
        Args:
            scan_dir: Directory containing scan results
            
        Returns:
            Dictionary with analysis results
        """
        analysis = {
            'total_findings': 0,
            'severity_breakdown': {},
            'service_breakdown': {},
            'compliance_scores': {},
            'top_issues': []
        }
        
        # TODO: Find all JSON result files in scan_dir
        # TODO: Parse each JSON file
        # TODO: Count findings by severity
        # TODO: Count findings by service
        # TODO: Calculate compliance scores
        # TODO: Identify top issues
        
        return analysis
        
    def generate_visualizations(self, analysis, output_dir):
        """
        Generate charts and visualizations from analysis
        
        Args:
            analysis: Analysis results dictionary
            output_dir: Directory to save visualizations
        """
        # TODO: Create figure with multiple subplots
        # TODO: Generate severity breakdown pie chart
        # TODO: Generate service breakdown bar chart
        # TODO: Generate compliance score chart
        # TODO: Add summary statistics
        # TODO: Save figure to output directory
        pass
        
    def generate_executive_report(self, analysis, output_dir):
        """
        Generate executive summary report in Markdown
        
        Args:
            analysis: Analysis results dictionary
            output_dir: Directory to save report
        """
        # TODO: Create report header with timestamp
        # TODO: Add executive summary section
        # TODO: Add key findings with statistics
        # TODO: Add severity breakdown
        # TODO: Add service analysis
        # TODO: Add recommendations section
        # TODO: Save report as Markdown file
        pass

def main():
    """Main execution function"""
    # TODO: Initialize AdvancedProwlerScanner
    # TODO: Execute comprehensive scan
    # TODO: Analyze results
    # TODO: Generate visualizations
    # TODO: Generate executive report
    # TODO: Display summary
    pass

if __name__ == "__main__":
    main()
```

> 💡 **Key Methods to Implement:**
> - `analyze_results()` — Parse all JSON files in scan dir, aggregate by severity and service
> - `generate_visualizations()` — Severity pie chart + service bar chart + compliance score chart saved as PNG
> - `generate_executive_report()` — Markdown report with summary, findings, and recommendations

---

## 📋 Step 3 — Create Report Analysis Script

![Python](https://img.shields.io/badge/File-report__analyzer.py-3776AB?style=flat-square&logo=python&logoColor=white)
![Pandas](https://img.shields.io/badge/Library-Pandas-150458?style=flat-square&logo=pandas&logoColor=white)

> Build a standalone report analyzer that loads existing scan results and exports findings to CSV and text summaries.

**📄 File:** `~/prowler-lab/report_analyzer.py`

```python
#!/usr/bin/env python3
"""
Prowler Report Analysis and Processing
Students: Complete the analysis functions
"""

import json
import pandas as pd
from pathlib import Path
import argparse

class ProwlerReportAnalyzer:
    def __init__(self, report_directory):
        """
        Initialize report analyzer
        
        Args:
            report_directory: Path to directory containing Prowler reports
        """
        self.report_dir = Path(report_directory)
        self.findings = []
        self.analysis_results = {}
        
    def load_json_reports(self):
        """Load all JSON reports from directory"""
        # TODO: Find all JSON files recursively
        # TODO: Parse each JSON file
        # TODO: Extract findings from different JSON structures
        # TODO: Store findings in self.findings list
        pass
        
    def analyze_severity_distribution(self):
        """
        Analyze distribution of findings by severity
        
        Returns:
            Dictionary with severity counts
        """
        # TODO: Count findings for each severity level
        # TODO: Store in analysis_results
        # TODO: Return severity counts
        pass
        
    def analyze_service_distribution(self):
        """
        Analyze distribution of findings by AWS service
        
        Returns:
            Dictionary with service counts
        """
        # TODO: Count findings for each AWS service
        # TODO: Sort by count descending
        # TODO: Return service distribution
        pass
        
    def identify_critical_findings(self, limit=10):
        """
        Identify top critical security findings
        
        Args:
            limit: Maximum number of findings to return
            
        Returns:
            List of critical findings
        """
        # TODO: Filter findings by CRITICAL severity
        # TODO: Sort by importance/impact
        # TODO: Return top N findings
        pass
        
    def generate_summary_report(self, output_file='summary_report.txt'):
        """
        Generate text summary report
        
        Args:
            output_file: Path to output file
        """
        # TODO: Create report header
        # TODO: Add severity distribution
        # TODO: Add service distribution
        # TODO: Add critical findings
        # TODO: Add recommendations
        # TODO: Write to file
        pass
        
    def export_to_csv(self, output_file='findings.csv'):
        """
        Export findings to CSV format
        
        Args:
            output_file: Path to output CSV file
        """
        # TODO: Convert findings to DataFrame
        # TODO: Select relevant columns
        # TODO: Export to CSV
        pass

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='Analyze Prowler Reports')
    parser.add_argument('report_dir', help='Directory containing Prowler reports')
    parser.add_argument('--output', default='analysis_results', 
                       help='Output directory for analysis')
    
    args = parser.parse_args()
    
    # TODO: Initialize analyzer
    # TODO: Load reports
    # TODO: Perform analysis
    # TODO: Generate reports
    # TODO: Export results
    pass

if __name__ == "__main__":
    main()
```

> 💡 **Key Methods to Implement:**
> - `load_json_reports()` — Recursively find and parse all `.json` files in the report directory
> - `analyze_severity_distribution()` — Count CRITICAL / HIGH / MEDIUM / LOW / INFO findings
> - `identify_critical_findings()` — Filter and sort by impact, return top N
> - `export_to_csv()` — Convert `self.findings` list to a Pandas DataFrame and save

---

## 📦 Step 4 — Install Required Dependencies

> Install all Python packages needed for analysis and visualization.

```bash
# 📦 Install Python packages for analysis and visualization
pip install pandas matplotlib seaborn pyyaml

# 🔐 Make scripts executable
chmod +x prowler_automation.py advanced_scanner.py report_analyzer.py
```

---

---

# 🏃 Task 3 — Execute Scans and Generate Reports

---

## 🔍 Step 1 — Run Basic Security Scan

![Scan](https://img.shields.io/badge/Scan_Type-Basic-4EAA25?style=flat-square&logoColor=white)

```bash
# 🚀 Execute basic scan with your automation script
python3 prowler_automation.py \
    --scan-type basic \
    --profile default \
    --output-dir ./basic_scan_results

# 📂 Verify output directory was created
ls -la ./basic_scan_results/
```

---

## 📏 Step 2 — Run Compliance Scans

![CIS](https://img.shields.io/badge/Framework-CIS_1.5_AWS-DD344C?style=flat-square&logoColor=white)
![FSS](https://img.shields.io/badge/Framework-AWS_FSS-FF9900?style=flat-square&logo=amazonaws&logoColor=white)

```bash
# 📋 Run CIS 1.5 compliance scan
python3 prowler_automation.py \
    --scan-type compliance \
    --framework cis_1.5_aws \
    --output-dir ./cis_scan_results

# 📋 Run AWS Foundational Security Standard scan
python3 prowler_automation.py \
    --scan-type compliance \
    --framework aws_foundational_security_standard \
    --output-dir ./fss_scan_results
```

---

## 🎯 Step 3 — Run Service-Specific Scans

![S3](https://img.shields.io/badge/Service-S3_Buckets-569A31?style=flat-square&logo=amazons3&logoColor=white)
![IAM](https://img.shields.io/badge/Service-IAM_Config-DD344C?style=flat-square&logo=amazonaws&logoColor=white)

```bash
# 🗄️ Scan S3 buckets
python3 prowler_automation.py \
    --scan-type service \
    --service s3 \
    --output-dir ./s3_scan_results

# 🔐 Scan IAM configuration
python3 prowler_automation.py \
    --scan-type service \
    --service iam \
    --output-dir ./iam_scan_results
```

---

## 📊 Step 4 — Analyze Results and Generate Reports

```bash
# 🤖 Run comprehensive analysis
python3 advanced_scanner.py

# 🔍 Analyze specific scan results
python3 report_analyzer.py ./basic_scan_results --output ./analysis_output

# 📂 View generated reports
ls -la ./analysis_output/
cat ./analysis_output/summary_report.txt
```

---

## 📄 Step 5 — Create Custom Report Script

![Python](https://img.shields.io/badge/File-custom__report.py-3776AB?style=flat-square&logo=python&logoColor=white)
![HTML](https://img.shields.io/badge/Output-HTML_Report-E34F26?style=flat-square&logo=html5&logoColor=white)

> Build a custom report generator that produces HTML reports, executive summaries, and remediation action plans.

**📄 File:** `~/prowler-lab/custom_report.py`

```python
#!/usr/bin/env python3
"""
Custom Security Report Generator
Students: Implement custom reporting logic
"""

import json
from pathlib import Path
from datetime import datetime

def generate_html_report(findings, output_file='security_report.html'):
    """
    Generate HTML security report
    
    Args:
        findings: List of security findings
        output_file: Path to output HTML file
    """
    # TODO: Create HTML template
    # TODO: Add CSS styling
    # TODO: Generate findings table
    # TODO: Add severity indicators
    # TODO: Write to file
    pass

def generate_executive_summary(analysis):
    """
    Generate executive summary for management
    
    Args:
        analysis: Analysis results dictionary
        
    Returns:
        Formatted summary string
    """
    # TODO: Create executive summary template
    # TODO: Add key metrics
    # TODO: Add risk assessment
    # TODO: Add recommendations
    # TODO: Return formatted summary
    pass

def generate_remediation_plan(critical_findings):
    """
    Generate remediation action plan
    
    Args:
        critical_findings: List of critical security findings
        
    Returns:
        Remediation plan dictionary
    """
    # TODO: Prioritize findings
    # TODO: Create action items
    # TODO: Assign severity-based timelines
    # TODO: Add remediation steps
    # TODO: Return structured plan
    pass

if __name__ == "__main__":
    # TODO: Load findings from scan results
    # TODO: Generate HTML report
    # TODO: Generate executive summary
    # TODO: Generate remediation plan
    pass
```

> 💡 **Functions to Implement:**
> - `generate_html_report()` — Full HTML page with styled findings table and severity color indicators
> - `generate_executive_summary()` — Key metrics, risk assessment, and top recommendations for management
> - `generate_remediation_plan()` — Prioritized action items with severity-based timelines (24h / 7d / 30d)

---

---

# ✅ Expected Outcomes

After completing this lab, you should have:

| ✅ | Deliverable |
|---|---|
| 🔎 | Functional Prowler installation with proper AWS configuration |
| 🐍 | Python automation scripts for executing various types of security scans |
| 🧠 | Ability to analyze security findings and identify critical vulnerabilities |
| 📋 | Generated security reports in multiple formats (JSON, CSV, HTML) |
| 🔒 | Understanding of AWS security best practices and compliance frameworks |
| 📊 | Custom report generation capabilities for different stakeholders |

---

---

# 🔧 Troubleshooting Guide

---

### ❌ Issue: Prowler Installation Fails

![pip](https://img.shields.io/badge/Tool-pip-3776AB?style=flat-square&logo=python&logoColor=white)

```bash
# ✅ Check Python version (3.8+ required)
python3 --version

# ⬆️ Upgrade pip and retry
pip install --upgrade pip
pip install prowler --no-cache-dir
```

---

### ❌ Issue: AWS Credentials Not Found

![AWS CLI](https://img.shields.io/badge/Service-AWS_CLI-FF9900?style=flat-square&logo=amazonaws&logoColor=white)

```bash
# 📋 Verify credentials file exists and has correct format
cat ~/.aws/credentials

# ✅ List active configuration
aws configure list
```

---

### ❌ Issue: Scan Produces No Results

![Prowler](https://img.shields.io/badge/Tool-Prowler-FF6B35?style=flat-square&logo=python&logoColor=white)

```bash
# Check that:
# ✅ AWS credentials are valid (in production environment)
aws sts get-caller-identity

# 🔐 Proper IAM permissions are configured
aws iam list-attached-user-policies --user-name YOUR_USERNAME

# 🌐 Network connectivity to AWS services is available
curl -I https://sts.amazonaws.com

# 📋 Prowler command syntax is correct
prowler aws --help
```

---

### ❌ Issue: Python Script Execution Errors

![Python](https://img.shields.io/badge/Tool-Python-3776AB?style=flat-square&logo=python&logoColor=white)

```bash
# 🐍 Verify virtual environment is activated
source ~/prowler-lab/prowler-env/bin/activate

# 📦 All required packages are installed
pip list

# 🔐 Script has execute permissions
chmod +x prowler_automation.py advanced_scanner.py report_analyzer.py

# 🔍 Python path is correct
which python3
```

---

---

# 🎓 Conclusion

This lab provided hands-on experience with **Prowler**, a powerful AWS security assessment tool. You learned to install and configure Prowler for automated security scanning, create Python automation scripts for various scan types, analyze security findings, and generate professional reports.

---

## 💡 Key Takeaways

| 🔑 | Insight |
|---|---|
| 🔍 | **Regular security assessments** are critical for maintaining AWS security posture |
| ⚙️ | **Automation** reduces manual effort and ensures consistent security checks |
| 📏 | **Compliance frameworks** (CIS, FSS) provide structured security guidelines |
| 🎯 | **Remediation** should be prioritized based on severity and business impact |
| 📊 | **Visualization** helps communicate findings to both technical and executive audiences |

---

## 🚀 Next Steps

- 🔗 Integrate Prowler into **CI/CD pipelines** for continuous security scanning
- 🎯 Customize checks for **organization-specific requirements**
- 🚨 Implement **automated alerting** for critical findings (SNS, Slack, PagerDuty)
- 📅 Schedule **regular security assessments** and track improvements over time
- 🤖 Explore **automated remediation** using Lambda functions triggered by findings

---

> 📚 *Continue practicing by scanning different AWS environments, customizing analysis scripts, and integrating security assessments into your CI/CD pipelines.*

---

<div align="center">

**Built for Al Nafi Cybersecurity Training**

![Security](https://img.shields.io/badge/Category-Cloud_Security-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Level](https://img.shields.io/badge/Level-Intermediate-orange?style=for-the-badge)
![Tasks](https://img.shields.io/badge/Tasks-3_Completed-green?style=for-the-badge)

</div>
