# 🛡️ AI-Assisted Threat Modeling

> **A hands-on cybersecurity lab combining local LLMs, threat intelligence feeds, SIEM integration, and automated threat hunting into one unified workflow.**

---

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security Onion](https://img.shields.io/badge/Security_Onion-SIEM-005F87?style=for-the-badge&logo=linux&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-7.x-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)
![Suricata](https://img.shields.io/badge/Suricata-IDS/IPS-EF3B2D?style=for-the-badge&logo=suricata&logoColor=white)
![Ollama](https://img.shields.io/badge/Ollama-Local_LLM-000000?style=for-the-badge&logo=ollama&logoColor=white)
![Kibana](https://img.shields.io/badge/Kibana-Dashboard-E8478B?style=for-the-badge&logo=kibana&logoColor=white)
![Llama2](https://img.shields.io/badge/Llama2-7B-7C3AED?style=for-the-badge&logo=meta&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Framework-FF0000?style=for-the-badge&logoColor=white)

---

## 🎯 Objectives

By the end of this lab, you will be able to:

- 🤖 Implement **AI-assisted threat modeling** using local language models
- 🌐 Collect and process **threat intelligence** from open-source feeds
- 📋 Generate **custom detection rules** based on threat analysis
- 🔗 Integrate **threat models with Security Onion SIEM**
- ⚙️ Automate **threat hunting workflows** using Python

---

## ✅ Prerequisites

| Skill | Level |
|---|---|
| 🔒 Cybersecurity threats & attack vectors | Basic |
| 🐧 Linux command line & Python | Familiar |
| 📊 SIEM concepts & log analysis | Working knowledge |
| 🌐 Network security fundamentals | Understanding |

---

## 🖥️ Lab Environment

> Al Nafi provides **pre-configured Linux-based cloud machines** with all required tools pre-installed. Click **Start Lab** to access your environment.

| Component | Role |
|---|---|
| 🛡️ Security Onion | SIEM platform |
| 🤖 Ollama | Local AI model service |
| 🐍 Python 3.8+ | Scripting & automation |
| ⚔️ Suricata | IDS/IPS engine |
| 📦 Elasticsearch | Data storage & search |
| 📊 Kibana | Visualization & dashboards |

---

---

# 🔧 Task 1 — Setting Up AI-Assisted Threat Modeling

---

## 🔍 Step 1.1 — Verify Environment

> Confirm all required services are running before proceeding.

```bash
# ✅ Verify Python and pip
python3 --version
pip3 --version

# ✅ Check Security Onion services
sudo so-status

# ✅ Verify Ollama service
systemctl status ollama
```

---

## 📁 Step 1.2 — Create Project Structure

> Set up the working directory and folder hierarchy.

```bash
# 📂 Create project directories
mkdir -p ~/threat-modeling-lab/{scripts,data,reports,configs}
cd ~/threat-modeling-lab

# 🔐 Set permissions
chmod -R 755 ~/threat-modeling-lab
```

**Expected structure:**
```
threat-modeling-lab/
├── 📂 scripts/      ← Python automation scripts
├── 📂 data/         ← Threat intelligence feeds
├── 📂 reports/      ← Hunt reports & dashboards
└── 📂 configs/      ← Configuration files
```

---

## 🤖 Step 1.3 — Pull AI Model

> Download the local Llama2 model for offline threat analysis.

```bash
# ⬇️ Pull Llama2 model for threat analysis
ollama pull llama2:7b

# 📋 Verify model is available
ollama list
```

> 💡 **Note:** The 7B model offers a good balance between speed and analytical capability for threat modeling tasks.

---

---

# 🏗️ Task 2 — Building the AI Threat Modeling Agent

---

## 🤖 Step 2.1 — Create AI Agent Template

![Python](https://img.shields.io/badge/File-ai__threat__agent.py-3776AB?style=flat-square&logo=python&logoColor=white)

> Create the main threat modeling agent that wraps the Ollama API.

**📄 File:** `~/threat-modeling-lab/scripts/ai_threat_agent.py`

```python
#!/usr/bin/env python3
"""
AI-Assisted Threat Modeling Agent
File: ~/threat-modeling-lab/scripts/ai_threat_agent.py
"""

import json
import requests
from datetime import datetime

class ThreatModelingAgent:
    def __init__(self, model_name="llama2:7b"):
        self.ollama_url = "http://localhost:11434/api/generate"
        self.model_name = model_name
        
    def query_ai_model(self, prompt, context=""):
        """
        Query the local AI model for threat analysis.
        
        Args:
            prompt: The question or analysis request
            context: Additional context for the AI
            
        Returns:
            AI-generated response text
        """
        # TODO: Implement payload construction with model, prompt, and context
        # TODO: Send POST request to Ollama API
        # TODO: Parse and return the response
        # TODO: Handle errors appropriately
        pass
    
    def analyze_asset(self, asset_info):
        """
        Analyze a specific asset for potential threats.
        
        Args:
            asset_info: Dictionary containing asset details
                - type: Asset type (e.g., 'Web Server')
                - name: Asset name
                - services: Running services
                - criticality: Business criticality
                
        Returns:
            Threat analysis report
        """
        context = """You are a cybersecurity expert. Analyze the asset 
        and identify attack vectors, vulnerabilities, and mitigations."""
        
        # TODO: Construct detailed prompt with asset information
        # TODO: Call query_ai_model with prompt and context
        # TODO: Return formatted analysis
        pass
    
    def generate_threat_scenarios(self, org_profile):
        """
        Generate realistic threat scenarios for an organization.
        
        Args:
            org_profile: Dictionary with organization details
                - industry: Industry sector
                - size: Organization size
                - assets: Key assets
                
        Returns:
            List of threat scenarios
        """
        # TODO: Create prompt requesting 3-5 threat scenarios
        # TODO: Include threat actor, methodology, and impact
        # TODO: Query AI model and parse response
        pass
    
    def map_to_mitre_attack(self, threat_description):
        """
        Map threats to MITRE ATT&CK framework.
        
        Args:
            threat_description: Description of the threat
            
        Returns:
            MITRE ATT&CK techniques and tactics
        """
        # TODO: Create prompt for MITRE mapping
        # TODO: Request technique IDs and descriptions
        # TODO: Return structured mapping
        pass

if __name__ == "__main__":
    # 🚀 Test the agent
    agent = ThreatModelingAgent()
    
    test_asset = {
        'type': 'Web Server',
        'name': 'Production API Server',
        'services': 'HTTPS, SSH',
        'criticality': 'High'
    }
    
    # TODO: Call analyze_asset and print results
    # TODO: Test other methods
```

> 💡 **Key Methods to Implement:**
> - `query_ai_model()` — Core API call to Ollama
> - `analyze_asset()` — Per-asset threat analysis
> - `generate_threat_scenarios()` — Org-level scenario generation
> - `map_to_mitre_attack()` — ATT&CK framework mapping

---

## 🌐 Step 2.2 — Create Threat Intelligence Collector

![Python](https://img.shields.io/badge/File-threat__intel__collector.py-3776AB?style=flat-square&logo=python&logoColor=white)
![ThreatFox](https://img.shields.io/badge/Source-ThreatFox-FF6B35?style=flat-square&logoColor=white)
![URLhaus](https://img.shields.io/badge/Source-URLhaus-4CAF50?style=flat-square&logoColor=white)

> Build a script to collect live IOCs from public threat intelligence feeds.

**📄 File:** `~/threat-modeling-lab/scripts/threat_intel_collector.py`

```python
#!/usr/bin/env python3
"""
Threat Intelligence Collector
File: ~/threat-modeling-lab/scripts/threat_intel_collector.py
"""

import requests
import json
import pandas as pd
from datetime import datetime

class ThreatIntelCollector:
    def __init__(self):
        self.sources = {
            'threatfox': 'https://threatfox-api.abuse.ch/api/v1/',
            'urlhaus': 'https://urlhaus-api.abuse.ch/v1/'
        }
        
    def collect_threatfox_iocs(self, days=7):
        """
        Collect IOCs from ThreatFox API.
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of IOC dictionaries
        """
        url = self.sources['threatfox']
        payload = {"query": "get_iocs", "days": days}
        
        # TODO: Send POST request to ThreatFox API
        # TODO: Parse JSON response
        # TODO: Extract and return IOC data
        # TODO: Handle API errors
        pass
    
    def collect_urlhaus_urls(self, limit=50):
        """
        Collect malicious URLs from URLhaus.
        
        Args:
            limit: Maximum number of URLs to retrieve
            
        Returns:
            List of malicious URL data
        """
        # TODO: Construct API endpoint with limit
        # TODO: Send GET request
        # TODO: Parse and return URL data
        pass
    
    def normalize_threat_data(self, raw_data, source):
        """
        Normalize threat data to common format.
        
        Args:
            raw_data: Raw data from threat feed
            source: Name of the data source
            
        Returns:
            List of normalized threat dictionaries
        """
        normalized = []
        
        for item in raw_data:
            # TODO: Create normalized dictionary with fields:
            #   - source, timestamp, threat_type, ioc_value
            #   - confidence, tags, first_seen, last_seen
            # TODO: Append to normalized list
            pass
        
        return normalized
    
    def save_threat_data(self, data, filename):
        """
        Save threat data to JSON and CSV files.
        
        Args:
            data: List of threat dictionaries
            filename: Base filename (without extension)
        """
        # TODO: Save data as JSON to ~/threat-modeling-lab/data/
        # TODO: Convert to DataFrame and save as CSV
        # TODO: Print confirmation message
        pass
    
    def generate_summary_report(self, data):
        """
        Generate summary statistics from threat data.
        
        Args:
            data: List of threat dictionaries
            
        Returns:
            Formatted report string
        """
        # TODO: Create DataFrame from data
        # TODO: Calculate statistics (total IOCs, unique types, etc.)
        # TODO: Generate formatted report text
        # TODO: Return report string
        pass

if __name__ == "__main__":
    collector = ThreatIntelCollector()
    
    # TODO: Collect data from both sources
    # TODO: Normalize and combine data
    # TODO: Save to files
    # TODO: Generate and print report
```

> 🔗 **Intel Sources Used:**
> - **ThreatFox** (`threatfox-api.abuse.ch`) — Malware IOCs & hashes
> - **URLhaus** (`urlhaus-api.abuse.ch`) — Malicious URL database

---

## ▶️ Step 2.3 — Test the AI Agent

> Run your implementations to verify end-to-end functionality.

```bash
cd ~/threat-modeling-lab

# 🤖 Test AI threat agent
python3 scripts/ai_threat_agent.py

# 🌐 Collect threat intelligence
python3 scripts/threat_intel_collector.py

# 📂 Verify output files
ls -lh data/
```

---

---

# 🔗 Task 3 — Integrating with Security Onion

---

## ⚔️ Step 3.1 — Create Suricata Rule Generator

![Python](https://img.shields.io/badge/File-rule__generator.py-3776AB?style=flat-square&logo=python&logoColor=white)
![Suricata](https://img.shields.io/badge/Output-Suricata_Rules-EF3B2D?style=flat-square&logoColor=white)

> Automatically generate Suricata IDS rules from collected IOCs.

**📄 File:** `~/threat-modeling-lab/scripts/rule_generator.py`

```python
#!/usr/bin/env python3
"""
Suricata Rule Generator
File: ~/threat-modeling-lab/scripts/rule_generator.py
"""

import json
import re
from datetime import datetime

class SuricataRuleGenerator:
    def __init__(self, start_sid=2000000):
        self.current_sid = start_sid
        
    def generate_ip_rule(self, ip_address, description):
        """
        Generate Suricata rule for malicious IP.
        
        Args:
            ip_address: IP address to block
            description: Rule description
            
        Returns:
            Suricata rule string
        """
        # TODO: Create alert rule for IP traffic
        # Format: alert ip {ip} any -> $HOME_NET any (msg:"..."; sid:{sid}; rev:1;)
        # TODO: Increment self.current_sid
        # TODO: Return rule string
        pass
    
    def generate_domain_rule(self, domain, description):
        """
        Generate Suricata rule for malicious domain.
        
        Args:
            domain: Domain name to detect
            description: Rule description
            
        Returns:
            Suricata rule string
        """
        # TODO: Create DNS query detection rule
        # Format: alert dns any any -> any any (msg:"..."; dns.query; content:"{domain}"; ...)
        # TODO: Increment SID and return rule
        pass
    
    def generate_url_rule(self, url_pattern, description):
        """
        Generate Suricata rule for malicious URL pattern.
        
        Args:
            url_pattern: URL or pattern to detect
            description: Rule description
            
        Returns:
            Suricata rule string
        """
        # TODO: Create HTTP URI detection rule
        # TODO: Use http.uri and content matching
        # TODO: Return formatted rule
        pass
    
    def generate_rules_from_iocs(self, ioc_data):
        """
        Generate multiple rules from IOC data.
        
        Args:
            ioc_data: List of IOC dictionaries
            
        Returns:
            List of Suricata rule strings
        """
        rules = []
        
        # TODO: Iterate through IOC data
        # TODO: Determine IOC type (ip, domain, url)
        # TODO: Call appropriate rule generation method
        # TODO: Append rules to list
        
        return rules
    
    def save_rules(self, rules, filename):
        """
        Save rules to file with header.
        
        Args:
            rules: List of rule strings
            filename: Output filename
        """
        filepath = f"/tmp/{filename}"
        
        # TODO: Write header with timestamp
        # TODO: Write each rule on separate line
        # TODO: Print confirmation with rule count
        pass

if __name__ == "__main__":
    generator = SuricataRuleGenerator()
    
    # TODO: Load threat intelligence data
    # TODO: Generate rules from IOCs
    # TODO: Save rules to file
    # TODO: Print sample rules
```

> 📌 **Rule Types Generated:**
> - 🔴 **IP Rules** — Block traffic from known malicious IPs
> - 🌐 **Domain Rules** — Detect DNS queries to C2 domains
> - 🔗 **URL Rules** — Match HTTP requests to malicious endpoints

---

## 🚀 Step 3.2 — Deploy Custom Rules to Security Onion

![Bash](https://img.shields.io/badge/File-deploy__rules.sh-4EAA25?style=flat-square&logo=gnubash&logoColor=white)
![Security Onion](https://img.shields.io/badge/Target-Security_Onion-005F87?style=flat-square&logo=linux&logoColor=white)

> Deploy the generated Suricata rules into the live Security Onion stack.

**📄 File:** `~/threat-modeling-lab/scripts/deploy_rules.sh`

```bash
#!/bin/bash
# File: ~/threat-modeling-lab/scripts/deploy_rules.sh

# ⚙️ Generate rules from threat intelligence
python3 ~/threat-modeling-lab/scripts/rule_generator.py

# 📋 Copy rules to Security Onion custom rules directory
sudo cp /tmp/ai_threat_rules.rules \
    /opt/so/saltstack/local/salt/suricata/files/rules/custom/

# 🔄 Update Suricata rules
sudo rule-update

# ♻️ Restart Suricata to load new rules
sudo so-suricata-restart

echo "✅ Custom rules deployed successfully"
```

```bash
# 🔐 Make the script executable
chmod +x ~/threat-modeling-lab/scripts/deploy_rules.sh
```

---

## 📦 Step 3.3 — Create Elasticsearch Integration

![Python](https://img.shields.io/badge/File-es__integration.py-3776AB?style=flat-square&logo=python&logoColor=white)
![Elasticsearch](https://img.shields.io/badge/Target-Elasticsearch-005571?style=flat-square&logo=elasticsearch&logoColor=white)

> Ingest normalized threat data into Elasticsearch for querying and visualization.

**📄 File:** `~/threat-modeling-lab/scripts/es_integration.py`

```python
#!/usr/bin/env python3
"""
Elasticsearch Threat Data Ingestion
File: ~/threat-modeling-lab/scripts/es_integration.py
"""

import json
import requests
from datetime import datetime

class ElasticsearchIntegrator:
    def __init__(self):
        self.es_url = "http://localhost:9200"
        self.index_prefix = "threat-model"
        
    def create_index_template(self):
        """
        Create Elasticsearch index template for threat data.
        
        Returns:
            True if successful, False otherwise
        """
        template = {
            "index_patterns": [f"{self.index_prefix}-*"],
            "template": {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "threat_type": {"type": "keyword"},
                        "ioc_value": {"type": "keyword"},
                        "confidence": {"type": "integer"},
                        "source": {"type": "keyword"}
                    }
                }
            }
        }
        
        # TODO: Send PUT request to create template
        # TODO: Check response status
        # TODO: Return success/failure
        pass
    
    def ingest_threat_document(self, threat_data):
        """
        Ingest single threat document into Elasticsearch.
        
        Args:
            threat_data: Dictionary with threat information
            
        Returns:
            Document ID if successful, None otherwise
        """
        index_name = f"{self.index_prefix}-{datetime.now().strftime('%Y-%m-%d')}"
        
        # TODO: Add @timestamp to document
        # TODO: POST document to Elasticsearch
        # TODO: Return document ID from response
        pass
    
    def bulk_ingest(self, threat_list):
        """
        Bulk ingest multiple threat documents.
        
        Args:
            threat_list: List of threat dictionaries
            
        Returns:
            Number of successfully ingested documents
        """
        # TODO: Iterate through threat_list
        # TODO: Call ingest_threat_document for each
        # TODO: Count successes
        # TODO: Return count
        pass

if __name__ == "__main__":
    integrator = ElasticsearchIntegrator()
    
    # TODO: Create index template
    # TODO: Load threat intelligence data
    # TODO: Bulk ingest into Elasticsearch
    # TODO: Print results
```

> 🗂️ **Index Schema Fields:**
> - `@timestamp` — Event time
> - `threat_type` — IOC category (ip, domain, url)
> - `ioc_value` — The actual indicator
> - `confidence` — Confidence score (0–100)
> - `source` — Feed origin (ThreatFox, URLhaus)

---

---

# 🕵️ Task 4 — Automated Threat Hunting

---

## 🔍 Step 4.1 — Create Threat Hunting Automation

![Python](https://img.shields.io/badge/File-threat__hunter.py-3776AB?style=flat-square&logo=python&logoColor=white)
![Automation](https://img.shields.io/badge/Mode-Automated_Hunt-FF6B35?style=flat-square&logoColor=white)

> Build an automated threat hunter that correlates network data with IOC feeds.

**📄 File:** `~/threat-modeling-lab/scripts/threat_hunter.py`

```python
#!/usr/bin/env python3
"""
Automated Threat Hunter
File: ~/threat-modeling-lab/scripts/threat_hunter.py
"""

import json
import subprocess
from datetime import datetime, timedelta

class ThreatHunter:
    def __init__(self):
        self.hunt_results = []
        
    def hunt_suspicious_connections(self, timeframe_hours=24):
        """
        Hunt for suspicious network connections.
        
        Args:
            timeframe_hours: Hours to look back
            
        Returns:
            List of suspicious connection findings
        """
        # TODO: Query Suricata logs for alerts
        # TODO: Filter by timeframe
        # TODO: Identify high-severity alerts
        # TODO: Return findings list
        pass
    
    def correlate_with_threat_intel(self, connections, threat_data):
        """
        Correlate connections with threat intelligence.
        
        Args:
            connections: List of connection data
            threat_data: Threat intelligence IOCs
            
        Returns:
            List of correlated matches
        """
        matches = []
        
        # TODO: Extract IPs/domains from connections
        # TODO: Compare against threat_data IOCs
        # TODO: Record matches with confidence scores
        # TODO: Return matches list
        
        return matches
    
    def generate_hunt_report(self, findings):
        """
        Generate threat hunting report.
        
        Args:
            findings: List of hunt findings
            
        Returns:
            Formatted report string
        """
        # TODO: Create report header with timestamp
        # TODO: Summarize findings by severity
        # TODO: List top threats detected
        # TODO: Include recommendations
        # TODO: Return formatted report
        pass
    
    def save_hunt_results(self, findings, filename):
        """
        Save hunt results to file.
        
        Args:
            findings: Hunt findings data
            filename: Output filename
        """
        # TODO: Save as JSON to reports directory
        # TODO: Generate and save text report
        pass

if __name__ == "__main__":
    hunter = ThreatHunter()
    
    # TODO: Run suspicious connection hunt
    # TODO: Load threat intelligence
    # TODO: Correlate findings
    # TODO: Generate and save report
```

---

## ⏰ Step 4.2 — Schedule Automated Hunting

![Cron](https://img.shields.io/badge/Scheduler-Cron_Job-4EAA25?style=flat-square&logo=linux&logoColor=white)

> Schedule the threat hunter to run automatically every 6 hours.

```bash
# 📅 Edit crontab
crontab -e

# ⏰ Add entry to run threat hunter every 6 hours
0 */6 * * * /usr/bin/python3 ~/threat-modeling-lab/scripts/threat_hunter.py \
    >> ~/threat-modeling-lab/reports/hunt.log 2>&1
```

> 🕐 **Schedule:** Every 6 hours (`0 */6 * * *`)
> 📝 **Logs saved to:** `~/threat-modeling-lab/reports/hunt.log`

---

## 📊 Step 4.3 — Create Dashboard Visualization

![Python](https://img.shields.io/badge/File-dashboard__generator.py-3776AB?style=flat-square&logo=python&logoColor=white)
![HTML](https://img.shields.io/badge/Output-HTML_Dashboard-E34F26?style=flat-square&logo=html5&logoColor=white)

> Generate an HTML dashboard to visualize threat data and hunt results.

**📄 File:** `~/threat-modeling-lab/scripts/dashboard_generator.py`

```python
#!/usr/bin/env python3
"""
Threat Dashboard Generator
File: ~/threat-modeling-lab/scripts/dashboard_generator.py
"""

import json
from datetime import datetime

def generate_dashboard_html(threat_data, hunt_results):
    """
    Generate HTML dashboard from threat data.
    
    Args:
        threat_data: Threat intelligence data
        hunt_results: Threat hunting results
        
    Returns:
        HTML string
    """
    # TODO: Create HTML template with CSS
    # TODO: Add threat statistics section
    # TODO: Add recent alerts table
    # TODO: Add hunt findings summary
    # TODO: Return complete HTML
    pass

def save_dashboard(html_content, filename="dashboard.html"):
    """
    Save dashboard HTML to file.
    
    Args:
        html_content: HTML string
        filename: Output filename
    """
    # TODO: Write HTML to reports directory
    # TODO: Print file location
    pass

if __name__ == "__main__":
    # TODO: Load threat and hunt data
    # TODO: Generate dashboard HTML
    # TODO: Save to file
    # TODO: Print access instructions
```

---

---

# ✅ Expected Outcomes

After completing this lab, you should have:

| ✅ | Deliverable |
|---|---|
| 🤖 | Functional AI threat modeling agent using local LLM |
| 🌐 | Automated threat intelligence collection from public feeds |
| ⚔️ | Custom Suricata rules deployed to Security Onion |
| 📦 | Threat data ingested into Elasticsearch |
| 🕵️ | Automated threat hunting workflow active |
| 📊 | HTML dashboard for threat visualization |

---

## 🧪 Verification Commands

```bash
# 📋 Check generated rules
cat /tmp/ai_threat_rules.rules | head -20

# 📦 Verify Elasticsearch data
curl -X GET "localhost:9200/threat-model-*/_count"

# 📂 Review threat hunting reports
ls -lh ~/threat-modeling-lab/reports/

# 🌐 View dashboard
firefox ~/threat-modeling-lab/reports/dashboard.html
```

---

---

# 🔧 Troubleshooting Guide

---

### ❌ Issue: Ollama API Connection Fails

![Ollama](https://img.shields.io/badge/Service-Ollama-000000?style=flat-square&logo=ollama&logoColor=white)

```bash
# 🔍 Verify service is running
systemctl status ollama

# 🔌 Check port 11434 is accessible
netstat -tlnp | grep 11434

# ♻️ Restart service
sudo systemctl restart ollama
```

---

### ❌ Issue: Security Onion Rules Not Loading

![Suricata](https://img.shields.io/badge/Service-Suricata-EF3B2D?style=flat-square&logoColor=white)

```bash
# ✅ Check rule syntax
suricata -T -c /etc/suricata/suricata.yaml

# 🔐 Verify file permissions
ls -l /opt/so/saltstack/local/salt/suricata/files/rules/custom/

# 📋 Review Suricata logs
sudo tail -f /var/log/suricata/suricata.log
```

---

### ❌ Issue: Elasticsearch Ingestion Fails

![Elasticsearch](https://img.shields.io/badge/Service-Elasticsearch-005571?style=flat-square&logo=elasticsearch&logoColor=white)

```bash
# 🔍 Verify Elasticsearch is running
sudo so-elasticsearch-status

# 📋 Check index template
curl -X GET "localhost:9200/_index_template/threat-model-template"

# 📜 Review error logs
sudo tail -f /var/log/elasticsearch/elasticsearch.log
```

---

---

# 🎓 Conclusion

This lab demonstrated **AI-assisted threat modeling** by combining local language models with threat intelligence feeds and SIEM integration. You built automated workflows for threat detection, created custom detection rules, and implemented threat hunting capabilities — skills essential for modern **Security Operations Centers (SOCs)**.

---

## 💡 Key Takeaways

| 🔑 | Insight |
|---|---|
| 🤖 | AI models **accelerate** threat analysis and scenario generation |
| 🌐 | Open-source threat intelligence provides **real-world IOCs** |
| ⚙️ | Automation **reduces response time** and analyst workload |
| 🔗 | SIEM integration enables **real-time detection** |
| 🕵️ | Continuous threat hunting **improves security posture** |

---

## 🚀 Next Steps

- 📡 Expand threat intelligence **sources and feeds**
- 🎯 Refine and tune detection **rule accuracy**
- 🔗 Correlate **multiple data sources** for deeper visibility
- 🤖 Experiment with **larger AI models** (Llama2 13B, Mistral, etc.)
- 📊 Build **Kibana dashboards** for real-time SOC monitoring

---

> 📚 *Continue practicing by expanding your threat intelligence sources, refining detection rules, and correlating multiple data sources for comprehensive threat visibility.*

---

<div align="center">

**Built for Al Nafi Cybersecurity Training**

![Security](https://img.shields.io/badge/Category-Cybersecurity-red?style=for-the-badge&logo=shield&logoColor=white)
![Level](https://img.shields.io/badge/Level-Intermediate-orange?style=for-the-badge)
![Tasks](https://img.shields.io/badge/Tasks-4_Completed-green?style=for-the-badge)

</div>
