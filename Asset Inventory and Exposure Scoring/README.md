# Asset Inventory and Exposure Scoring

## Objectives
By the end of this lab, students will be able to:

- Install and configure OpenVAS for vulnerability scanning  
- Perform network asset vulnerability assessments  
- Develop Python scripts to calculate risk exposure scores using CVSS ratings  
- Visualize vulnerability data using the ELK Stack  
- Interpret vulnerability data to prioritize remediation efforts  

---

## Prerequisites

- Basic Linux command line proficiency  
- Fundamental networking knowledge (IP addresses, ports)  
- Python programming basics  
- Understanding of cybersecurity vulnerabilities and risk concepts  
- Familiarity with JSON data structures  

---

## Lab Environment

Al Nafi provides a pre-configured Ubuntu 20.04 LTS cloud machine. Click **Start Lab** to access your environment. All tasks are performed on a single Linux machine with internet access.

Installed tools:

- OpenVAS (GVM) vulnerability scanner  
- PostgreSQL & Redis  
- Python 3.x with data libraries  
- ELK Stack (Elasticsearch, Logstash, Kibana)  
- Firefox browser  

---

# Task 1: Install and Configure OpenVAS

## Step 1: Install Dependencies

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y gvm postgresql redis-server
Step 2: Configure Database
sudo systemctl start postgresql redis-server
sudo systemctl enable postgresql redis-server

sudo -u postgres createuser gvm
sudo -u postgres createdb -O gvm gvmd
sudo -u postgres psql gvmd -c "create extension \"uuid-ossp\";"
sudo -u postgres psql gvmd -c "create extension \"pgcrypto\";"
Step 3: Initialize OpenVAS
sudo gvm-setup

⚠️ This may take 15–30 minutes.

Step 4: Start Services
sudo systemctl start gvmd gsad ospd-openvas
sudo systemctl enable gvmd gsad ospd-openvas

Create admin user:

sudo gvmd --create-user=admin --password=SecurePass123

Access UI:

https://localhost:9392
Task 2: Vulnerability Scanning
Step 1: Configure Target

In OpenVAS:

Name: Lab Asset Scan
Hosts: 127.0.0.1, 192.168.1.0/24
Ports: All TCP
Step 2: Run Scan
Go to Scans → Tasks
Create task:
Name: Asset Inventory Scan
Config: Full and Fast
Target: Lab Asset Scan
Start scan
Step 3: Export Results

Export as XML:

vulnerability_scan.xml

Move file:

mkdir -p ~/asset_lab
mv vulnerability_scan.xml ~/asset_lab/
Task 3: Python Risk Scoring
Step 1: Environment Setup
python3 -m venv venv
source venv/bin/activate
pip install lxml pandas numpy matplotlib seaborn
Step 2: XML Parser
parse_openvas.py
import xml.etree.ElementTree as ET
import pandas as pd
import json

class OpenVASParser:
    def __init__(self, xml_file):
        self.tree = ET.parse(xml_file)
        self.root = self.tree.getroot()

    def extract_vulnerabilities(self):
        vulnerabilities = []

        # TODO: Parse XML results
        return vulnerabilities

    def save_to_json(self, vulnerabilities, output_file):
        with open(output_file, "w") as f:
            json.dump(vulnerabilities, f, indent=4)

    def create_dataframe(self, vulnerabilities):
        return pd.DataFrame(vulnerabilities)


if __name__ == "__main__":
    parser = OpenVASParser("vulnerability_scan.xml")
    vulns = parser.extract_vulnerabilities()
    parser.save_to_json(vulns, "vulnerabilities.json")
    df = parser.create_dataframe(vulns)
    df.to_csv("vulnerabilities.csv", index=False)
Step 3: Risk Scoring Engine
risk_scorer.py
import pandas as pd
from collections import defaultdict

class RiskScorer:
    def __init__(self, file):
        self.df = pd.read_csv(file)
        self.asset_scores = defaultdict(dict)

    def calculate_cvss_multiplier(self, score):
        if score >= 9:
            return 1.0
        elif score >= 7:
            return 0.8
        elif score >= 4:
            return 0.6
        elif score > 0:
            return 0.3
        return 0.1

    def calculate_port_criticality(self, port):
        critical_ports = [22, 80, 443, 3389]
        return 1.0 if port in critical_ports else 0.6

    def calculate_asset_exposure_score(self):
        for host in self.df['host'].unique():
            subset = self.df[self.df['host'] == host]

            score = 0
            for _, row in subset.iterrows():
                cvss = float(row.get("cvss_base", 0))
                port = int(str(row.get("port", "0")).split("/")[0])

                score += cvss * self.calculate_cvss_multiplier(cvss)

            self.asset_scores[host] = {
                "exposure_score": round(score, 2),
                "vulnerability_count": len(subset)
            }

    def generate_risk_report(self):
        self.calculate_asset_exposure_score()
        return pd.DataFrame.from_dict(self.asset_scores, orient="index")

    def save_report(self, df):
        df.to_csv("risk_report.csv")
        df.to_json("risk_report.json", orient="records")


if __name__ == "__main__":
    scorer = RiskScorer("vulnerabilities.csv")
    report = scorer.generate_risk_report()
    scorer.save_report(report)
Task 4: ELK Stack Setup
Elasticsearch
sudo apt install -y elasticsearch
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

Test:

curl localhost:9200
Logstash Pipeline
input {
  file {
    path => "/home/ubuntu/asset_lab/risk_report.json"
    codec => json
    start_position => "beginning"
  }
}

filter {
  mutate {
    convert => { "exposure_score" => "float" }
  }

  if [exposure_score] > 7 {
    mutate { add_field => { "risk_level" => "HIGH" } }
  } else if [exposure_score] > 4 {
    mutate { add_field => { "risk_level" => "MEDIUM" } }
  } else {
    mutate { add_field => { "risk_level" => "LOW" } }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "asset-risk"
  }
}
Kibana

Start service:

sudo apt install -y kibana
sudo systemctl start kibana

Open:

http://localhost:5601
Task 5: Visualization
Kibana Dashboards

Create:

Risk Heatmap (host vs risk level)
Vulnerability Bar Chart
Risk Distribution Pie Chart
Python Heatmap
vulnerability_heatmap.py
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

class Heatmap:
    def __init__(self, file):
        self.df = pd.read_csv(file)

    def create_heatmap(self):
        pivot = self.df.pivot_table(
            index="host",
            values="exposure_score",
            aggfunc="sum"
        )

        sns.heatmap(pivot, annot=True)
        plt.title("Asset Exposure Heatmap")
        plt.savefig("heatmap.png")
        plt.close()


if __name__ == "__main__":
    h = Heatmap("risk_report.csv")
    h.create_heatmap()
Expected Outcomes
OpenVAS vulnerability scanner installed
Vulnerability dataset extracted and parsed
Custom Python risk scoring engine
ELK Stack visualization dashboard
Heatmaps showing asset exposure
Key Takeaways
CVSS helps quantify vulnerability severity
Asset exposure depends on cumulative risk
Automation improves vulnerability prioritization
Visualization supports security decision-making
Troubleshooting
OpenVAS
Ensure PostgreSQL is running
Run gvm-setup again if feed sync fails
Python
pip install --upgrade pip
ELK
Check port 9200 (Elasticsearch)
Ensure Java is installed
Conclusion

This lab demonstrated a full asset inventory and exposure scoring pipeline using OpenVAS, Python analytics, and ELK Stack visualization.

You learned how to:

Discover and extract vulnerabilities
Build exposure scoring models
Automate risk analysis
Visualize security posture effectively
