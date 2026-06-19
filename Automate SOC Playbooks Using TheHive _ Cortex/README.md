# Automate SOC Playbooks Using TheHive + Cortex

## Objectives

By the end of this lab, students will be able to:

* Deploy and configure TheHive case management platform for incident tracking
* Set up Cortex analyzers for automated threat intelligence analysis
* Create automated incident response workflows using Python
* Integrate multiple security tools for SOAR capabilities
* Design and test security playbooks for common incident scenarios

---

## Prerequisites

Before starting this lab, students should have:

* Basic Linux command line proficiency
* Understanding of Docker and containerization
* Python programming fundamentals
* Knowledge of REST APIs and JSON
* Familiarity with incident response concepts

---

## Lab Environment

Al Nafi provides ready-to-use Linux-based cloud machines for this lab. Click **Start Lab** to access your pre-configured environment.

Your lab machine includes:

* Ubuntu 20.04 LTS with Docker pre-installed
* Python 3.8+ with pip package manager
* Git and necessary development tools
* All required network ports configured

---

## Technology Stack

### Core SOAR Platform

![TheHive](https://img.shields.io/badge/TheHive-Incident_Response-blue?style=for-the-badge)
![Cortex](https://img.shields.io/badge/Cortex-Threat_Intelligence-orange?style=for-the-badge)
![SOAR](https://img.shields.io/badge/SOAR-Automation-red?style=for-the-badge)

### Infrastructure & Containerization

![Docker](https://img.shields.io/badge/Docker-Containerization-2496ED?style=for-the-badge\&logo=docker\&logoColor=white)
![Docker Compose](https://img.shields.io/badge/Docker_Compose-Orchestration-1488C6?style=for-the-badge\&logo=docker\&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu_20.04-Linux-E95420?style=for-the-badge\&logo=ubuntu\&logoColor=white)

### Development & Automation

![Python](https://img.shields.io/badge/Python_3.8+-Automation-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![REST API](https://img.shields.io/badge/REST_API-Integration-009688?style=for-the-badge)
![JSON](https://img.shields.io/badge/JSON-Data_Exchange-black?style=for-the-badge)

### Security Operations

![Threat Intelligence](https://img.shields.io/badge/Threat_Intelligence-IOC_Enrichment-purple?style=for-the-badge)
![Incident Response](https://img.shields.io/badge/Incident_Response-Playbooks-success?style=for-the-badge)
![Automation](https://img.shields.io/badge/Security_Automation-SOAR-critical?style=for-the-badge)

---

# Task 1: Deploy TheHive and Cortex Platforms

## Step 1: Prepare the Environment

Update system and create project structure:

```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y curl wget git python3-pip docker-compose jq

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker

# Create project directories
mkdir -p ~/soar-lab/{thehive,cortex,scripts}
cd ~/soar-lab
```

---

## Step 2: Deploy TheHive

Create TheHive configuration and deploy:

```bash
cd ~/soar-lab/thehive

# Create application configuration
cat > application.conf << 'EOF'
play.http.secret.key = "SecureKeyForTheHiveLab2024"

db.janusgraph {
  storage {
    backend = berkeleyje
    directory = /opt/thp/thehive/db
  }
  index.search {
    backend = lucene
    directory = /opt/thp/thehive/index
  }
}

storage {
  provider = localfs
  localfs.location = /opt/thp/thehive/files
}
EOF
```

### Create Docker Compose file

```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  thehive:
    image: thehiveproject/thehive4:4.1.24-1
    container_name: thehive4
    restart: unless-stopped
    ports:
      - "9000:9000"
    volumes:
      - ./application.conf:/etc/thehive/application.conf:ro
      - thehive_data:/opt/thp/thehive/db
      - thehive_files:/opt/thp/thehive/files
    networks:
      - soar_network
    environment:
      - JVM_OPTS="-Xms1024m -Xmx2048m"

volumes:
  thehive_data:
  thehive_files:

networks:
  soar_network:
    driver: bridge
EOF
```

Deploy TheHive:

```bash
docker-compose up -d

# Wait for startup
sleep 30
docker-compose ps
```

---

## Step 3: Deploy Cortex

Set up Cortex with Elasticsearch:

```bash
cd ~/soar-lab/cortex
```

Create Cortex Docker Compose:

```bash
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: cortex_elasticsearch
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - cluster.name=hive
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
      - xpack.security.enabled=false
    volumes:
      - cortex_es_data:/usr/share/elasticsearch/data
    networks:
      - soar_network
    ports:
      - "9200:9200"

  cortex:
    image: thehiveproject/cortex:3.1.7-1
    container_name: cortex
    restart: unless-stopped
    ports:
      - "9001:9001"
    volumes:
      - cortex_jobs:/tmp/cortex-jobs
    networks:
      - soar_network
    depends_on:
      - elasticsearch
    environment:
      - JVM_OPTS="-Xms512m -Xmx1024m"

volumes:
  cortex_es_data:
  cortex_jobs:

networks:
  soar_network:
    external: true
EOF
```

Deploy services:

```bash
docker network create soar_network 2>/dev/null || true
docker-compose up -d

# Wait for services
sleep 45
docker-compose ps
```

---

## Step 4: Verify Deployments

```bash
# List all containers
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# Test connectivity
curl -s -o /dev/null -w "TheHive: %{http_code}\n" http://localhost:9000
curl -s -o /dev/null -w "Cortex: %{http_code}\n" http://localhost:9001
curl -s -o /dev/null -w "Elasticsearch: %{http_code}\n" http://localhost:9200
```

Access TheHive at:

```text
http://localhost:9000
Username: admin@thehive.local
Password: secret
```

---

# Task 2: Configure Platforms and Create Initial Setup

## Step 1: Initialize TheHive

Create initialization script:

**File:** `scripts/init_thehive.py`

```python
#!/usr/bin/env python3
import requests
import json
import time

class TheHiveSetup:
    def __init__(self, url="http://localhost:9000"):
        self.url = url
        self.token = None

    def wait_for_service(self, max_attempts=30):
        """
        Wait for TheHive to be ready.

        TODO: Implement retry logic with exponential backoff
        TODO: Check /api/status endpoint
        TODO: Return True when ready, False on timeout
        """
        pass

    def authenticate(self, username, password):
        """
        Authenticate and get API token.

        TODO: Send POST request to /api/login
        TODO: Extract Authorization header from response
        TODO: Store token in self.token
        """
        pass

    def create_case(self, title, description, severity=2):
        """
        Create a new case in TheHive.

        TODO: Prepare case data dictionary
        TODO: Send POST request to /api/case
        TODO: Return parsed JSON response
        """
        pass

if __name__ == "__main__":
    setup = TheHiveSetup()
    # TODO: Implement initialization workflow
```

---

## Step 2: Initialize Cortex

Create initialization script:

**File:** `scripts/init_cortex.py`

```python
#!/usr/bin/env python3
import requests
import json

class CortexSetup:
    def __init__(self, url="http://localhost:9001"):
        self.url = url
        self.api_key = None

    def create_organization(self, org_name):
        """
        TODO: Prepare organization data
        TODO: Send POST request
        TODO: Handle response
        """
        pass

    def create_user(self, username, password, org_name):
        """
        TODO: Create Cortex user
        TODO: Assign analyzer permissions
        """
        pass

    def get_api_key(self, username, password):
        """
        TODO: Authenticate
        TODO: Generate API key
        TODO: Save key to file
        """
        pass

if __name__ == "__main__":
    setup = CortexSetup()
    # TODO: Implement initialization workflow
```

---

## Step 3: Test Platform Integration

```bash
# Check TheHive API
curl -X GET http://localhost:9000/api/status | jq

# Check Cortex API
curl -X GET http://localhost:9001/api/status | jq

# Check Elasticsearch
curl -X GET http://localhost:9200/_cluster/health | jq
```

---

# Task 3: Build Automated Incident Response Workflows

## Step 1: Create SOAR Automation Framework

Create:

**File:** `scripts/soar_automation.py`

Key capabilities:

* Load TheHive and Cortex credentials
* Create incident cases
* Add observables and IOCs
* Run Cortex analyzers
* Calculate risk scores
* Execute automated response actions

Students must implement all TODO sections.

---

## Step 2: Create Incident Playbooks

Create:

**File:** `scripts/playbooks.py`

Playbooks to implement:

### Malware Detection Playbook

Workflow:

1. Create case
2. Add file hash observable
3. Add source IP
4. Add hostname
5. Enrich indicators
6. Calculate risk score
7. Execute containment actions

### Phishing Email Playbook

Workflow:

1. Create phishing case
2. Add sender, URLs and attachments
3. Check reputation
4. Determine verdict
5. Execute response actions

### Brute Force Playbook

Workflow:

1. Create authentication attack case
2. Check attacker reputation
3. Calculate severity
4. Block malicious IP

### Data Exfiltration Playbook

Workflow:

1. Create high-severity incident
2. Analyze destination IP
3. Assess data transfer risk
4. Isolate affected host

---

## Step 3: Implement Threat Intelligence Integration

Create:

**File:** `scripts/threat_intel.py`

Functions to implement:

```python
check_ip_reputation()
check_hash_reputation()
check_domain_reputation()
check_url_reputation()
enrich_ioc()
```

Threat intelligence sources (simulated):

* VirusTotal
* AbuseIPDB
* MalwareBazaar
* WHOIS
* SSL validation

---

## Step 4: Test Complete Workflow

```bash
chmod +x ~/soar-lab/scripts/test_workflow.py

python3 ~/soar-lab/scripts/test_workflow.py
```

The test workflow should validate:

* Malware detection workflow
* Phishing detection workflow
* IOC enrichment
* Automated response actions
* Case creation and reporting

---

# Task 4: Implement Response Actions and Reporting

## Step 1: Create Response Action Module

Create:

**File:** `scripts/response_actions.py`

Implement:

```python
block_ip_address()
quarantine_file()
isolate_host()
reset_user_password()
generate_action_report()
```

Actions should:

* Log all activities
* Simulate security controls
* Return execution status
* Generate audit trails

---

## Step 2: Create Reporting Module

Create:

**File:** `scripts/reporting.py`

Functions:

```python
generate_incident_summary()
generate_metrics_report()
export_to_json()
```

Metrics should include:

* Number of incidents
* Incident severity distribution
* Mean Time to Detect (MTTD)
* Mean Time to Respond (MTTR)
* Automated action statistics

---

# Expected Outcomes

After completing this lab, you should have:

* Functional TheHive and Cortex platforms running in Docker
* Python automation framework for incident response
* Multiple playbooks for common security incidents
* Threat intelligence integration capabilities
* Automated response action framework
* Reporting and metrics generation

### Test your implementation by:

* Creating test cases through the API
* Adding observables and running analyzers
* Executing playbooks with sample data
* Verifying automated actions are logged
* Generating incident reports

---

# Troubleshooting Tips

## Services won't start

```bash
docker-compose logs -f

netstat -tulpn | grep -E '9000|9001|9200'

free -h
```

---

## Authentication failures

Verify:

```bash
ls -l /tmp/*token*

cat /tmp/thehive_token.txt
cat /tmp/cortex_api_key.txt
```

Re-run initialization scripts if necessary.

---

## API requests fail

```bash
docker ps

curl http://localhost:9000/api/status

sudo ufw status
```

---

# Conclusion

This lab demonstrated building a complete SOAR solution using open-source tools. You learned to:

* Deploy and configure TheHive and Cortex platforms
* Create automated incident response workflows
* Integrate threat intelligence for IOC enrichment
* Implement automated response actions
* Generate incident reports and metrics

## Key Takeaways

* SOAR platforms reduce response time through automation
* Playbooks standardize incident handling procedures
* Integration between tools enables end-to-end automation
* Proper logging and reporting are essential for continuous improvement
* Threat intelligence enrichment enhances investigation quality

Continue practicing by creating additional playbooks tailored to your organization's security requirements and integrating with existing SIEM, EDR, and threat intelligence platforms.
