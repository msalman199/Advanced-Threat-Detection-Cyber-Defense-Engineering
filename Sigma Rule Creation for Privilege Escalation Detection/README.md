# Sigma Rule Creation for Privilege Escalation Detection

## Objectives

By the end of this lab, students will be able to:

- Create custom Sigma rules using proper YAML syntax for detecting privilege escalation
- Convert Sigma rules to Elasticsearch queries for integration with ELK Stack
- Configure Logstash pipelines to process security logs and trigger alerts
- Develop Python scripts to automate alert monitoring and incident response
- Validate and test detection rules against simulated attack scenarios

---

## Technologies Used

- Sigma Rules
- Sigma CLI (pySigma)
- Elasticsearch
- Logstash
- Kibana
- Python 3
- Linux (Ubuntu 20.04 LTS)
- YAML
- JSON
- Git

---

## Prerequisites

Students should have:

- Basic Linux command line proficiency
- Understanding of privilege escalation techniques (sudo abuse, SUID exploitation)
- Familiarity with YAML syntax
- Basic Python programming skills
- Knowledge of log analysis concepts

---

## Lab Environment

Al Nafi provides pre-configured Linux cloud machines. Click **Start Lab** to access your environment with:

- Ubuntu 20.04 LTS
- ELK Stack (Elasticsearch, Logstash, Kibana) pre-installed
- Python 3.8+ with pip
- Sigma toolkit repository
- Sample log data for testing

---

# Task 1: Create Sigma Rules for Privilege Escalation Detection

## Step 1.1: Set Up Sigma Toolkit

Install and configure the Sigma toolkit on your lab machine.

```bash
# Clone Sigma repository
cd /opt
sudo git clone https://github.com/SigmaHQ/sigma.git
sudo chown -R $USER:$USER /opt/sigma

# Install dependencies
cd /opt/sigma
pip3 install pysigma pysigma-backend-elasticsearch

# Create working directory
mkdir -p ~/sigma-lab/{rules,logs,scripts,output}
cd ~/sigma-lab
```

---

## Step 1.2: Create Sudo Privilege Escalation Rule

Create a Sigma rule to detect suspicious sudo usage patterns.

```bash
cat > rules/sudo_privilege_escalation.yml << 'EOF'
title: Suspicious Sudo Privilege Escalation
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Detects privilege escalation attempts using sudo
author: Security Lab
date: 2024/01/15
tags:
    - attack.privilege_escalation
    - attack.t1548.003
logsource:
    category: process_creation
    product: linux
detection:
    selection_sudo:
        Image|endswith: '/sudo'
    selection_commands:
        CommandLine|contains:
            - 'sudo su -'
            - 'sudo -i'
            - 'sudo /bin/bash'
            - 'sudo passwd'
            - 'sudo visudo'
    condition: selection_sudo and selection_commands
falsepositives:
    - Legitimate administrative activities
level: medium
EOF
```

---

## Step 1.3: Create SUID Binary Exploitation Rule

Develop a rule for detecting SUID binary abuse.

```bash
cat > rules/suid_exploitation.yml << 'EOF'
title: SUID Binary Privilege Escalation
id: b2c3d4e5-f6g7-8901-bcde-f23456789012
status: experimental
description: Detects privilege escalation via SUID binaries
author: Security Lab
date: 2024/01/15
tags:
    - attack.privilege_escalation
    - attack.t1548.001
logsource:
    category: process_creation
    product: linux
detection:
    selection_binaries:
        Image|endswith:
            - '/find'
            - '/vim'
            - '/python'
            - '/perl'
    selection_commands:
        CommandLine|contains:
            - 'find . -exec /bin/sh'
            - 'vim -c :sh'
            - 'python -c "import os'
    condition: selection_binaries and selection_commands
falsepositives:
    - Legitimate scripting activities
level: high
EOF
```

---

## Step 1.4: Create Additional Privilege Escalation Rule

Create a rule to detect unauthorized user account modifications.

```bash
cat > rules/user_account_modification.yml << 'EOF'
title: Unauthorized User Account Modification
id: c3d4e5f6-g7h8-9012-cdef-345678901234
status: experimental
description: Detects suspicious user account modifications
author: Security Lab
date: 2024/01/15
tags:
    - attack.persistence
    - attack.t1098
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - 'usermod -aG sudo'
            - 'passwd root'
            - 'chsh'
            - 'useradd'
    condition: selection
falsepositives:
    - Legitimate system administration
level: high
EOF
```

---

## Step 1.5: Validate Rule Syntax

Verify your Sigma rules are correctly formatted.

```bash
# Validate rules
for rule in rules/*.yml; do
    echo "Validating: $rule"
    python3 /opt/sigma/tools/sigmac -t es-qs "$rule" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "Valid"
    else
        echo "Syntax error detected"
    fi
done
```

---

# Task 2: Integrate Sigma Rules with ELK Stack

## Step 2.1: Start ELK Services

Ensure all ELK Stack components are running.

```bash
# Start services
sudo systemctl start elasticsearch
sudo systemctl start logstash
sudo systemctl start kibana

# Verify status
sleep 20
sudo systemctl status elasticsearch --no-pager
```

---

## Step 2.2: Convert Sigma Rules to Elasticsearch Format

Create a Python script to convert Sigma rules to Elasticsearch queries.

### File: `scripts/convert_sigma.py`

```python
#!/usr/bin/env python3
import subprocess
import json
import os

def convert_sigma_to_es(rule_path, output_dir):
    """
    Convert Sigma rule to Elasticsearch query format.

    Args:
        rule_path: Path to Sigma YAML rule
        output_dir: Directory to save converted queries

    TODO: Implement conversion using sigmac tool
    TODO: Create Elasticsearch query structure
    TODO: Save output as JSON file
    TODO: Handle conversion errors
    """
    pass

def main():
    """
    Main function to process all Sigma rules.

    TODO: Iterate through rules directory
    TODO: Convert each rule
    TODO: Log conversion results
    """
    rules_dir = "rules"
    output_dir = "output/es-queries"
    os.makedirs(output_dir, exist_ok=True)

    # TODO: Implement conversion logic
    pass

if __name__ == "__main__":
    main()
```

---

## Step 2.3: Configure Logstash Pipeline

Create a Logstash configuration to process security logs.

```bash
sudo tee /etc/logstash/conf.d/sigma-detection.conf << 'EOF'
input {
  file {
    path => "/var/log/auth.log"
    start_position => "beginning"
    tags => ["auth"]
  }
}

filter {
  if "auth" in [tags] {
    grok {
      match => {
        "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{WORD:process}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}"
      }
    }

    if [log_message] =~ /sudo.*(su -|\/bin\/bash|passwd)/ {
      mutate {
        add_field => {
          "alert_type" => "privilege_escalation"
          "rule_name" => "sudo_privilege_escalation"
          "severity" => "medium"
        }
      }
    }
  }
}

output {
  if [alert_type] {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "security-alerts-%{+YYYY.MM.dd}"
    }
  }

  elasticsearch {
    hosts => ["localhost:9200"]
    index => "security-logs-%{+YYYY.MM.dd}"
  }
}
EOF

sudo systemctl restart logstash
```

---

## Step 2.4: Create Elasticsearch Index Template

```bash
curl -X PUT "localhost:9200/_index_template/security-logs" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["security-logs-*", "security-alerts-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp": {"type": "date"},
        "alert_type": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "rule_name": {"type": "keyword"},
        "user": {"type": "keyword"},
        "command": {"type": "text"}
      }
    }
  }
}'
```

---

## Step 2.5: Generate Test Log Data

### File: `scripts/generate_test_logs.py`

```python
#!/usr/bin/env python3
import datetime
import time

def generate_sudo_escalation_log(user, command):
    """
    Generate auth log entry for sudo escalation.

    Args:
        user: Username attempting escalation
        command: Command being executed

    TODO: Format log entry with proper timestamp
    TODO: Write to test log file
    TODO: Return formatted log string
    """
    pass

def generate_suid_exploitation_log(user, binary):
    """
    Generate log entry for SUID binary exploitation.

    TODO: Create realistic log format
    TODO: Include process and command details
    TODO: Write to appropriate log file
    """
    pass

def main():
    """
    Generate various privilege escalation scenarios.

    TODO: Create multiple test scenarios
    TODO: Write logs to /tmp/test_auth.log
    TODO: Copy to /var/log for Logstash processing
    """
    scenarios = [
        ("testuser", "sudo su -"),
        ("testuser", "sudo /bin/bash"),
        ("testuser", "sudo passwd root")
    ]

    # TODO: Implement log generation
    pass

if __name__ == "__main__":
    main()
```

---

# Task 3: Automate Alert Monitoring with Python

## Step 3.1: Create Alert Manager Script

### File: `scripts/alert_manager.py`

```python
#!/usr/bin/env python3
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import time

class AlertManager:
    def __init__(self):
        """
        Initialize AlertManager with Elasticsearch connection.

        TODO: Connect to Elasticsearch
        TODO: Set up alert index pattern
        TODO: Initialize processed alerts tracking
        """
        pass

    def search_alerts(self, time_range_minutes=5):
        """
        Search for new privilege escalation alerts.

        Args:
            time_range_minutes: Time window to search

        Returns:
            List of alert documents

        TODO: Build Elasticsearch query
        TODO: Filter by alert_type and timestamp
        TODO: Return matching alerts
        """
        pass

    def format_alert(self, alert):
        """
        Format alert for notification.
        """
        pass

    def send_console_alert(self, alert):
        """
        Display alert on console.
        """
        pass

    def save_alert_to_file(self, alert):
        """
        Save alert to file for record keeping.
        """
        pass

    def process_alerts(self):
        """
        Main alert processing function.
        """
        pass

    def start_monitoring(self, interval_seconds=30):
        """
        Start continuous alert monitoring.
        """
        pass

if __name__ == "__main__":
    pass
```

---

## Step 3.2: Create Automated Response Script

### File: `scripts/automated_response.py`

```python
#!/usr/bin/env python3
import subprocess
from datetime import datetime

class IncidentResponse:
    def __init__(self):
        """
        Initialize incident response system.
        """
        pass

    def log_action(self, action, details):
        """
        Log response actions taken.
        """
        pass

    def block_user_session(self, username):
        """
        Block user session (simulation for lab).
        """
        pass

    def disable_sudo_access(self, username):
        """
        Temporarily restrict sudo access.
        """
        pass

    def quarantine_file(self, filepath):
        """
        Move suspicious file to quarantine.
        """
        pass

    def respond_to_alert(self, alert):
        """
        Execute appropriate response based on alert.
        """
        pass

    def create_incident_record(self, alert):
        """
        Create detailed incident record.
        """
        pass

if __name__ == "__main__":
    pass
```

---

## Step 3.3: Test Alert System

```bash
# Generate test logs
python3 scripts/generate_test_logs.py

# Wait for Logstash to process
sleep 10

# Run alert manager
python3 scripts/alert_manager.py

# Check output directory for saved alerts
ls -l output/
```

---

# Expected Outcomes

After completing this lab, you should have:

- Three functional Sigma rules detecting different privilege escalation techniques
- Logstash pipeline processing logs and triggering alerts
- Python scripts monitoring Elasticsearch for security alerts
- Automated alert notifications saved to files
- Understanding of Sigma rule structure and ELK integration

---

# Validation Checklist

- Sigma rules validate successfully
- Elasticsearch contains security-alert indices
- Logstash processes incoming logs
- Alert Manager detects privilege escalation events
- Incident response scripts execute correctly
- Alert files are generated in output directory

---

# Troubleshooting Tips

## Elasticsearch not starting

```bash
sudo netstat -tlnp | grep 9200
sudo journalctl -u elasticsearch -n 50
free -h
```

---

## Logstash not processing logs

```bash
sudo /usr/share/logstash/bin/logstash --config.test_and_exit \
-f /etc/logstash/conf.d/sigma-detection.conf

sudo journalctl -u logstash -n 50
```

---

## No alerts appearing

```bash
cat /tmp/test_auth.log

curl localhost:9200/_cat/indices?v

curl localhost:9200/security-alerts-*/_search?pretty
```

---

## Python scripts failing

```bash
pip3 install elasticsearch

curl localhost:9200

python3 --version
```

---

# Conclusion

This lab demonstrated creating Sigma rules for privilege escalation detection and integrating them with the ELK Stack. You learned to:

- Write Sigma detection rules using YAML
- Detect sudo abuse and SUID exploitation attempts
- Convert Sigma rules into Elasticsearch-compatible queries
- Configure Logstash pipelines for automated alert generation
- Build Python-based monitoring and incident response workflows
- Validate detection capabilities using simulated attack data

---

## Key Takeaways

- Sigma provides a vendor-neutral detection rule format
- Privilege escalation is a critical attack stage requiring monitoring
- ELK Stack enables centralized detection and investigation
- Automated alerting improves security operations efficiency
- Testing rules regularly ensures detection effectiveness

---

## Next Steps

- Create Sigma rules for persistence techniques
- Implement MITRE ATT&CK mapping for all detections
- Integrate alerts with ticketing systems
- Develop automated containment workflows
- Expand detection coverage to lateral movement and credential access techniques

---

## Additional Resources

- Sigma Documentation: https://sigmahq.io
- Sigma Rules Repository: https://github.com/SigmaHQ/sigma
- Elasticsearch Documentation: https://www.elastic.co/guide
- Logstash Documentation: https://www.elastic.co/logstash
- Kibana Documentation: https://www.elastic.co/kibana
- MITRE ATT&CK Framework: https://attack.mitre.org
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org
