# Monitor User Risk Behavior with ELK Stack

## Objectives

By the end of this lab, students will be able to:

* Install and configure the ELK Stack (Elasticsearch, Logstash, Kibana) on Linux
* Create Python scripts to simulate user behavior and generate security logs
* Configure Logstash pipelines to parse and enrich user activity data
* Build Kibana dashboards to visualize user risk patterns
* Implement basic alerting for suspicious user activities

---

## Technologies Used

* Elasticsearch 7.x
* Logstash 7.x
* Kibana 7.x
* Python 3.8+
* Ubuntu 20.04 LTS
* JSON
* REST APIs
* Linux System Administration
* Security Monitoring
* User Behavior Analytics (UBA)

---

## Prerequisites

* Basic Linux command line proficiency
* Fundamental Python programming knowledge
* Understanding of JSON data format
* Basic cybersecurity concepts
* Familiarity with log analysis principles

---

## Lab Environment

### Pre-configured Cloud Machine Includes

* Ubuntu 20.04 LTS
* Java 11 (ELK Stack requirement)
* Python 3.8+
* 8GB RAM minimum
* Network access for package installation

Click **Start Lab** to access your dedicated environment.

---

# Task 1: Install and Configure ELK Stack

## Step 1: Install Elasticsearch

```bash
# Update system and install Java
sudo apt update && sudo apt install openjdk-11-jdk -y

# Add Elasticsearch repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list

# Install Elasticsearch
sudo apt update && sudo apt install elasticsearch -y
```

---

## Step 2: Configure Elasticsearch

Edit:

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Add:

```yaml
cluster.name: user-behavior-monitoring
node.name: node-1
network.host: localhost
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
```

Start Elasticsearch:

```bash
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

sleep 30

curl -X GET "localhost:9200/"
```

---

## Step 3: Install and Configure Logstash

```bash
sudo apt install logstash -y

sudo mkdir -p /etc/logstash/conf.d
```

Create:

```bash
sudo nano /etc/logstash/conf.d/user-behavior.conf
```

```ruby
input {
  file {
    path => "/var/log/user-behavior/*.log"
    start_position => "beginning"
    sincedb_path => "/dev/null"
    codec => "json"
  }
}

filter {
  date {
    match => [ "timestamp", "ISO8601" ]
  }

  # TODO: Add risk scoring logic based on activity_type
  # Hint: Use conditional statements and mutate filter

  mutate {
    convert => { "risk_score" => "integer" }
  }

  if [source_ip] {
    geoip {
      source => "source_ip"
      target => "geoip"
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "user-behavior-%{+YYYY.MM.dd}"
  }

  stdout {
    codec => rubydebug
  }
}
```

Start Logstash:

```bash
sudo systemctl start logstash
sudo systemctl enable logstash
```

---

## Step 4: Install and Configure Kibana

```bash
sudo apt install kibana -y
```

Edit:

```bash
sudo nano /etc/kibana/kibana.yml
```

```yaml
server.port: 5601
server.host: "localhost"
elasticsearch.hosts: ["http://localhost:9200"]
```

Start Kibana:

```bash
sudo mkdir -p /var/log/kibana
sudo chown kibana:kibana /var/log/kibana

sudo systemctl start kibana
sudo systemctl enable kibana
```

---

## Step 5: Verify Installation

```bash
curl -X GET "localhost:9200/_cluster/health?pretty"

sudo systemctl status logstash

curl -I http://localhost:5601
```

---

# Task 2: Create User Behavior Simulation Scripts

## Step 1: Set Up Project Directory

```bash
mkdir -p ~/user-behavior-lab
cd ~/user-behavior-lab

sudo mkdir -p /var/log/user-behavior
sudo chmod 777 /var/log/user-behavior
```

---

## Step 2: Create Behavior Simulator

Create:

```bash
nano user_behavior_simulator.py
```

### Features to Implement

* Generate normal user behavior
* Generate failed login attempts
* Simulate privilege escalation attempts
* Create after-hours file access events
* Simulate large file downloads
* Log all events in JSON format

### Learning Goals

Students will implement:

* Logging configuration
* Randomized event generation
* Risk-based activity simulation
* Continuous event generation
* Security event logging

---

## Step 3: Create Risk Analyzer

Create:

```bash
nano risk_analyzer.py
```

### Features to Implement

* Query Elasticsearch indices
* Calculate user risk scores
* Categorize users by risk level
* Retrieve high-risk activities
* Generate security reports

### Risk Categories

| Score | Risk Level |
| ----- | ---------- |
| 0-4   | Low        |
| 5-7   | Medium     |
| 8-9   | High       |
| 10+   | Critical   |

---

## Step 4: Run Simulation

```bash
chmod +x user_behavior_simulator.py
chmod +x risk_analyzer.py

pip3 install requests

python3 user_behavior_simulator.py &
```

Monitor logs:

```bash
tail -f /var/log/user-behavior/user_activity.log
```

---

# Task 3: Build Kibana Dashboards

## Step 1: Create Index Pattern

Open Kibana:

```text
http://localhost:5601
```

Navigate:

```text
Management
 → Stack Management
 → Index Patterns
 → Create Index Pattern
```

Pattern:

```text
user-behavior-*
```

Time field:

```text
@timestamp
```

---

## Step 2: Create Visualizations

### Risk Score Distribution

* Visualization Type: Vertical Bar Chart
* Y-Axis: Count
* X-Axis: Terms Aggregation on `risk_score`

Save As:

```text
Risk Score Distribution
```

---

### Top Risky Users

* Visualization Type: Data Table
* Metric: Sum of `risk_score`
* Bucket: Terms on `user.keyword`

Save As:

```text
Top Risky Users
```

---

### Activity Timeline

* Visualization Type: Line Chart
* Y-Axis: Count
* X-Axis: Date Histogram on `@timestamp`

Save As:

```text
Activity Timeline
```

---

### Activity Type Breakdown

* Visualization Type: Pie Chart
* Slice By: Terms on `activity_type.keyword`

Save As:

```text
Activity Types
```

---

## Step 3: Build Dashboard

Navigate:

```text
Dashboard
 → Create Dashboard
```

Add:

* Risk Score Distribution
* Top Risky Users
* Activity Timeline
* Activity Types

Configuration:

```text
Time Range: Last 1 Hour
Auto Refresh: 10 Seconds
```

Save Dashboard:

```text
User Behavior Risk Monitoring
```

---

## Step 4: Create Alert Monitor

Create:

```bash
nano alert_monitor.py
```

### Features to Implement

* Query Elasticsearch periodically
* Detect users exceeding risk thresholds
* Generate alert messages
* Continuous monitoring loop
* Alert notification framework

---

# Task 4: Test and Validate Detection

## Step 1: Generate Test Events

```bash
# Simulate suspicious shell activity
bash -c 'sleep 30' &

# Simulate suspicious network activity
nc -l 4444 &
sleep 5
killall nc

# Simulate file activity
touch /tmp/test_file.sh
echo "#!/bin/bash" > /tmp/test_file.sh
rm /tmp/test_file.sh
```

---

## Step 2: Run Detection Scripts

```bash
cd ~/user-behavior-lab

python3 risk_analyzer.py
```

Review results:

```bash
cat /tmp/threat_report_*.json | jq '.'
```

Run monitoring:

```bash
python3 alert_monitor.py
```

---

## Step 3: Validate Data Collection

Check logs:

```bash
sudo tail -50 /var/log/user-behavior/user_activity.log
```

Verify Elasticsearch indices:

```bash
curl -X GET "localhost:9200/_cat/indices?v"
```

Review reports:

```bash
ls -lh /tmp/threat_report_*.json
```

---

# Expected Outcomes

After completing this lab, students should have:

* Fully functional ELK Stack
* User behavior simulation environment
* Automated risk analysis scripts
* Log enrichment and processing workflows
* Interactive Kibana dashboards
* Basic alert monitoring capabilities
* Understanding of User Behavior Analytics (UBA)

---

# Validation Checklist

### ELK Stack

* [ ] Elasticsearch running
* [ ] Logstash processing logs
* [ ] Kibana accessible

### Data Collection

* [ ] Logs generated successfully
* [ ] Events indexed in Elasticsearch
* [ ] Data visible in Kibana

### Risk Monitoring

* [ ] Risk scores calculated correctly
* [ ] High-risk users identified
* [ ] Alerts generated

### Dashboard

* [ ] Visualizations working
* [ ] Dashboard auto-refresh enabled
* [ ] Security metrics displayed correctly

---

# Troubleshooting Tips

## Elasticsearch Won't Start

```bash
sudo journalctl -u elasticsearch -f

java -version

df -h
```

---

## No Data in Kibana

```bash
ls -la /var/log/user-behavior/

curl -X GET "localhost:9200/_cat/indices?v"

sudo /usr/share/logstash/bin/logstash \
--config.test_and_exit \
--path.config=/etc/logstash/conf.d/
```

---

## Logstash Not Processing Logs

```bash
sudo tail -f /var/log/logstash/logstash-plain.log

sudo systemctl restart logstash

ls -la /var/log/user-behavior/
```

---

## Python Script Errors

```bash
pip3 install requests

sudo chmod 777 /var/log/user-behavior/
```

---

# Conclusion

This lab demonstrated how to build a complete User Behavior Monitoring solution using the ELK Stack. Students gained practical experience deploying Elasticsearch, Logstash, and Kibana, generating security event data with Python, enriching logs through Logstash pipelines, creating risk-based analytics, and building dashboards for monitoring suspicious activities.

## Key Takeaways

* ELK Stack enables centralized security monitoring
* User Behavior Analytics improves threat visibility
* Risk scoring prioritizes security investigations
* Dashboards provide real-time situational awareness
* Automated alerting reduces incident response times
* Log enrichment enhances security context

## Next Steps

* Implement machine learning anomaly detection
* Add advanced correlation rules
* Integrate with enterprise SIEM platforms
* Build automated incident response workflows
* Scale deployment using distributed ELK clusters
* Incorporate threat intelligence feeds

This lab provides a strong foundation for Security Operations Center (SOC) monitoring, insider threat detection, and enterprise-scale user behavior analytics.
