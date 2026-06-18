# 🧭 Threat Mapping with MITRE ATT&CK Navigator Lab

![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![Navigator](https://img.shields.io/badge/Tool-ATT%26CK%20Navigator-blue)
![Python](https://img.shields.io/badge/Language-Python%203.x-yellow)
![Focus](https://img.shields.io/badge/Focus-Threat%20Intelligence-critical)
![Level](https://img.shields.io/badge/Difficulty-Intermediate-orange)

---

# 🎯 Objectives

By the end of this lab, students will be able to:

🧭 Navigate the **MITRE ATT&CK Navigator** interface  
🎯 Map adversary TTPs to real-world threat actors  
📊 Create custom threat intelligence layers  
🛡️ Analyze defense gaps against adversary techniques  
📌 Generate actionable security recommendations  

---

# 📌 Prerequisites

Before starting this lab, students should have:

🧠 Basic cybersecurity knowledge (attack lifecycle)  
🐧 Linux command-line familiarity  
🐍 Python basics (loops, functions, dictionaries)  
📄 Understanding of JSON data format  

---

# 🖥️ Lab Environment

⚙️ **Al Nafi Cloud Machine**

Includes:

🧾 Ubuntu 22.04 LTS (GUI enabled)  
🐍 Python 3.10+ preinstalled  
🌐 Firefox browser  
🧰 Text editors (nano, vim, gedit)  
📦 MITRE ATT&CK Navigator preloaded  

👉 Click **Start Lab** to begin

---

# 🧩 Task 1: MITRE ATT&CK Navigator Setup

---

## 🚀 Step 1.1: Launch Navigator

```bash id="nav-start"
cd ~/attack-navigator
npm start

🌐 Open in browser:

http://localhost:4200
🧭 Step 1.2: Explore Interface

Key components:

🟦 Tactics → Attack goals (Initial Access, Execution, Persistence)
🟨 Techniques → Attack methods
🧩 Sub-techniques → Detailed variations
⚙️ Layer Controls → Visualization tools

🔍 Practice Navigation

✔ Search: PowerShell
✔ Click: T1566 (Phishing)
✔ Toggle views: Compact / Expanded
✔ Inspect technique details panel

📊 Step 1.3: Create Baseline Layer
Name: Lab1-Baseline
Domain: Enterprise ATT&CK
Description: Baseline threat mapping exercise

📁 Save:

mkdir -p ~/threat-mapping-lab

Save as:

~/threat-mapping-lab/baseline-layer.json
🧩 Task 2: Threat Actor Mapping (APT29)
🕵️ Step 2.1: APT29 Research Layer

Create new layer:

Name: APT29-Mapping
🎯 Step 2.2: Map ATT&CK Techniques
📧 Initial Access
T1566.001 → Spearphishing Attachment → Score 3 🔴
T1566.002 → Spearphishing Link → Score 3 🔴
⚙️ Execution
T1059.001 → PowerShell → Score 3 🔴
T1059.003 → Command Shell → Score 2 🟡
🔁 Persistence
T1547.001 → Registry Run Keys → Score 2 🟡
T1078.004 → Cloud Accounts → Score 3 🔴
🧬 Defense Evasion
T1055 → Process Injection → Score 3 🔴
T1027 → Obfuscation → Score 3 🔴
🔐 Credential Access
T1003.001 → LSASS Dumping → Score 2 🟡
T1555.003 → Browser Credentials → Score 3 🔴
🔎 Discovery
T1083 → File Discovery → Score 2 🟡
T1057 → Process Discovery → Score 2 🟡
📦 Collection
T1114.002 → Email Collection → Score 3 🔴
🌐 C2
T1071.001 → Web Protocols → Score 3 🔴
📤 Exfiltration
T1041 → Exfiltration Over C2 → Score 3 🔴
📝 Step 2.3: Add Intelligence Notes

Example:

T1566.001:
APT29 uses spearphishing documents with macros.
Used in COVID-19 research targeting campaigns.
💾 Save Layer
apt29-mapping.json
🧩 Step 3: Automated Threat Mapping (Python)
🐍 Threat Mapper Script
mkdir -p ~/threat-mapping-lab

cat > ~/threat-mapping-lab/threat_mapper.py << 'EOF'
#!/usr/bin/env python3
import json
from datetime import datetime

class ThreatMapper:
    def __init__(self):
        self.base_layer = {
            "name": "",
            "domain": "enterprise-attack",
            "techniques": []
        }

    def create_technique_entry(self, tid, score, comment=""):
        return {
            "techniqueID": tid,
            "score": score,
            "comment": comment,
            "enabled": True
        }

    def create_threat_layer(self, actor, techniques):
        layer = self.base_layer.copy()
        layer["name"] = f"{actor}-{datetime.now().date()}"
        layer["description"] = f"Threat mapping for {actor}"

        for tid, score, comment in techniques:
            layer["techniques"].append(
                self.create_technique_entry(tid, score, comment)
            )

        return layer

    def save_layer(self, layer, filename):
        with open(filename, "w") as f:
            json.dump(layer, f, indent=4)
        print("Saved:", filename)

    def generate_statistics(self, layer):
        stats = {"total": len(layer["techniques"])}
        stats["high"] = len([t for t in layer["techniques"] if t["score"] == 3])
        stats["medium"] = len([t for t in layer["techniques"] if t["score"] == 2])
        stats["low"] = len([t for t in layer["techniques"] if t["score"] == 1])
        return stats


def main():
    mapper = ThreatMapper()

    apt29 = [
        ("T1566.001", 3, "Spearphishing attachments"),
        ("T1059.001", 3, "PowerShell execution"),
        ("T1071.001", 3, "Web C2 communication")
    ]

    layer = mapper.create_threat_layer("APT29", apt29)

    mapper.save_layer(layer, "apt29-layer.json")

    print("Stats:", mapper.generate_statistics(layer))

if __name__ == "__main__":
    main()
EOF

chmod +x ~/threat-mapping-lab/threat_mapper.py
python3 ~/threat-mapping-lab/threat_mapper.py
🧩 Task 4: Defense Gap Analysis
🛡️ Defense Mapping Concept

Score system:

🟢 3 → Strong protection
🟡 2 → Partial coverage
🔴 1 → Weak/no defense

🧠 Defense Analyzer Script
cat > ~/threat-mapping-lab/defense_analyzer.py << 'EOF'
#!/usr/bin/env python3
import json

class DefenseAnalyzer:
    def load_layer(self, file):
        with open(file) as f:
            return json.load(f)

    def calculate_gaps(self, threat, defense):
        gaps = {"critical": [], "high": [], "medium": []}

        for t in threat["techniques"]:
            tid = t["techniqueID"]
            ts = t["score"]
            ds = 1  # default weak defense

            gap = ts - ds

            if gap >= 2:
                gaps["critical"].append(tid)
            elif gap == 1:
                gaps["high"].append(tid)
            else:
                gaps["medium"].append(tid)

        return gaps

    def generate_recommendations(self, gaps):
        recs = []
        for tid in gaps["critical"]:
            recs.append(f"Upgrade detection for {tid}")
        return recs


def main():
    analyzer = DefenseAnalyzer()
    print("Defense gap analysis complete (template)")

if __name__ == "__main__":
    main()
EOF
🧩 Task 5: Output & Visualization
📊 Load Layers in Navigator

✔ Baseline layer
✔ APT29 mapping layer
✔ Defense coverage layer
✔ Gap analysis layer

🔥 Key Insights

🧠 APT29 uses spearphishing heavily
⚙️ PowerShell is primary execution method
🛡️ Cloud account security is critical weak point
📡 C2 communication is web-based

📌 Expected Outcomes

✔ ATT&CK Navigator layer creation
✔ Threat actor technique mapping
✔ Automated Python threat modeling
✔ Defense gap identification
✔ Security recommendation generation

⚠️ Troubleshooting

❌ Navigator not loading → restart npm start
❌ Layer not importing → check JSON format
❌ Python error → verify file paths
❌ Missing techniques → ensure correct ATT&CK IDs

🏁 Conclusion

You learned:

🧭 MITRE ATT&CK threat mapping
🎯 APT29 technique analysis
🐍 Python-based automation of threat intelligence
🛡️ Defense gap analysis and prioritization

🚀 Next Steps
Map additional threat actors (Lazarus, FIN7)
Integrate ATT&CK with SIEM tools
Automate threat intelligence ingestion
Build enterprise security dashboards
