# IEUK Log-Analysis Project

A lightweight Python toolkit for analyzing web server access logs, detecting bot‑like traffic, and summarizing its impact—complete with CSV outputs and bot‑detection heuristics.

📂 Repository Structure
ieuk-projj/
├─ logs/
│ └─ sample-log.log # Raw Apache-style access log
├─ src/
│ ├─ analyze_logs.py # Parses logs → top IPs, URLs, UAs
│ ├─ detect_bots.py # Flags suspect IPs & User-Agents
│ └─ summarize_impact.py # Computes % of bot traffic and top bot-hit URLs
├─ .venv/ # Python virtual environment
├─ .gitignore
├─ requirements.txt # Python dependencies
├─ suspect_ips.csv
├─ suspect_user_agents.csv
├─ top_ips.csv
├─ top_urls.csv
├─ top_user_agents.csv
├─ report.md # 300‑word summary and recommendations
└─ README.md

🛠️ Prerequisites

- Python 3.8+  
- `git` (optional, for version control)  
-  Install Dependencies : py -m pip install -r requirements.txt
-  Analyze logs: py src/analyze_logs.py logs/sample-log.log
-  Detect bots: py src/detect_bots.py
-  Summarize impact: py src/summarize_impact.py
