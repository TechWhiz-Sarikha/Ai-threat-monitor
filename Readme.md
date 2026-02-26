<div align="center">

<br/>

```
█████╗ ██╗    ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
██╔══██╗██║    ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
███████║██║       ██║   ███████║██████╔╝█████╗  ███████║   ██║
██╔══██║██║       ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
██║  ██║██║       ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
╚═╝  ╚═╝╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
    MONITOR
```

### AI-Assisted Web Threat Monitoring System

**Real-time web threat detection · ML classification · SOC-style AI summaries**

<br/>

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-000000?style=for-the-badge&logo=owasp&logoColor=white)

![Status](https://img.shields.io/badge/Status-Active-30d158?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-4cc9f0?style=flat-square)
![Portfolio](https://img.shields.io/badge/Project-Portfolio-ff6b35?style=flat-square)

<br/>

</div>

---

## ⬡ Overview

A Python-powered security engine that **detects OWASP Top 10 web attacks in real time**, classifies traffic using **Machine Learning**, scores severity, and generates **SOC-analyst-style AI incident summaries** — all visualized on a live React dashboard built with a dark terminal aesthetic.

Built to demonstrate practical skills in:
`Python` · `Security Automation` · `Machine Learning` · `REST APIs` · `OWASP` · `Frontend Engineering`

---

## 🎯 Features

| Module | What It Does |
|---|---|
| 🤖 **ML Classifier** | TF-IDF + Logistic Regression pipeline classifies every payload as `malicious` or `normal` with confidence score |
| 🔍 **Threat Detection Engine** | Regex-based OWASP rule engine catches SQLi, XSS, Directory Traversal, Command Injection |
| ⚠️ **Severity Scoring** | Maps each attack to `Critical` / `High` / `Medium` / `Low` severity level |
| 🧠 **AI Summary Engine** | Generates structured SOC-style incident reports: what happened, impact, recommended action, OWASP reference |
| 📂 **Log File Analysis** | Upload any `.txt` or `.log` file — system analyzes every line and returns full threat report |
| 📊 **Live Dashboard** | React + Vite dashboard with real-time stats, filterable threat table, attack distribution, and click-to-expand incident detail panel |
| 🔄 **Auto Refresh** | Dashboard polls the API every 30 seconds automatically |

---

## 🛠️ Tech Stack

```
Backend                          Frontend
───────────────────────────      ───────────────────────────
Python 3.10+                     React 18
FastAPI                          Vite 5
scikit-learn (ML pipeline)       JetBrains Mono font
TF-IDF Vectorizer                Fetch API
Logistic Regression              Auto-refresh (setInterval)
Uvicorn (ASGI server)
python-multipart (file upload)
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+

---

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/ai-threat-monitor.git
cd ai-threat-monitor
```

---

### 2. Start the Backend

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate — Windows
venv\Scripts\activate

# Activate — Linux / Mac
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn main:app --reload
```

```
✓  API running   →  http://127.0.0.1:8000
✓  Swagger docs  →  http://127.0.0.1:8000/docs
```

---

### 3. Start the Frontend *(new terminal)*

```bash
cd frontend
npm install
npm run dev
```

```
✓  Dashboard  →  http://localhost:3000
```

---

## 📡 API Reference

### `GET /analyze`
Returns threat analysis of sample web logs.

**Response:**
```json
[
  {
    "timestamp": "2025-02-26 14:32:10",
    "ip": "192.168.1.10",
    "endpoint": "/login",
    "method": "POST",
    "payload": "' OR 1=1 --",
    "ml_classification": "malicious",
    "attack_type": "SQL Injection",
    "severity": "High",
    "confidence": 97.2,
    "ai_summary": {
      "what_happened": "Attacker injected malicious SQL statements...",
      "potential_impact": "Unauthorized database access, credential theft...",
      "recommended_action": "Enforce parameterized queries, apply WAF rules...",
      "owasp_reference": "A03:2021 – Injection",
      "targeted_endpoint": "/login",
      "severity_level": "High"
    }
  }
]
```

---

### `GET /stats`
Returns aggregated threat statistics.

**Response:**
```json
{
  "total_requests": 8,
  "malicious_detected": 5,
  "normal_traffic": 3,
  "high_severity": 3,
  "detection_rate": 62.5,
  "attack_distribution": {
    "SQL Injection": 2,
    "Cross-Site Scripting": 1,
    "Directory Traversal": 1,
    "Command Injection": 1
  }
}
```

---

### `POST /analyze-log`
Upload a `.txt` or `.log` file for batch analysis.

```bash
curl -X POST "http://127.0.0.1:8000/analyze-log" \
     -F "file=@your_logs.txt"
```

---

## 🎯 Detection Coverage

| Attack Type | OWASP 2021 | Severity | Detection Method |
|---|---|---|---|
| SQL Injection | A03 – Injection | 🔴 High | Regex + ML |
| Cross-Site Scripting | A03 – Injection | 🟡 Medium | Regex + ML |
| Directory Traversal | A01 – Broken Access Control | 🔴 High | Regex + ML |
| Command Injection | A03 – Injection | 🟣 Critical | Regex + ML |
| Unknown / Anomalous | — | 🟢 Low | ML only |

---

## 📁 Project Structure

```
ai-threat-monitor/
│
├── backend/
│   ├── main.py              ← FastAPI app · CORS · all endpoints
│   ├── ml_model.py          ← TF-IDF pipeline · Logistic Regression
│   ├── threat_engine.py     ← OWASP regex pattern detection
│   ├── severity_engine.py   ← Attack → severity mapping
│   ├── ai_summarizer.py     ← SOC-style structured incident summaries
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── App.jsx          ← Full dashboard (single component file)
│   │   └── main.jsx         ← React 18 entry point
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
│
└── README.md
```

---

## 🖥️ Dashboard

**The React frontend connects to the FastAPI backend and displays:**

```
┌─────────────────────────────────────────────────────────────────┐
│  ⬡ AI Threat Monitor                       ↻ REFRESH  ↑ LOG   │
│  Web Threat Intelligence · ML Classification · OWASP Detection  │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│      8       │      5       │      3       │        3           │
│  TOTAL REQ   │   THREATS    │  HIGH SEV    │     NORMAL         │
├──────────────────────────────────────────┬─────────────────────┤
│  [ALL (8)]  [⚠ MALICIOUS (5)]  [✓ NORMAL]│  Attack Distrib.   │
│                                          │  SQL Injection ████ │
│  Time    IP            Endpoint  Type    │  XSS          ██    │
│  ──────────────────────────────────────  │  Dir Traversal ██   │
│  14:32   192.168.1.10  /login    SQLi    │                     │
│  14:32   10.0.0.5      /search   XSS     │  Severity Legend    │
│  14:32   172.16.0.8    /file     DirTrav │  🟣 Critical        │
│  ...                                     │  🔴 High            │
│                                          │  🟡 Medium          │
│                                          │  🟢 Low             │
├──────────────────────────────────────────┴─────────────────────┤
│  INCIDENT DETAIL  ─  SQL Injection · 192.168.1.10 · /login     │
│  ┌─────────────────────┐  ┌──────────────────────────┐         │
│  │  WHAT HAPPENED      │  │  POTENTIAL IMPACT        │         │
│  │  Attacker injected  │  │  Unauthorized DB access  │         │
│  │  malicious SQL...   │  │  credential theft...     │         │
│  └─────────────────────┘  └──────────────────────────┘         │
│  ┌─────────────────────┐  ┌──────────────────────────┐         │
│  │  RECOMMENDED ACTION │  │  OWASP REFERENCE         │         │
│  │  Use parameterized  │  │  A03:2021 – Injection    │         │
│  │  queries, WAF...    │  │                          │         │
│  └─────────────────────┘  └──────────────────────────┘         │
│  RAW PAYLOAD:  ' OR 1=1 --                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧪 Test with a Sample Log File

Create a file `test_logs.txt` and upload it via the dashboard:

```
' OR 1=1 --
<script>alert(document.cookie)</script>
../../etc/passwd
UNION SELECT username, password FROM users
normal product search
user login attempt
exec(base64_decode('malicious'))
view order history
```

---

## 📌 Roadmap

- [x] Python detection engine (regex + ML)
- [x] FastAPI REST backend with file upload
- [x] Live React dashboard with SOC terminal design
- [x] AI-generated incident summaries
- [ ] Real OpenAI / Gemini API integration
- [ ] PostgreSQL threat history logging
- [ ] Live Apache / Nginx log tail ingestion
- [ ] Expanded ML dataset (1000+ labeled samples)
- [ ] Confusion matrix + precision/recall metrics
- [ ] Docker containerization
- [ ] IEEE research paper

---

## 💡 Skills Demonstrated

```
Security         →  OWASP Top 10 · Attack pattern detection · Severity classification
Python           →  FastAPI · scikit-learn · regex · REST API design
Machine Learning →  Text classification · TF-IDF · pipeline architecture
Frontend         →  React 18 · component design · async data fetching
Engineering      →  Modular architecture · clean separation of concerns
```

---

## 👩‍💻 Author

**Sarikha S**

Cybersecurity · VAPT · Ethical Hacking · CTF · AI Security

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/your-profile)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/your-username)

---

<div align="center">

*Built with Python + React · OWASP Top 10 Detection · ML Classification · Portfolio Project*

⬡

</div>
