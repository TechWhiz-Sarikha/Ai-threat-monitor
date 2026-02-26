# AI-Assisted Web Threat Monitoring System

An AI-assisted security dashboard that classifies web traffic, detects OWASP-aligned attacks, and produces SOC-style summaries for portfolio-ready threat monitoring demos.

## Features

| Feature | Description |
| --- | --- |
| ML Classification | TF-IDF + Logistic Regression classifies malicious vs normal payloads |
| OWASP Detection | Regex-based detection for common web attacks |
| AI Summaries | SOC-style response guidance per threat type |
| Severity Scoring | Maps attack types to severity levels |
| Log Upload | Upload .txt/.log files for analysis |
| Live Dashboard | Auto-refreshing threat monitor UI |

## Tech Stack

- Backend: Python, FastAPI, scikit-learn
- Frontend: React, Vite
- No database, simulated AI summaries

## Quick Start

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | /analyze | Analyze the built-in sample logs |
| GET | /stats | Return detection statistics |
| POST | /analyze-log | Upload a .txt/.log file for analysis |

## Detection Coverage

| Attack Type | OWASP Category | Severity |
| --- | --- | --- |
| SQL Injection | A03:2021 - Injection | High |
| Cross-Site Scripting | A03:2021 - Injection | Medium |
| Directory Traversal | A01:2021 - Broken Access Control | High |
| Command Injection | A03:2021 - Injection | Critical |
| Unknown | A09:2021 - Security Logging and Monitoring Failures | Low |

## Project Structure

```
ai-threat-monitor/
├── backend/
│   ├── main.py
│   ├── ml_model.py
│   ├── threat_engine.py
│   ├── severity_engine.py
│   ├── ai_summarizer.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
└── README.md
```

## Dashboard Features

- Terminal-style SOC UI with scanline overlay and neon status indicators
- Auto-refresh every 30 seconds
- Filtered threat tables with severity badges
- Detailed AI summary panel with OWASP references
- Attack distribution and system metadata sidebar

## Roadmap

- Add exportable reports (PDF/CSV)
- Add user-selectable models and thresholds
- Add rule management for attack signatures
- Add multi-tenant alerting and notification hooks
