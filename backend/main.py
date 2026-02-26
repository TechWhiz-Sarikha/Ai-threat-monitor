from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict
from datetime import datetime
import re

from ml_model import predict_payload
from threat_engine import detect_attack_type
from severity_engine import assign_severity
from ai_summarizer import generate_summary

app = FastAPI(title="AI-Assisted Web Threat Monitoring System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

SAMPLE_LOGS = [
    "2026-02-26T10:01:12Z 185.72.14.5 GET /login payload=' OR 1=1 --",
    "2026-02-26T10:02:31Z 10.2.3.4 POST /api/search payload=<script>alert(1)</script>",
    "2026-02-26T10:03:55Z 172.16.0.8 GET /download payload=../../etc/passwd",
    "2026-02-26T10:05:03Z 203.0.113.9 POST /admin payload=;cat /etc/shadow",
    "2026-02-26T10:06:17Z 192.168.1.10 GET /products payload=summer shoes",
    "2026-02-26T10:07:44Z 198.51.100.22 POST /checkout payload=card=4111-1111-1111-1111",
    "2026-02-26T10:08:02Z 203.0.113.44 GET /profile payload=%3Cimg%20src=x%20onerror=alert(1)%3E",
    "2026-02-26T10:09:20Z 10.0.0.5 GET /api/export payload=../windows/system32/drivers/etc/hosts"
]

LOG_REGEX = re.compile(
    r"^(?P<ts>\S+)\s+(?P<ip>\S+)\s+(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<endpoint>\S+)\s+payload=(?P<payload>.*)$",
    re.IGNORECASE
)


def _parse_line(line: str) -> Dict:
    line = line.strip()
    match = LOG_REGEX.match(line)
    if match:
        return {
            "timestamp": match.group("ts"),
            "ip": match.group("ip"),
            "method": match.group("method").upper(),
            "endpoint": match.group("endpoint"),
            "payload": match.group("payload").strip("'\"")
        }

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": "0.0.0.0",
        "method": "GET",
        "endpoint": "/unknown",
        "payload": line
    }


def _confidence(ml_classification: str, attack_type: str) -> float:
    if ml_classification == "malicious" and attack_type != "Unknown":
        return 0.94
    if ml_classification == "malicious" and attack_type == "Unknown":
        return 0.78
    if ml_classification == "normal" and attack_type != "Unknown":
        return 0.62
    return 0.35


def analyze_payload(entry: Dict) -> Dict:
    payload = entry["payload"]
    ml_classification = predict_payload(payload)
    attack_type = detect_attack_type(payload)
    severity = assign_severity(attack_type)
    summary = generate_summary(attack_type, severity, entry["endpoint"])
    confidence = _confidence(ml_classification, attack_type)

    return {
        "timestamp": entry["timestamp"],
        "ip": entry["ip"],
        "endpoint": entry["endpoint"],
        "method": entry["method"],
        "payload": payload,
        "ml_classification": ml_classification,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": confidence,
        "ai_summary": summary
    }


def analyze_logs(lines: List[str]) -> List[Dict]:
    results = []
    for line in lines:
        if line.strip():
            entry = _parse_line(line)
            results.append(analyze_payload(entry))
    return results


def build_stats(results: List[Dict]) -> Dict:
    total = len(results)
    malicious = sum(1 for r in results if r["ml_classification"] == "malicious")
    normal = sum(1 for r in results if r["ml_classification"] == "normal")
    high_sev = sum(1 for r in results if r["severity"] in ["High", "Critical"])
    detection_rate = round((malicious / total) * 100, 2) if total else 0.0

    distribution: Dict[str, int] = {}
    for r in results:
        attack = r["attack_type"]
        distribution[attack] = distribution.get(attack, 0) + 1

    return {
        "total_requests": total,
        "malicious_detected": malicious,
        "normal_traffic": normal,
        "high_severity": high_sev,
        "detection_rate": detection_rate,
        "attack_distribution": distribution
    }


@app.get("/analyze")
def analyze():
    results = analyze_logs(SAMPLE_LOGS)
    return {"results": results}


@app.get("/stats")
def stats():
    results = analyze_logs(SAMPLE_LOGS)
    return build_stats(results)


@app.post("/analyze-log")
async def analyze_log(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".txt", ".log")):
        return {"error": "Only .txt or .log files are supported."}

    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    lines = text.splitlines()
    results = analyze_logs(lines)
    return {"results": results}
