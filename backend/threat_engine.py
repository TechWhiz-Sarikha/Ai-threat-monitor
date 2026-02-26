import re

PATTERNS = {
    "SQL Injection": re.compile(r"(\bor\b\s+1=1|\bunion\b\s+select|\bselect\b.+\bfrom\b|\bdrop\b\s+table|--|;--|/\*|\*/)", re.IGNORECASE),
    "Cross-Site Scripting": re.compile(r"(<script|onerror=|onload=|<img|<svg|javascript:)", re.IGNORECASE),
    "Directory Traversal": re.compile(r"(\.\./|%2e%2e%2f|%2e%2e\\|/etc/passwd|\\windows\\system32)", re.IGNORECASE),
    "Command Injection": re.compile(r"(;\s*(cat|ls|whoami|id|pwd|curl|wget)|\|\s*(cat|ls|whoami|id|pwd)|&&\s*(cat|ls|whoami|id|pwd)|`.+`)", re.IGNORECASE)
}


def detect_attack_type(payload: str) -> str:
    for attack, pattern in PATTERNS.items():
        if pattern.search(payload):
            return attack
    return "Unknown"
