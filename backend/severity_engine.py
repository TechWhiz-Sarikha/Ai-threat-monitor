SEVERITY_MAP = {
    "Command Injection": "Critical",
    "SQL Injection": "High",
    "Directory Traversal": "High",
    "Cross-Site Scripting": "Medium",
    "Unknown": "Low"
}


def assign_severity(attack_type: str) -> str:
    return SEVERITY_MAP.get(attack_type, "Low")
