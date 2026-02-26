from typing import Dict


def generate_summary(attack_type: str, severity: str, endpoint: str) -> Dict:
    if attack_type == "SQL Injection":
        return {
            "what_happened": "Input appears to manipulate SQL logic to bypass authentication or extract data.",
            "potential_impact": "Unauthorized access to database records, data leakage, or data manipulation.",
            "recommended_action": "Parameterize queries, validate inputs, and review database access logs.",
            "owasp_reference": "A03:2021 - Injection",
            "targeted_endpoint": endpoint,
            "severity_level": severity
        }

    if attack_type == "Cross-Site Scripting":
        return {
            "what_happened": "User-supplied script content was detected, likely attempting to execute in a client browser.",
            "potential_impact": "Session hijacking, credential theft, or defacement of content.",
            "recommended_action": "Encode output, sanitize inputs, and enforce Content Security Policy.",
            "owasp_reference": "A03:2021 - Injection",
            "targeted_endpoint": endpoint,
            "severity_level": severity
        }

    if attack_type == "Directory Traversal":
        return {
            "what_happened": "Request contains traversal sequences that attempt to access restricted files.",
            "potential_impact": "Exposure of system files, configuration secrets, or credentials.",
            "recommended_action": "Normalize paths, restrict filesystem access, and enforce allowlists.",
            "owasp_reference": "A01:2021 - Broken Access Control",
            "targeted_endpoint": endpoint,
            "severity_level": severity
        }

    if attack_type == "Command Injection":
        return {
            "what_happened": "Payload indicates shell metacharacters used to execute arbitrary commands.",
            "potential_impact": "Remote code execution, system compromise, and lateral movement.",
            "recommended_action": "Avoid shell execution, sanitize inputs, and run services with least privilege.",
            "owasp_reference": "A03:2021 - Injection",
            "targeted_endpoint": endpoint,
            "severity_level": severity
        }

    return {
        "what_happened": "No known attack signature matched; activity appears low risk.",
        "potential_impact": "Minimal. Monitor for anomalous patterns over time.",
        "recommended_action": "Continue monitoring and enforce baseline input validation.",
        "owasp_reference": "A09:2021 - Security Logging and Monitoring Failures",
        "targeted_endpoint": endpoint,
        "severity_level": severity
    }
