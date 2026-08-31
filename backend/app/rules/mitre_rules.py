MITRE_RULES = {
    "powershell": {
        "technique": "T1059.001",
        "tactic": "Execution",
        "description": "PowerShell is used to execute commands or scripts.",
        "confidence": 0.95,
    },
    "brute force": {
        "technique": "T1110",
        "tactic": "Credential Access",
        "description": "Repeated attempts are made to obtain or guess credentials.",
        "confidence": 0.90,
    },
    "impossible travel": {
        "technique": "T1078",
        "tactic": "Initial Access",
        "description": "Valid accounts may be used from geographically inconsistent locations.",
        "confidence": 0.75,
    },
}