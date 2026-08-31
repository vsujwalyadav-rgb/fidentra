from backend.app.rules.mitre_rules import MITRE_RULES
from backend.app.models.alert import Alert, Severity
from backend.app.services.alert_service import AlertService

def test_powershell_rule():
    rule = MITRE_RULES["powershell"]

    assert rule["technique"] == "T1059.001"
    assert rule["tactic"] == "Execution"


def test_brute_force_rule():
    rule = MITRE_RULES["brute force"]

    assert rule["technique"] == "T1110"
    assert rule["tactic"] == "Credential Access"


def test_impossible_travel_rule():
    rule = MITRE_RULES["impossible travel"]

    assert rule["technique"] == "T1078"
    assert rule["tactic"] == "Initial Access"

def test_map_mitre_powershell():
    alert = Alert(
        title="PowerShell Execution",
        severity=Severity.MEDIUM,
        source_ip="10.0.0.5",
    )

    rule = AlertService.map_mitre(alert)

    assert rule is not None
    assert rule["technique"] == "T1059.001"
    assert rule["tactic"] == "Execution"


def test_map_mitre_unknown_alert():
    alert = Alert(
        title="Unknown Security Event",
        severity=Severity.LOW,
        source_ip="10.0.0.6",
    )

    rule = AlertService.map_mitre(alert)

    assert rule is None