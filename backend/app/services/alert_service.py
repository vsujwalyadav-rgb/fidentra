from sqlalchemy.orm import Session
from backend.app.rules.mitre_rules import MITRE_RULES
from backend.app.core.logger import logger
from backend.app.database.repository import AlertRepository
from backend.app.models.alert import Alert


class AlertService:

    @staticmethod
    def calculate_risk(alert: Alert) -> int:

        if alert.severity.value == "Critical":
            return 100

        if alert.severity.value == "High":
            return 80

        if alert.severity.value == "Medium":
            return 50

        return 20

    @staticmethod
    def map_mitre(alert: Alert) -> dict | None:

        title = alert.title.lower()

        for keyword, rule in MITRE_RULES.items():
            if keyword in title:
                return rule

        return None

    @staticmethod
    def process_alert(
        alert: Alert,
        db: Session
    ):

        risk_score = AlertService.calculate_risk(alert)

        mitre_rule = AlertService.map_mitre(alert)

        mitre_technique = (
        mitre_rule["technique"]
        if mitre_rule
        else None
        )

        mitre_tactic = (
        mitre_rule["tactic"]
        if mitre_rule
        else None
        )

        logger.info(
            f"Received alert: {alert.title} | Severity: {alert.severity}"
        )

        recommended_action = (
            "Investigate immediately"
            if risk_score >= 80
            else "Monitor"
        )

        AlertRepository.create(
            db=db,
            title=alert.title,
            severity=alert.severity.value,
            source_ip=str(alert.source_ip),
            risk_score=risk_score,
            recommended_action=recommended_action,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
        )

        processed_alert = {
            "message": "Alert processed successfully",
            "risk_score": risk_score,
            "recommended_action": recommended_action,
            "mitre_technique": mitre_technique,
            "mitre_tactic": mitre_tactic,
            "mitre_description": (
                mitre_rule["description"]
                if mitre_rule
                else None
            ),
            "mitre_confidence": (
                mitre_rule["confidence"]
                if mitre_rule
                else None
            ),
            "alert": alert.model_dump()
        }

        return processed_alert