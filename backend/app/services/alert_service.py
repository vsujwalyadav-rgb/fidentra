from sqlalchemy.orm import Session

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
    def map_mitre(alert: Alert) -> tuple[str | None, str | None]:

        title = alert.title.lower()

        if "powershell" in title:
            return "T1059.001", "Execution"

        if "brute force" in title:
            return "T1110", "Credential Access"

        if "impossible travel" in title:
            return "T1078", "Initial Access"

        return None, None

    @staticmethod
    def process_alert(
        alert: Alert,
        db: Session
    ):

        risk_score = AlertService.calculate_risk(alert)

        mitre_technique, mitre_tactic = AlertService.map_mitre(alert)

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
            "alert": alert.model_dump()
        }

        return processed_alert