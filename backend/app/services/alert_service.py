from sqlalchemy.orm import Session

from backend.app.core.logger import logger
from backend.app.database.repository import AlertRepository
from backend.app.models.alert import Alert
from backend.app.services.storage import alerts


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
    def process_alert(
        alert: Alert,
        db: Session
    ):

        risk_score = AlertService.calculate_risk(alert)

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
        )

        processed_alert = {
            "message": "Alert processed successfully",
            "risk_score": risk_score,
            "recommended_action": recommended_action,
            "alert": alert.model_dump()
        }

        return processed_alert