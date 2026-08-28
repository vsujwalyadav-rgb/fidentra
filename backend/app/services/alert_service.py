from backend.app.models.alert import Alert
from backend.app.core.logger import logger


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
    def process_alert(alert: Alert):

        risk_score = AlertService.calculate_risk(alert)

        logger.info(
            f"Received alert: {alert.title} | Severity: {alert.severity}"
        )

        return {
            "message": "Alert processed successfully",
            "risk_score": risk_score,
            "recommended_action": (
                "Investigate immediately"
                if risk_score >= 80
                else "Monitor"
            ),
            "alert": alert
        }