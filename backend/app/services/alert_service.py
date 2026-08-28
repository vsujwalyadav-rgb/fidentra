from backend.app.models.alert import Alert
from backend.app.core.logger import logger


class AlertService:
    @staticmethod
    def process_alert(alert: Alert):

        logger.info(
            f"Received alert: {alert.title} | Severity: {alert.severity}"
        )

        return {
            "message": "Alert received successfully",
            "alert": alert
        }