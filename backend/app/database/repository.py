from sqlalchemy.orm import Session

from backend.app.database.models import Alert


class AlertRepository:

    @staticmethod
    def create(
        db: Session,
        title: str,
        severity: str,
        source_ip: str,
        risk_score: int,
        recommended_action: str,
    ):
        alert = Alert(
            title=title,
            severity=severity,
            source_ip=source_ip,
            risk_score=risk_score,
            recommended_action=recommended_action,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert

    @staticmethod
    def get_all(
        db: Session,
        severity: str | None = None,
        source_ip: str | None = None,
    ):
        query = db.query(Alert)

        if severity:
            query = query.filter(Alert.severity == severity)

        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)

        return query.all()

    @staticmethod
    def get_by_id(
        db: Session,
        alert_id: int,
    ):
        return db.query(Alert).filter(Alert.id == alert_id).first()