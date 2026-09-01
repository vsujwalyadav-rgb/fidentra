from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.database.models import Alert
from datetime import date


class AlertRepository:

    @staticmethod
    def create(
        db: Session,
        title: str,
        severity: str,
        source_ip: str,
        risk_score: int,
        recommended_action: str,
        mitre_technique: str | None = None,
        mitre_tactic: str | None = None,
    ):
        alert = Alert(
            title=title,
            severity=severity,
            source_ip=source_ip,
            risk_score=risk_score,
            recommended_action=recommended_action,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
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
        start_date: date | None = None,
        end_date: date | None = None,
        skip: int = 0,
        limit: int = 20,
        sort: str = "latest",
    ):
        query = db.query(Alert)

        if severity:
            query = query.filter(Alert.severity == severity)

        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)

        if start_date:
            query = query.filter(
            func.date(Alert.created_at) >= start_date
        )

        if end_date:
            query = query.filter(
            func.date(Alert.created_at) <= end_date
        )

        if sort == "oldest":
            query = query.order_by(Alert.id.asc())
        else:
            query = query.order_by(Alert.id.desc())

        return query.offset(skip).limit(limit).all()

    @staticmethod
    def count(
        db: Session,
        severity: str | None = None,
        source_ip: str | None = None,
        start_date: date | None = None,
        end_date: date | None = None,
    ):
        query = db.query(Alert)

        if severity:
            query = query.filter(Alert.severity == severity)

        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)

        if start_date:
            query = query.filter(
                func.date(Alert.created_at) >= start_date
            )

        if end_date:
            query = query.filter(
                func.date(Alert.created_at) <= end_date
            )

        return query.count()

    @staticmethod
    def get_by_id(
        db: Session,
        alert_id: int,
    ):
        return db.query(Alert).filter(Alert.id == alert_id).first()

    @staticmethod
    def get_severity_statistics(db: Session):
        results = (
            db.query(
                Alert.severity,
                func.count(Alert.id).label("count")
            )
            .group_by(Alert.severity)
            .all()
        )

        return {
            severity: count
            for severity, count in results
        }

    @staticmethod
    def get_high_risk_count(db: Session):
        return (
            db.query(Alert)
            .filter(Alert.risk_score >= 80)
            .count()
        )

    @staticmethod
    def get_mitre_technique_statistics(db: Session):
        results = (
            db.query(
                Alert.mitre_technique,
                func.count(Alert.id).label("count")
            )
            .filter(Alert.mitre_technique.isnot(None))
            .group_by(Alert.mitre_technique)
            .all()
        )

        return {
            technique: count
            for technique, count in results
        }

    @staticmethod
    def get_top_source_ips(
        db: Session,
        limit: int = 5,
    ):
        results = (
            db.query(
                Alert.source_ip,
                func.count(Alert.id).label("count")
            )
            .group_by(Alert.source_ip)
            .order_by(func.count(Alert.id).desc())
            .limit(limit)
            .all()
        )

        return {
            source_ip: count
            for source_ip, count in results
        }

    @staticmethod
    def get_mitre_tactic_statistics(db: Session):
        results = (
            db.query(
                Alert.mitre_tactic,
                func.count(Alert.id).label("count")
            )
            .filter(Alert.mitre_tactic.isnot(None))
            .group_by(Alert.mitre_tactic)
            .all()
        )

        return {
            tactic: count
            for tactic, count in results
        }

    @staticmethod
    def get_alert_trends(db: Session):
        results = (
            db.query(
                func.date(Alert.created_at).label("date"),
                func.count(Alert.id).label("count"),
            )
            .group_by(func.date(Alert.created_at))
            .order_by(func.date(Alert.created_at))
            .all()
        )

        return {
            str(date): count
            for date, count in results
        }