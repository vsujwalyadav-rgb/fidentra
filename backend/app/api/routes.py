from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.database.connection import get_db
from backend.app.models.alert import Alert
from backend.app.services.alert_service import AlertService
from backend.app.database.repository import AlertRepository

router = APIRouter()


@router.get("/")
def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "running",
        "documentation": "/docs"
    }


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Fidentra API",
        "version": "0.1.0"
    }


@router.post("/alerts")
def receive_alert(
    alert: Alert,
    db: Session = Depends(get_db)
):
    return AlertService.process_alert(alert, db)


@router.get("/alerts")
@router.get("/alerts")
def get_alerts(
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    db: Session = Depends(get_db)
):
    alerts = AlertRepository.get_all(
        db=db,
        severity=severity,
        source_ip=source_ip,
    )

    return {
        "count": len(alerts),
        "alerts": [
            {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "risk_score": alert.risk_score,
                "recommended_action": alert.recommended_action,
            }
            for alert in alerts
        ]
    }