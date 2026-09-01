from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
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
def get_alerts(
    severity: Optional[str] = None,
    source_ip: Optional[str] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    sort: str = Query("latest", pattern="^(latest|oldest)$"),
    db: Session = Depends(get_db)
):
    skip = (page - 1) * limit

    alerts = AlertRepository.get_all(
    db=db,
    severity=severity,
    source_ip=source_ip,
    skip=skip,
    limit=limit,
    sort=sort,
)
    total = AlertRepository.count(
        db=db,
        severity=severity,
        source_ip=source_ip,
    )

    total_pages = (total + limit - 1) // limit

    return {
        "page": page,
        "limit": limit,
        "count": len(alerts),
        "total": total,
        "total_pages": total_pages,
        "alerts": [
            {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "risk_score": alert.risk_score,
                "mitre_technique": alert.mitre_technique,
                "mitre_tactic": alert.mitre_tactic,
                "recommended_action": alert.recommended_action,
            }
            for alert in alerts
        ]
    }

@router.get("/alerts/statistics")
def get_alert_statistics(
    db: Session = Depends(get_db)
):
    severity_statistics = AlertRepository.get_severity_statistics(db)

    total_alerts = AlertRepository.count(db)

    high_risk_alerts = AlertRepository.get_high_risk_count(db)

    mitre_technique_statistics = (
        AlertRepository.get_mitre_technique_statistics(db)
    )

    top_source_ips = AlertRepository.get_top_source_ips(db)

    return {
        "total_alerts": total_alerts,
        "high_risk_alerts": high_risk_alerts,
        "severity_distribution": severity_statistics,
        "mitre_technique_distribution": mitre_technique_statistics,
        "top_source_ips": top_source_ips,
    }

@router.get("/alerts/{alert_id}")
def get_alert_by_id(
    alert_id: int,
    db: Session = Depends(get_db)
):
    alert = AlertRepository.get_by_id(
        db=db,
        alert_id=alert_id,
    )

    if alert is None:
        raise HTTPException(
        status_code=404,
        detail="Alert not found"
        )

    return {
        "id": alert.id,
        "title": alert.title,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "risk_score": alert.risk_score,
        "recommended_action": alert.recommended_action,
        "mitre_technique": alert.mitre_technique,
        "mitre_tactic": alert.mitre_tactic,
    }