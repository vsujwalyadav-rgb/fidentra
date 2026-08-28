from fastapi import APIRouter
from backend.app.models.alert import Alert
from backend.app.services.alert_service import AlertService
from backend.app.core.config import settings


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
def receive_alert(alert: Alert):
    return AlertService.process_alert(alert)