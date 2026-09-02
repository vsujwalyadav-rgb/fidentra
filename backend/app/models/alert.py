from enum import Enum

from pydantic import BaseModel, IPvAnyAddress


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Alert(BaseModel):
    title: str
    severity: Severity
    source_ip: IPvAnyAddress

from typing import Literal
class AlertStatusUpdate(BaseModel):
    status: Literal[
        "new",
        "in_progress",
        "resolved",
        "false_positive",
    ]