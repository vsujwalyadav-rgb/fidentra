from sqlalchemy import Column, DateTime, Integer, String, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String, nullable=False)

    severity = Column(String, nullable=False)

    source_ip = Column(String, nullable=False)

    risk_score = Column(Integer, nullable=False)

    status = Column(
    String,
    nullable=False,
    default="new",
    )

    acknowledged_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    resolved_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    false_positive_at = Column(
        DateTime(timezone=True),
        nullable=True,
    )

    recommended_action = Column(String, nullable=False)

    mitre_technique = Column(String, nullable=True)

    mitre_tactic = Column(String, nullable=True)

    created_at = Column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
    )

    

class AlertStatusHistory(Base):
    __tablename__ = "alert_status_history"

    id = Column(Integer, primary_key=True, index=True)

    alert_id = Column(
        Integer,
        ForeignKey("alerts.id"),
        nullable=False,
    )

    previous_status = Column(
        String,
        nullable=False,
    )

    new_status = Column(
        String,
        nullable=False,
    )

    changed_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    alert = relationship(
        "Alert",
        backref="status_history",
    )