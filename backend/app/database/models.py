from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base

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

    recommended_action = Column(String, nullable=False)

    mitre_technique = Column(String, nullable=True)

    mitre_tactic = Column(String, nullable=True)

    created_at = Column(
    DateTime(timezone=True),
    server_default=func.now(),
    nullable=False,
    )