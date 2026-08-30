from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)

    title = Column(String, nullable=False)

    severity = Column(String, nullable=False)

    source_ip = Column(String, nullable=False)

    risk_score = Column(Integer, nullable=False)

    recommended_action = Column(String, nullable=False)