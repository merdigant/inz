from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    policy = Column(String, default="STANDARD")

    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)

class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)

    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    country = Column(String, nullable=True)
    asn = Column(Integer, nullable=True)
    asn_org = Column(String, nullable=True)



class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True)
    username = Column(String)
    risk_score = Column(Integer)
    decision = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    trace = Column(String, nullable=True)
