# app/models.py

from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean, default=False)
