# app/app.py

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from pydantic import BaseModel, constr

from app.database import Base, engine, SessionLocal
from app.security import hash_password, verify_password


app = FastAPI(
    title="Adaptive Authentication MVP",
    version="0.1.0"
)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

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
    username = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    success = Column(Boolean)

class UserCreate(BaseModel):
    username: str
    password: constr(min_length=8, max_length=64)


class LoginRequest(BaseModel):
    username: str
    password: str


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False)
    risk_score = Column(Integer, nullable=False)
    decision = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/users", status_code=201)
def register_user(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=409, detail="User already exists")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password)
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "User created"}

def calculate_risk(db: Session, username: str) -> int:
    """
    Minimalny, deterministyczny risk engine.
    Bazuje WYŁĄCZNIE na historii logowań.
    """
    attempts = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.username == username)
        .order_by(LoginAttempt.timestamp.desc())
        .limit(5)
        .all()
    )

    score = 0

    # Reguła 1: ostatnia próba nieudana
    if attempts and not attempts[0].success:
        score += 30

    # Reguła 2: >= 3 nieudane próby w ostatnich 5
    failed = [a for a in attempts if not a.success]
    if len(failed) >= 3:
        score += 40

    return score

@app.post("/auth/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()

    success = False
    if user and verify_password(payload.password, user.password_hash):
        success = True

    # ❌ BŁĘDNE HASŁO — ZAPISZ I WYJDŹ
    if not success:
        attempt = LoginAttempt(
            username=payload.username,
            success=False
        )
        db.add(attempt)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    # ✅ TU JEST KLUCZ — LICZYMY RYZYKO ZANIM ZAPISZEMY SUKCES
    risk_score = calculate_risk(db, payload.username)

    # TERAZ dopiero zapisujemy SUCCESS
    attempt = LoginAttempt(
        username=payload.username,
        success=True
    )
    db.add(attempt)
    db.commit()

    decision = "MFA_REQUIRED" if risk_score >= 50 else "ALLOW"

    assessment = RiskAssessment(
        username=payload.username,
        risk_score=risk_score,
        decision=decision
    )
    db.add(assessment)
    db.commit()

    if decision == "MFA_REQUIRED":
        return {
            "status": "MFA_REQUIRED",
            "risk_score": risk_score
        }

    return {
        "status": "AUTHENTICATED",
        "risk_score": risk_score
    }


@app.get("/debug/assessments")
def list_risk_assessments(db: Session = Depends(get_db)):
    return db.query(RiskAssessment).order_by(RiskAssessment.timestamp.desc()).all()

