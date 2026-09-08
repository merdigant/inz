from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from datetime import datetime
from pydantic import BaseModel, constr
from fastapi import Request


from app.risk.context import RiskContext
from app.risk.engine import RiskEngine
from app.risk.rules import (
    FailedAttemptsRule,
    LastAttemptFailedRule,
    NewIPRule,
    NewUserAgentRule,
    UnusualHourRule,
    RapidAttemptsRule,
    UnusualLoginPatternRule,
    NewCountryRule,
    RiskyASNRule,
    ImpossibleTravelRule,
    PositiveLoginHistoryRule,
    ChronicRiskRule,
    ConfidenceDecayRule,
)

from app.database import Base, engine, SessionLocal
from app.security import hash_password, verify_password
from app.models import User, LoginAttempt, RiskAssessment

from app.geo.lookup import GeoLookup
from app.risk.normalization import normalize

from app.risk.policies import decide_mfa

MAX_RAW_SCORE = 335


geo = GeoLookup(
    country_db="app/geo/GeoLite2-Country.mmdb",
    asn_db="app/geo/GeoLite2-ASN.mmdb"
)


app = FastAPI(
    title="Adaptive Authentication MVP",
    version="0.1.0"
)

def build_risk_engine() -> RiskEngine:
    return RiskEngine(
        rules=[
            FailedAttemptsRule(),
            LastAttemptFailedRule(),
            NewIPRule(),
            NewUserAgentRule(),
            UnusualHourRule(),
            RapidAttemptsRule(),
            UnusualLoginPatternRule(),
            NewCountryRule(),
            RiskyASNRule(),
            ImpossibleTravelRule(),
            PositiveLoginHistoryRule(),
            ChronicRiskRule(),
            ConfidenceDecayRule(),
        ]
    )

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

class UserCreate(BaseModel):
    username: str
    password: constr(min_length=8, max_length=64)


class LoginRequest(BaseModel):
    username: str
    password: str


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

def calculate_risk(
    db: Session,
    username: str,
    client_ip: str | None,
    user_agent: str | None,
    country: str | None,
    asn: str | None,
    asn_org: str | None
) -> int:

    attempts = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.username == username)
        .order_by(LoginAttempt.timestamp.desc())
        .limit(5)
        .all()
    )

    risk_history = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.username == username)
        .order_by(RiskAssessment.timestamp.desc())
        .limit(20)
        .all()
    )

    context = RiskContext(
        username=username,
        login_history=attempts,
        login_time=datetime.utcnow(),
        ip_address=client_ip,
        user_agent=user_agent,
        country=country,
        asn=asn,
        asn_org=asn_org,
        risk_history=risk_history
    )

    engine = build_risk_engine()

    raw_score = engine.calculate(context)
    normalized_score = normalize(raw_score)

    return int(normalized_score)

@app.post("/auth/login")
def login(payload: LoginRequest,request: Request,db: Session = Depends(get_db)):

    user = (db.query(User).filter(User.username == payload.username).first())   

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    country = geo.get_country(client_ip) if client_ip else None
    asn = geo.get_asn(client_ip) if client_ip else None
    asn_org = geo.get_asn_org(client_ip) if client_ip else None

    success = False
    if user and verify_password(payload.password, user.password_hash):
        success = True

    if not success:
        attempt = LoginAttempt(
            username=payload.username,
            success=False,
            ip_address=client_ip,
            user_agent=user_agent,
            country=country,
            asn=asn,
            asn_org=asn_org
        )

        db.add(attempt)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    risk_score = calculate_risk(
    db,
    payload.username,
    client_ip,
    user_agent,
    country,
    asn,
    asn_org
    )

    attempt = LoginAttempt(
        username=payload.username,
        success=True,
        ip_address=client_ip,
        user_agent=user_agent,
        country=country,
        asn=asn,
        asn_org=asn_org
    )
    db.add(attempt)
    db.commit()


    policy = user.policy if user.policy else "STANDARD"
    decision = decide_mfa(risk_score, policy)


    assessment = RiskAssessment(
    username=payload.username,
    risk_score=risk_score,
    decision=decision
    )

    db.add(assessment)
    db.commit()

    if decision == "BLOCK":
        return {
            "status": "BLOCKED",
            "risk_score": risk_score
        }

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

@app.post("/debug/auth/trace")
def login_with_trace(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    country = geo.get_country(client_ip) if client_ip else None
    asn = geo.get_asn(client_ip) if client_ip else None
    asn_org = geo.get_asn_org(client_ip) if client_ip else None

    attempts = (
        db.query(LoginAttempt)
        .filter(LoginAttempt.username == payload.username)
        .order_by(LoginAttempt.timestamp.desc())
        .limit(5)
        .all()
    )

    risk_history = (
        db.query(RiskAssessment)
        .filter(RiskAssessment.username == payload.username)
        .order_by(RiskAssessment.timestamp.desc())
        .limit(20)
        .all()
    )

    context = RiskContext(
        username=payload.username,
        login_history=attempts,
        login_time=datetime.utcnow(),
        ip_address=client_ip,
        user_agent=user_agent,
        country=country,
        asn=asn,
        asn_org=asn_org,
        risk_history=risk_history
    )

    engine = build_risk_engine()

    policy = "STANDARD"
    raw_score, trace = engine.calculate_with_trace(context)
    score = normalize(raw_score)
    decision = decide_mfa(score, "STANDARD")

    return {
        "raw_score": raw_score,
        "policy":policy,
        "normalized_score": score,
        "decision": decision,
        "trace": trace
    }

@app.post("/debug/auth/baseline")
def baseline_login(
    payload: LoginRequest,
    db: Session = Depends(get_db)
):
    user = (
        db.query(User)
        .filter(User.username == payload.username)
        .first()
    )

    if not user or not verify_password(
        payload.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    return {
        "status": "AUTHENTICATED"
    }

@app.post("/debug/auth/adaptive")
def adaptive_login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    user = (
        db.query(User)
        .filter(User.username == payload.username)
        .first()
    )

    if not user or not verify_password(
        payload.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
    )

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    country = geo.get_country(client_ip) if client_ip else None
    asn = geo.get_asn(client_ip) if client_ip else None
    asn_org = geo.get_asn_org(client_ip) if client_ip else None

    risk_score = calculate_risk(
        db,
        payload.username,
        client_ip,
        user_agent,
        country,
        asn,
        asn_org
    )

    decision = decide_mfa(risk_score, user.policy or "STANDARD")

    return {
        "status": "AUTHENTICATED",
        "risk_score": risk_score,
        "decision": decision
    }