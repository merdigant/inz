from datetime import datetime, timedelta
from app.models import LoginAttempt
from app.risk.context import RiskContext


def make_attempt(success=True, **kwargs):
    return LoginAttempt(
        username="alice",
        success=success,
        timestamp=kwargs.get("timestamp", datetime.utcnow()),
        ip_address=kwargs.get("ip_address"),
        user_agent=kwargs.get("user_agent"),
        country=kwargs.get("country"),
        asn=kwargs.get("asn"),
        asn_org=kwargs.get("asn_org"),
    )


def make_context(history, **kwargs):
    return RiskContext(
        username="alice",
        login_history=history,
        login_time=kwargs.get("login_time", datetime.utcnow()),
        ip_address=kwargs.get("ip_address"),
        user_agent=kwargs.get("user_agent"),
        country=kwargs.get("country"),
        asn=kwargs.get("asn"),
        asn_org=kwargs.get("asn_org"),
        risk_history=kwargs.get("risk_history", []),
    )
