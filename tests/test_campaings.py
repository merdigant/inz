from datetime import datetime, timedelta

from app.risk.engine import RiskEngine
from app.risk.normalization import normalize
from app.risk.policies import decide_mfa
from app.risk.rules import *
from app.risk.context import RiskContext

from tests.conftest import make_attempt
from app.models import RiskAssessment

def run_scenario(login_history, **kwargs):
    engine = RiskEngine([
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
    ])

    context = RiskContext(
        username="alice",
        login_history=login_history,
        login_time=kwargs.get("login_time", datetime.utcnow()),
        ip_address=kwargs.get("ip_address"),
        user_agent=kwargs.get("user_agent"),
        country=kwargs.get("country"),
        asn=kwargs.get("asn"),
        risk_history=kwargs.get("risk_history", []),
    )

    raw = engine.calculate(context)
    score = normalize(raw, 335)

    return score

def test_scenario_baseline():
    history = [
        make_attempt(
            True,
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome"
        )
        for _ in range(20)
    ]

    score = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=datetime.utcnow().replace(hour=13),
    )

    assert score < 15
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "ALLOW"
    assert decide_mfa(score, "STRICT") == "ALLOW"

def test_scenario_bruteforce_then_success():
    now = datetime.utcnow()

    history = [
        make_attempt(False, timestamp=now - timedelta(seconds=60)),
        make_attempt(False, timestamp=now - timedelta(seconds=45)),
        make_attempt(False, timestamp=now - timedelta(seconds=30)),
        make_attempt(False, timestamp=now - timedelta(seconds=15)),
        make_attempt(False, timestamp=now),
    ]

    score = run_scenario(
        history,
        ip_address="2.2.2.2",
        country="PL",
        user_agent="UA",
        login_time=now,
    )

    assert score >= 55
    assert decide_mfa(score, "STANDARD") == "MFA_REQUIRED"
    assert decide_mfa(score, "STRICT") == "MFA_REQUIRED"


def test_scenario_account_takeover():
    history = [
        make_attempt(True, ip_address="1.1.1.1", country="PL", user_agent="UA")
        for _ in range(5)
    ]

    score = run_scenario(
        history,
        ip_address="8.8.8.8",
        country="US",
        user_agent="Firefox",
        login_time=datetime.utcnow().replace(hour=2),
        asn=15169,
    )

    assert 50 <= score <= 70
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "MFA_REQUIRED"
    assert decide_mfa(score, "STRICT") == "MFA_REQUIRED"


def test_scenario_user_travel():
    history = [
        make_attempt(True, ip_address="1.1.1.1", country="PL", user_agent="UA")
        for _ in range(15)
    ]

    score = run_scenario(
        history,
        ip_address="9.9.9.9",
        country="DE",
        user_agent="UA",
        login_time=datetime.utcnow().replace(hour=14),
    )

    assert 20 <= score <= 50
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "ALLOW"
    assert decide_mfa(score, "STRICT") == "MFA_REQUIRED"


def test_scenario_confidence_recovery():
    now = datetime.utcnow()

    history = [
        make_attempt(True, ip_address="1.1.1.1", country="PL", user_agent="UA")
        for _ in range(10)
    ]

    risk_history = [
    RiskAssessment(
        username="alice",
        risk_score=90,
        decision="MFA_REQUIRED",
        timestamp=now - timedelta(days=12),
    ),
    RiskAssessment(
        username="alice",
        risk_score=75,
        decision="MFA_REQUIRED",
        timestamp=now - timedelta(days=10),
    ),
    RiskAssessment(
        username="alice",
        risk_score=50,
        decision="ALLOW",
        timestamp=now - timedelta(days=7),
    ),
    RiskAssessment(
        username="alice",
        risk_score=25,
        decision="ALLOW",
        timestamp=now - timedelta(days=3),
    ),
]

    score = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="UA",
        login_time=now,
        risk_history=risk_history,
    )

    assert score < 40
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "ALLOW"

def test_scenario_new_device():
    history = [
        make_attempt(True, ip_address="1.1.1.1", country="PL", user_agent="Chrome")
        for _ in range(10)
    ]

    score = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Firefox",
        login_time=datetime.utcnow().replace(hour=14),
    )

    assert 5 <= score <= 35
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "ALLOW"
    assert decide_mfa(score, "STRICT") == "ALLOW"

def test_campaign_new_ip():
    history = [
        make_attempt(True, ip_address="1.1.1.1", country="PL", user_agent="Chrome")
        for _ in range(10)
    ]

    score = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Chrome",
        login_time=datetime.utcnow().replace(hour=14),
    )

    assert 10 <= score <= 35
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "ALLOW"
    assert decide_mfa(score, "STRICT") == "ALLOW"   

def test_scenario_unusual_hour():
    history = [
        make_attempt(True, ip_address="1.1.1.1", country="PL", user_agent="Chrome")
        for _ in range(10)
    ]

    score = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=datetime.utcnow().replace(hour=3),
    )

    assert 10 <= score <= 40
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "ALLOW"
    assert decide_mfa(score, "STRICT") == "ALLOW"

def test_scenario_multiple_anomalies():
    history = [
        make_attempt(True, ip_address="1.1.1.1", country="PL", user_agent="Chrome")
        for _ in range(10)
    ]

    score = run_scenario(
        history,
        ip_address="8.8.8.8",
        country="US",
        user_agent="Firefox",
        login_time=datetime.utcnow().replace(hour=2),
        asn=15169,
    )

    assert score >= 50
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "ALLOW"
    assert decide_mfa(score, "STRICT") == "MFA_REQUIRED"

def test_scenario_positive_login_history():
    history = [
        make_attempt(
            True,
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome"
        )
        for _ in range(20)
    ]

    score = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Chrome",
        login_time=datetime.utcnow().replace(hour=14),
    )

    assert score < 30
    assert decide_mfa(score, "LOW_FRICTION") == "ALLOW"
    assert decide_mfa(score, "STANDARD") == "ALLOW"
    assert decide_mfa(score, "STRICT") == "ALLOW"

def test_scenario_progressive_risk():

    history = [
        make_attempt(
            True,
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome"
        )
        for _ in range(15)
    ]

    baseline = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=datetime.utcnow().replace(hour=13),
    )

    new_ip = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Chrome",
        login_time=datetime.utcnow().replace(hour=13),
    )

    new_device = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Firefox",
        login_time=datetime.utcnow().replace(hour=13),
    )

    new_country = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="US",
        user_agent="Firefox",
        login_time=datetime.utcnow().replace(hour=13),
    )

    night = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="US",
        user_agent="Firefox",
        login_time=datetime.utcnow().replace(hour=2),
    )

    assert baseline < new_ip
    assert new_ip <= new_device
    assert new_device <= new_country
    assert new_country <= night