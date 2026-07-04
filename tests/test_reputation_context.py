from datetime import datetime, timedelta
from app.risk.rules import (
    PositiveLoginHistoryRule,
    ChronicRiskRule,
    ConfidenceDecayRule,
)
from tests.conftest import make_attempt, make_context
from app.models import RiskAssessment


def make_assessment(decision, days_ago=0):
    return RiskAssessment(
        username="alice",
        risk_score=80,
        decision=decision,
        timestamp=datetime.utcnow() - timedelta(days=days_ago)
    )


def test_positive_login_history_rule():
    history = [make_attempt(True) for _ in range(10)]
    context = make_context(history, risk_history=[])
    assert PositiveLoginHistoryRule().evaluate(context) == -20


def test_chronic_risk_rule():
    risks = [
        make_assessment("MFA_REQUIRED"),
        make_assessment("MFA_REQUIRED"),
        make_assessment("MFA_REQUIRED"),
    ]
    context = make_context([], risk_history=risks)
    assert ChronicRiskRule().evaluate(context) == 30


def test_confidence_decay_rule():
    risks = [make_assessment("ALLOW", days_ago=10)]
    context = make_context([], risk_history=risks)
    assert ConfidenceDecayRule().evaluate(context) == -15
