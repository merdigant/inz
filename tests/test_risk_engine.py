from app.risk.engine import RiskEngine
from app.risk.rules import FailedAttemptsRule, NewIPRule
from tests.conftest import make_attempt, make_context


def test_risk_engine_aggregates_rules():
    history = [
        make_attempt(False),
        make_attempt(False),
        make_attempt(False),
    ]
    context = make_context(history, ip_address="2.2.2.2")
    engine = RiskEngine([FailedAttemptsRule(), NewIPRule()])
    assert engine.calculate(context) == 70
