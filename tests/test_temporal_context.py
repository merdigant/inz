from datetime import datetime, timedelta
from app.risk.rules import UnusualHourRule, RapidAttemptsRule, UnusualLoginPatternRule
from tests.conftest import make_attempt, make_context


def test_unusual_hour_rule_triggers():
    context = make_context([], login_time=datetime.utcnow().replace(hour=2))
    assert UnusualHourRule().evaluate(context) == 15


def test_unusual_hour_rule_not_triggered():
    context = make_context([], login_time=datetime.utcnow().replace(hour=12))
    assert UnusualHourRule().evaluate(context) == 0


def test_rapid_attempts_rule_triggers():
    now = datetime.utcnow()
    history = [
        make_attempt(timestamp=now),
        make_attempt(timestamp=now - timedelta(seconds=20)),
        make_attempt(timestamp=now - timedelta(seconds=40)),
    ]
    context = make_context(history)
    assert RapidAttemptsRule().evaluate(context) == 30


def test_unusual_login_pattern_rule_triggers():
    history = [
        make_attempt(True, timestamp=datetime.utcnow().replace(hour=10)),
        make_attempt(True, timestamp=datetime.utcnow().replace(hour=11)),
    ]
    context = make_context(history, login_time=datetime.utcnow().replace(hour=2))
    assert UnusualLoginPatternRule().evaluate(context) == 20
