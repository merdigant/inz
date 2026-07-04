from app.risk.rules import FailedAttemptsRule, LastAttemptFailedRule
from tests.conftest import make_attempt, make_context


def test_failed_attempts_rule_triggers():
    history = [make_attempt(False) for _ in range(3)]
    context = make_context(history)
    assert FailedAttemptsRule().evaluate(context) == 40


def test_failed_attempts_rule_not_triggered():
    history = [make_attempt(True), make_attempt(False)]
    context = make_context(history)
    assert FailedAttemptsRule().evaluate(context) == 0


def test_last_attempt_failed_rule_triggers():
    history = [make_attempt(False)]
    context = make_context(history)
    assert LastAttemptFailedRule().evaluate(context) == 30


def test_last_attempt_failed_rule_not_triggered():
    history = [make_attempt(True)]
    context = make_context(history)
    assert LastAttemptFailedRule().evaluate(context) == 0
