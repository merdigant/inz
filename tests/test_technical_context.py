from app.risk.rules import NewIPRule, NewUserAgentRule
from tests.conftest import make_attempt, make_context


def test_new_ip_rule_triggers():
    history = [make_attempt(ip_address="1.1.1.1")]
    context = make_context(history, ip_address="2.2.2.2")
    assert NewIPRule().evaluate(context) == 30


def test_new_ip_rule_not_triggered():
    history = [make_attempt(ip_address="1.1.1.1")]
    context = make_context(history, ip_address="1.1.1.1")
    assert NewIPRule().evaluate(context) == 0


def test_new_user_agent_rule_triggers():
    history = [make_attempt(user_agent="UA1")]
    context = make_context(history, user_agent="UA2")
    assert NewUserAgentRule().evaluate(context) == 20


def test_new_user_agent_rule_not_triggered():
    history = [make_attempt(user_agent="UA1")]
    context = make_context(history, user_agent="UA1")
    assert NewUserAgentRule().evaluate(context) == 0
