from datetime import datetime, timedelta
from app.risk.rules import NewCountryRule, RiskyASNRule, ImpossibleTravelRule
from tests.conftest import make_attempt, make_context


def test_new_country_rule_triggers():
    history = [make_attempt(country="PL")]
    context = make_context(history, country="DE")
    assert NewCountryRule().evaluate(context) == 40


def test_risky_asn_rule_triggers():
    history = [
        make_attempt(
            asn_org="Some Cloud Provider"
        )
    ]

    context = make_context(
        history,
        asn=1234,
        asn_org="Some Cloud Provider",
    )

    assert RiskyASNRule().evaluate(context) == 30


def test_impossible_travel_rule_triggers():
    now = datetime.utcnow()
    history = [
        make_attempt(country="PL", timestamp=now - timedelta(minutes=30))
    ]
    context = make_context(history, country="US", login_time=now)
    assert ImpossibleTravelRule().evaluate(context) == 50
