from datetime import datetime, timedelta

from app.models import RiskAssessment
from app.risk.context import RiskContext
from app.risk.engine import RiskEngine
from app.risk.normalization import normalize
from app.risk.policies import decide_mfa
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

from tests.conftest import make_attempt

def build_engine():
    return RiskEngine([
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


def run_scenario(login_history, **kwargs):
    engine = build_engine()

    context = RiskContext(
        username="alice",
        login_history=login_history,
        login_time=kwargs.get(
            "login_time",
            datetime.utcnow()
        ),
        ip_address=kwargs.get("ip_address"),
        user_agent=kwargs.get("user_agent"),
        country=kwargs.get("country"),
        asn=kwargs.get("asn"),
        asn_org=kwargs.get("asn_org"),
        risk_history=kwargs.get("risk_history", []),
    )

    raw_score, trace = engine.calculate_with_trace(context)
    score = normalize(raw_score)

    return score, trace


def print_result(title, score, trace):
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)

    print(f"Score: {score}")

    print()
    print("TRACE — AKTYWNE REGUŁY")

    if trace:
        for item in trace:
            print(
                f"  {item['rule']:<30}"
                f"{item['score']:+}"
            )
    else:
        print("  brak aktywnych reguł")

    print()

    for policy in [
        "LOW_FRICTION",
        "STANDARD",
        "STRICT",
    ]:
        decision = decide_mfa(
            score,
            policy
        )

        print(
            f"{policy:<13}: {decision}"
        )


def test_experiment_baseline(): 

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    score, trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 1: NORMALNE LOGOWANIE",
        score,
        trace,
    )

    assert score == 0

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "ALLOW"


def test_experiment_new_ip():

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    score, trace = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 2: NOWY ADRES IP",
        score,
        trace,
    )

    assert score == 30

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "MFA_REQUIRED"

def test_experiment_new_device():

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    score, trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Firefox",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 3: NOWE URZĄDZENIE",
        score,
        trace,
    )

    assert score == 20

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "ALLOW"

def test_experiment_new_country():

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    score, trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="DE",
        user_agent="Chrome",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 4: LOGOWANIE Z NOWEGO KRAJU",
        score,
        trace,
    )

    assert score == 40

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "MFA_REQUIRED"

def test_experiment_unusual_hour():

    login_time = datetime.utcnow().replace(
        hour=3,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    score, trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 5: NIETYPOWA GODZINA LOGOWANIA",
        score,
        trace,
    )

    assert score == 15

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "ALLOW"

def test_experiment_unusual_login_pattern():

    login_time = datetime.utcnow().replace(
        hour=20,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        ),
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=2),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        ),
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=3),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        ),
    ]

    for attempt in history:
        attempt.timestamp = attempt.timestamp.replace(
            hour=10,
            minute=0,
            second=0,
            microsecond=0,
        )

    score, trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 6: NIETYPOWY WZORZEC LOGOWANIA",
        score,
        trace,
    )

    assert score == 20

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "ALLOW"

def test_experiment_risky_asn():

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    score, trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        asn=1234,
        asn_org="Some Cloud Provider",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 7: RYZYKOWNY ASN",
        score,
        trace,
    )

    assert score == 30

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "ALLOW"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "MFA_REQUIRED"

def test_experiment_brute_force():

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            False,
            timestamp=login_time - timedelta(seconds=60),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        ),
        make_attempt(
            False,
            timestamp=login_time - timedelta(seconds=45),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        ),
        make_attempt(
            False,
            timestamp=login_time - timedelta(seconds=30),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        ),
        make_attempt(
            False,
            timestamp=login_time - timedelta(seconds=15),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        ),
        make_attempt(
            False,
            timestamp=login_time,
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        ),
    ]

    score, trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 8: ATAK BRUTE FORCE",
        score,
        trace,
    )

    assert score == 100

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "BLOCK"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "BLOCK"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "BLOCK"

def test_experiment_impossible_travel():

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(minutes=30),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    score, trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="DE",
        user_agent="Chrome",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 9: NIEMOŻLIWA PODRÓŻ",
        score,
        trace,
    )

    assert score == 90

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "BLOCK"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "BLOCK"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "BLOCK"


def test_experiment_account_takeover():

    login_time = datetime.utcnow().replace(
        hour=2,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(minutes=30),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    score, trace = run_scenario(
        history,
        ip_address="8.8.8.8",
        country="US",
        user_agent="Firefox",
        asn=15169,
        asn_org="Google Cloud",
        login_time=login_time,
    )

    print_result(
        "EKSPERYMENT 10: POTENCJALNE PRZEJĘCIE KONTA",
        score,
        trace,
    )

    assert score == 100

    assert decide_mfa(
        score,
        "LOW_FRICTION"
    ) == "BLOCK"

    assert decide_mfa(
        score,
        "STANDARD"
    ) == "BLOCK"

    assert decide_mfa(
        score,
        "STRICT"
    ) == "BLOCK"

def test_experiment_positive_login_history():

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    positive_history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=i),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
        for i in range(1, 11)
    ]

    negative_history = [
        make_attempt(
            False,
            timestamp=login_time - timedelta(seconds=60 + i * 10),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
        for i in range(5)
    ]

    positive_score, positive_trace = run_scenario(
        positive_history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
    )

    negative_score, negative_trace = run_scenario(
        negative_history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
    )

    print()
    print("=" * 60)
    print(
        "EKSPERYMENT 11: "
        "WPŁYW POZYTYWNEJ HISTORII LOGOWAŃ"
    )
    print("=" * 60)

    print()
    print(f"Pozytywna historia: {positive_score}")
    print("  Aktywne reguły:")

    for item in positive_trace:
        print(
            f"    {item['rule']:<28}"
            f"{item['score']:+}"
        )

    print()
    print(f"Negatywna historia: {negative_score}")
    print("  Aktywne reguły:")

    for item in negative_trace:
        print(
            f"    {item['rule']:<28}"
            f"{item['score']:+}"
        )

    assert positive_score < negative_score

    assert (
        positive_score
        <= negative_score
    )

def test_experiment_chronic_risk_and_confidence_recovery():

    login_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=login_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    current_risk_history = [
        RiskAssessment(
            username="alice",
            risk_score=80,
            decision="MFA_REQUIRED",
            timestamp=login_time - timedelta(days=2),
        ),
        RiskAssessment(
            username="alice",
            risk_score=70,
            decision="MFA_REQUIRED",
            timestamp=login_time - timedelta(days=3),
        ),
        RiskAssessment(
            username="alice",
            risk_score=60,
            decision="MFA_REQUIRED",
            timestamp=login_time - timedelta(days=4),
        ),
    ]

    old_risk_history = [
        RiskAssessment(
            username="alice",
            risk_score=80,
            decision="MFA_REQUIRED",
            timestamp=login_time - timedelta(days=10),
        ),
        RiskAssessment(
            username="alice",
            risk_score=70,
            decision="MFA_REQUIRED",
            timestamp=login_time - timedelta(days=11),
        ),
        RiskAssessment(
            username="alice",
            risk_score=60,
            decision="MFA_REQUIRED",
            timestamp=login_time - timedelta(days=12),
        ),
    ]

    current_score, current_trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
        risk_history=current_risk_history,
    )

    old_score, old_trace = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=login_time,
        risk_history=old_risk_history,
    )

    print()
    print("=" * 60)
    print(
        "EKSPERYMENT 12: "
        "UTRWALONE RYZYKO I ODBUDOWA ZAUFANIA"
    )
    print("=" * 60)

    print()
    print(f"Aktualne ryzyko: {current_score}")
    print("  Aktywne reguły:")

    for item in current_trace:
        print(
            f"    {item['rule']:<28}"
            f"{item['score']:+}"
        )

    print()
    print(f"Stare ryzyko:    {old_score}")
    print("  Aktywne reguły:")

    for item in old_trace:
        print(
            f"    {item['rule']:<28}"
            f"{item['score']:+}"
        )

    # ChronicRisk pozostaje aktywne,
    # ale ConfidenceDecay zmniejsza wynik.
    assert old_score < current_score

    assert current_score == 30
    assert old_score == 15

def test_experiment_progressive_risk():

    base_time = datetime.utcnow().replace(
        hour=13,
        minute=0,
        second=0,
        microsecond=0,
    )

    history = [
        make_attempt(
            True,
            timestamp=base_time - timedelta(days=1),
            ip_address="1.1.1.1",
            country="PL",
            user_agent="Chrome",
        )
    ]

    baseline, _ = run_scenario(
        history,
        ip_address="1.1.1.1",
        country="PL",
        user_agent="Chrome",
        login_time=base_time,
    )

    new_ip, _ = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Chrome",
        login_time=base_time,
    )

    new_device, _ = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="PL",
        user_agent="Firefox",
        login_time=base_time,
    )

    new_country, _ = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="DE",
        user_agent="Firefox",
        login_time=base_time,
    )

    night, _ = run_scenario(
        history,
        ip_address="5.5.5.5",
        country="DE",
        user_agent="Firefox",
        login_time=base_time.replace(hour=3),
    )

    print()
    print("=" * 60)
    print(
        "EKSPERYMENT 13: "
        "PROGRESYWNE NARASTANIE RYZYKA"
    )
    print("=" * 60)

    print(f"Baseline      : {baseline}")
    print(f"New IP        : {new_ip}")
    print(f"New Device    : {new_device}")
    print(f"New Country   : {new_country}")
    print(f"Unusual Hour  : {night}")

    assert baseline < new_ip
    assert new_ip < new_device
    assert new_device < new_country
    assert new_country < night