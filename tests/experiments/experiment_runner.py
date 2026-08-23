import time

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

from .experiment_models import (
    ExperimentResult,
    UserProfile,
    Scenario,
)
from .scenario_generator import generate_scenarios


# ============================================================
# KONFIGURACJA EKSPERYMENTU
# ============================================================

PERMISSION_LEVELS = [
    "LOW_FRICTION",
    "STANDARD",
    "STRICT",
]


# Maksymalna suma dodatnich punktów możliwych do uzyskania
# przez RiskEngine.
#
# FailedAttemptsRule       40
# LastAttemptFailedRule    30
# NewIPRule                 30
# NewUserAgentRule          20
# UnusualHourRule           15
# RapidAttemptsRule         30
# UnusualLoginPatternRule  20
# NewCountryRule            40
# RiskyASNRule              30
# ImpossibleTravelRule      50
#
# PositiveLoginHistoryRule -20
# ChronicRiskRule           30
# ConfidenceDecayRule      -15
#
# Wartość 335 jest zgodna z dotychczasowymi testami kampanii.
NORMALIZATION_MAX = 335


# ============================================================
# BUDOWANIE SILNIKA
# ============================================================

def build_engine() -> RiskEngine:
    """
    Tworzy RiskEngine wykorzystywany podczas eksperymentu.

    Kolejność reguł nie wpływa na wynik sumowania,
    ale jest utrzymywana jawnie dla czytelności i
    powtarzalności eksperymentu.
    """

    rules = [
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

    return RiskEngine(rules)


# ============================================================
# POJEDYNCZY SCENARIUSZ
# ============================================================

def run_scenario(
    engine: RiskEngine,
    scenario: Scenario,
) -> tuple[int, int, float]:
    """
    Uruchamia pojedynczy scenariusz.

    Zwraca:
        raw_score
        normalized_score
        execution_time_ms
    """

    start = time.perf_counter()

    raw_score = engine.calculate(
        scenario.context
    )

    normalized_score = normalize(
        raw_score,
    )

    end = time.perf_counter()

    execution_time_ms = (
        end - start
    ) * 1000

    return (
        raw_score,
        normalized_score,
        execution_time_ms,
    )


# ============================================================
# POJEDYNCZY PROFIL
# ============================================================

def run_profile(
    engine: RiskEngine,
    profile: UserProfile,
) -> list[ExperimentResult]:
    """
    Uruchamia wszystkie scenariusze dla jednego profilu.

    Każdy scenariusz jest wykonywany dla wszystkich poziomów
    uprawnień/polityki MFA.
    """

    results = []

    scenarios = generate_scenarios(
        profile
    )

    for scenario in scenarios:

        (
            raw_score,
            normalized_score,
            execution_time_ms,
        ) = run_scenario(
            engine,
            scenario,
        )

        for permission_level in PERMISSION_LEVELS:

            decision = decide_mfa(
                normalized_score,
                permission_level,
            )

            results.append(
                ExperimentResult(
                    username=profile.username,
                    profile_type=profile.profile_type,
                    scenario=scenario.name,
                    permission_level=permission_level,
                    expected=None,
                    score=normalized_score,
                    raw_score=raw_score,
                    decision=decision,
                    execution_time_ms=execution_time_ms,
                )
            )

    return results


# ============================================================
# CAŁY EKSPERYMENT
# ============================================================

def run_experiment(
    profiles: list[UserProfile],
) -> list[ExperimentResult]:
    """
    Uruchamia kompletny eksperyment dla przekazanej populacji
    użytkowników.

    Dla każdego profilu generowany jest pełny zestaw scenariuszy,
    a każdy scenariusz oceniany jest dla wszystkich poziomów
    polityki MFA.
    """

    engine = build_engine()

    results = []

    for profile in profiles:

        profile_results = run_profile(
            engine,
            profile,
        )

        results.extend(
            profile_results
        )

    return results