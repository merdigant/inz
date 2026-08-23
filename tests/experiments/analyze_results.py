from collections import Counter, defaultdict
from statistics import mean, median


# ============================================================
# KONFIGURACJA
# ============================================================

SCENARIO_ORDER = [
    "NORMAL",
    "NEW_IP",
    "NEW_DEVICE",
    "NEW_COUNTRY",
    "UNUSUAL_HOUR",
    "RISKY_ASN",
    "IMPOSSIBLE_TRAVEL",
    "MULTI_ANOMALY",
    "BRUTE_FORCE",
    "ACCOUNT_TAKEOVER",
    "CHRONIC_RISK",
    "CONFIDENCE_DECAY",
]

POLICY_ORDER = [
    "LOW_FRICTION",
    "STANDARD",
    "STRICT",
]

PROFILE_ORDER = [
    "STANDARD",
    "REMOTE",
    "TRAVELER",
]


# ============================================================
# POMOCNICZE
# ============================================================

def _scores(results):
    return [result.score for result in results]


def _decision_counts(results):
    return dict(
        Counter(result.decision for result in results)
    )


def _percentile(values, percentile):
    """
    Oblicza percentyl bez dodatkowych zależności.

    percentile:
        wartość od 0 do 100.
    """

    if not values:
        return None

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    position = (len(values) - 1) * percentile / 100
    lower = int(position)
    upper = lower + 1

    if upper >= len(values):
        return values[lower]

    weight = position - lower

    return (
        values[lower]
        + (values[upper] - values[lower]) * weight
    )


def _score_statistics(results):
    """
    Zwraca podstawowe statystyki score.
    """

    scores = _scores(results)

    if not scores:
        return {
            "count": 0,
            "min": None,
            "q1": None,
            "median": None,
            "mean": None,
            "q3": None,
            "max": None,
        }

    return {
        "count": len(scores),
        "min": min(scores),
        "q1": _percentile(scores, 25),
        "median": median(scores),
        "mean": mean(scores),
        "q3": _percentile(scores, 75),
        "max": max(scores),
    }


# ============================================================
# PODSTAWOWE PODSUMOWANIE
# ============================================================

def summarize_results(results):
    """
    Zwraca podstawowe informacje o eksperymencie.
    """

    usernames = {
        result.username
        for result in results
    }

    scenarios = {
        result.scenario
        for result in results
    }

    policies = {
        result.permission_level
        for result in results
    }

    profiles = {
        result.profile_type
        for result in results
    }

    return {
        "results": len(results),
        "profiles": len(usernames),
        "scenarios": len(scenarios),
        "policies": len(policies),
        "profile_types": len(profiles),
    }


# ============================================================
# ANALIZA SCENARIUSZY
# ============================================================

def analyze_scenarios(results):
    """
    Analizuje rozkład score dla każdego scenariusza.
    """

    grouped = defaultdict(list)

    for result in results:
        grouped[result.scenario].append(result)

    analysis = {}

    for scenario in SCENARIO_ORDER:

        scenario_results = grouped.get(
            scenario,
            []
        )

        if not scenario_results:
            continue

        analysis[scenario] = _score_statistics(
            scenario_results
        )

    return analysis


# ============================================================
# ANALIZA POLITYK
# ============================================================

def analyze_policies(results):
    """
    Analizuje działanie poszczególnych polityk MFA.
    """

    grouped = defaultdict(list)

    for result in results:
        grouped[result.permission_level].append(
            result
        )

    analysis = {}

    for policy in POLICY_ORDER:

        policy_results = grouped.get(
            policy,
            []
        )

        if not policy_results:
            continue

        stats = _score_statistics(
            policy_results
        )

        stats["decisions"] = _decision_counts(
            policy_results
        )

        analysis[policy] = stats

    return analysis


# ============================================================
# ANALIZA PROFILI
# ============================================================

def analyze_profiles(results):
    """
    Analizuje wpływ typu profilu użytkownika
    na wynik eksperymentu.
    """

    grouped = defaultdict(list)

    for result in results:
        grouped[result.profile_type].append(
            result
        )

    analysis = {}

    for profile_type in PROFILE_ORDER:

        profile_results = grouped.get(
            profile_type,
            []
        )

        if not profile_results:
            continue

        stats = _score_statistics(
            profile_results
        )

        stats["decisions"] = _decision_counts(
            profile_results
        )

        analysis[profile_type] = stats

    return analysis


# ============================================================
# MACIERZ SCENARIUSZ × POLITYKA
# ============================================================

def analyze_scenario_policy(results):
    """
    Tworzy analizę wyników w podziale:

        scenariusz × polityka

    Dzięki temu można sprawdzić, jak każda polityka
    reaguje na każdy scenariusz.
    """

    grouped = defaultdict(list)

    for result in results:
        key = (
            result.scenario,
            result.permission_level,
        )

        grouped[key].append(result)

    analysis = {}

    for scenario in SCENARIO_ORDER:

        scenario_data = {}

        for policy in POLICY_ORDER:

            key = (
                scenario,
                policy,
            )

            scenario_results = grouped.get(
                key,
                []
            )

            if not scenario_results:
                continue

            scores = _scores(
                scenario_results
            )

            scenario_data[policy] = {
                "mean_score": mean(scores),
                "median_score": median(scores),
                "decisions": _decision_counts(
                    scenario_results
                ),
            }

        if scenario_data:
            analysis[scenario] = scenario_data

    return analysis


# ============================================================
# ANALIZA FALSE POSITIVE
# ============================================================

def analyze_false_positives(results):
    """
    Analizuje potencjalne false positive.

    Za normalne zachowanie uznajemy scenariusz NORMAL.

    False positive:
        NORMAL -> MFA_REQUIRED
        NORMAL -> BLOCK
    """

    normal_results = [
        result
        for result in results
        if result.scenario == "NORMAL"
    ]

    false_positives = [
        result
        for result in normal_results
        if result.decision != "ALLOW"
    ]

    total = len(normal_results)

    rate = (
        len(false_positives) / total * 100
        if total
        else 0
    )

    by_policy = Counter(
        result.permission_level
        for result in false_positives
    )

    by_decision = Counter(
        result.decision
        for result in false_positives
    )

    return {
        "total_normal": total,
        "false_positives": len(false_positives),
        "rate_percent": rate,
        "by_policy": dict(by_policy),
        "by_decision": dict(by_decision),
    }


# ============================================================
# ANALIZA FALSE NEGATIVE
# ============================================================

def analyze_false_negatives(results):
    """
    Analizuje potencjalne false negative.

    Scenariusze uznane za wysokiego ryzyka:

        BRUTE_FORCE
        ACCOUNT_TAKEOVER
        IMPOSSIBLE_TRAVEL
        MULTI_ANOMALY

    False negative:
        scenariusz wysokiego ryzyka -> ALLOW
    """

    high_risk_scenarios = {
        "BRUTE_FORCE",
        "ACCOUNT_TAKEOVER",
        "IMPOSSIBLE_TRAVEL",
        "MULTI_ANOMALY",
    }

    high_risk_results = [
        result
        for result in results
        if result.scenario in high_risk_scenarios
    ]

    false_negatives = [
        result
        for result in high_risk_results
        if result.decision == "ALLOW"
    ]

    total = len(high_risk_results)

    rate = (
        len(false_negatives) / total * 100
        if total
        else 0
    )

    by_scenario = Counter(
        result.scenario
        for result in false_negatives
    )

    by_policy = Counter(
        result.permission_level
        for result in false_negatives
    )

    return {
        "total_high_risk": total,
        "false_negatives": len(false_negatives),
        "rate_percent": rate,
        "by_scenario": dict(by_scenario),
        "by_policy": dict(by_policy),
    }


# ============================================================
# SKUTECZNOŚĆ SCENARIUSZY
# ============================================================

def analyze_scenario_detection(results):
    """
    Określa, jak często poszczególne scenariusze
    powodują reakcję systemu.

    Reakcja:
        ALLOW
        MFA_REQUIRED
        BLOCK
    """

    grouped = defaultdict(list)

    for result in results:
        grouped[result.scenario].append(
            result
        )

    analysis = {}

    for scenario in SCENARIO_ORDER:

        scenario_results = grouped.get(
            scenario,
            []
        )

        if not scenario_results:
            continue

        decisions = Counter(
            result.decision
            for result in scenario_results
        )

        total = len(scenario_results)

        analysis[scenario] = {
            "allow_percent": (
                decisions["ALLOW"] / total * 100
            ),
            "mfa_percent": (
                decisions["MFA_REQUIRED"] / total * 100
            ),
            "block_percent": (
                decisions["BLOCK"] / total * 100
            ),
        }

    return analysis


# ============================================================
# ANALIZA CZASU
# ============================================================

def analyze_execution_time(results):
    """
    Analizuje czas wykonywania RiskEngine.
    """

    times = [
        result.execution_time_ms
        for result in results
        if result.execution_time_ms is not None
    ]

    if not times:
        return {
            "count": 0,
            "mean_ms": None,
            "median_ms": None,
            "min_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "max_ms": None,
        }

    return {
        "count": len(times),
        "mean_ms": mean(times),
        "median_ms": median(times),
        "min_ms": min(times),
        "p95_ms": _percentile(times, 95),
        "p99_ms": _percentile(times, 99),
        "max_ms": max(times),
    }


# ============================================================
# PEŁNA ANALIZA
# ============================================================

def analyze_results(results):
    """
    Wykonuje kompletną analizę wyników eksperymentu.
    """

    return {
        "summary": summarize_results(results),
        "scenarios": analyze_scenarios(results),
        "policies": analyze_policies(results),
        "profiles": analyze_profiles(results),
        "scenario_policy": analyze_scenario_policy(
            results
        ),
        "scenario_detection": analyze_scenario_detection(
            results
        ),
        "false_positives": analyze_false_positives(
            results
        ),
        "false_negatives": analyze_false_negatives(
            results
        ),
        "execution_time": analyze_execution_time(
            results
        ),
    }


# ============================================================
# FORMATOWANIE WYNIKÓW
# ============================================================

def _format_number(value, digits=2):
    if value is None:
        return "-"

    return f"{value:.{digits}f}"


def print_analysis(data):
    """
    Wyświetla pełną analizę eksperymentu.

    Funkcja może otrzymać:
    - listę ExperimentResult,
    - albo gotowy słownik zwrócony przez analyze_results().
    """

    if isinstance(data, dict):
        analysis = data
    else:
        analysis = analyze_results(data)

    summary = analysis["summary"]

    print()
    print("=" * 70)
    print("PODSUMOWANIE EKSPERYMENTU")
    print("=" * 70)

    print(f"Liczba wyników:   {summary['results']}")
    print(f"Liczba profili:   {summary['profiles']}")
    print(f"Liczba scenariuszy: {summary['scenarios']}")
    print(f"Liczba polityk:    {summary['policies']}")

    # --------------------------------------------------------
    # SCENARIUSZE
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("SCENARIUSZE — ROZKŁAD SCORE")
    print("=" * 70)

    print(
        f"{'SCENARIUSZ':<22}"
        f"{'MIN':>7}"
        f"{'Q1':>7}"
        f"{'MED':>7}"
        f"{'ŚR.':>7}"
        f"{'Q3':>7}"
        f"{'MAX':>7}"
    )

    for scenario, stats in analysis["scenarios"].items():

        print(
            f"{scenario:<22}"
            f"{stats['min']:>7.0f}"
            f"{stats['q1']:>7.1f}"
            f"{stats['median']:>7.1f}"
            f"{stats['mean']:>7.1f}"
            f"{stats['q3']:>7.1f}"
            f"{stats['max']:>7.0f}"
        )

    # --------------------------------------------------------
    # POLITYKI
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("POLITYKI")
    print("=" * 70)

    for policy, stats in analysis["policies"].items():

        print()
        print(policy)

        print(
            f"  średni score: "
            f"{_format_number(stats['mean'])}"
        )

        print(
            f"  mediana:      "
            f"{_format_number(stats['median'])}"
        )

        print(
            f"  decyzje:      "
            f"{stats['decisions']}"
        )

    # --------------------------------------------------------
    # PROFILE
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("PROFILE UŻYTKOWNIKÓW")
    print("=" * 70)

    for profile_type, stats in analysis["profiles"].items():

        print()
        print(profile_type)

        print(
            f"  średni score: "
            f"{_format_number(stats['mean'])}"
        )

        print(
            f"  mediana:      "
            f"{_format_number(stats['median'])}"
        )

        print(
            f"  decyzje:      "
            f"{stats['decisions']}"
        )

    # --------------------------------------------------------
    # SCENARIUSZ × POLITYKA
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("SCENARIUSZ × POLITYKA")
    print("=" * 70)

    for scenario, policies in analysis[
        "scenario_policy"
    ].items():

        print()
        print(scenario)

        for policy, data in policies.items():

            print(
                f"  {policy:<14}"
                f" score={data['mean_score']:.1f}"
                f" | decyzje={data['decisions']}"
            )

    # --------------------------------------------------------
    # DETEKCJA SCENARIUSZY
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("REAKCJA SYSTEMU NA SCENARIUSZE")
    print("=" * 70)

    print(
        f"{'SCENARIUSZ':<22}"
        f"{'ALLOW':>10}"
        f"{'MFA':>10}"
        f"{'BLOCK':>10}"
    )

    for scenario, data in analysis[
        "scenario_detection"
    ].items():

        print(
            f"{scenario:<22}"
            f"{data['allow_percent']:>9.1f}%"
            f"{data['mfa_percent']:>9.1f}%"
            f"{data['block_percent']:>9.1f}%"
        )

    # --------------------------------------------------------
    # FALSE POSITIVE
    # --------------------------------------------------------

    fp = analysis["false_positives"]

    print()
    print("=" * 70)
    print("FALSE POSITIVE")
    print("=" * 70)

    print(
        f"Normalne logowania: "
        f"{fp['total_normal']}"
    )

    print(
        f"False positive:     "
        f"{fp['false_positives']}"
    )

    print(
        f"FP rate:            "
        f"{fp['rate_percent']:.2f}%"
    )

    print(
        f"Według polityki:    "
        f"{fp['by_policy']}"
    )

    # --------------------------------------------------------
    # FALSE NEGATIVE
    # --------------------------------------------------------

    fn = analysis["false_negatives"]

    print()
    print("=" * 70)
    print("FALSE NEGATIVE")
    print("=" * 70)

    print(
        f"Logowania wysokiego ryzyka: "
        f"{fn['total_high_risk']}"
    )

    print(
        f"False negative:             "
        f"{fn['false_negatives']}"
    )

    print(
        f"FN rate:                    "
        f"{fn['rate_percent']:.2f}%"
    )

    print(
        f"Według scenariusza:         "
        f"{fn['by_scenario']}"
    )

    print(
        f"Według polityki:            "
        f"{fn['by_policy']}"
    )

    # --------------------------------------------------------
    # CZAS
    # --------------------------------------------------------

    execution = analysis["execution_time"]

    print()
    print("=" * 70)
    print("CZAS WYKONANIA")
    print("=" * 70)

    print(
        f"Średni:   "
        f"{_format_number(execution['mean_ms'], 4)} ms"
    )

    print(
        f"Mediana:  "
        f"{_format_number(execution['median_ms'], 4)} ms"
    )

    print(
        f"Min:      "
        f"{_format_number(execution['min_ms'], 4)} ms"
    )

    print(
        f"P95:      "
        f"{_format_number(execution['p95_ms'], 4)} ms"
    )

    print(
        f"P99:      "
        f"{_format_number(execution['p99_ms'], 4)} ms"
    )

    print(
        f"Max:      "
        f"{_format_number(execution['max_ms'], 4)} ms"
    )

    print()


# ============================================================
# GŁÓWNE API MODUŁU
# ============================================================

__all__ = [
    "analyze_results",
    "analyze_scenarios",
    "analyze_policies",
    "analyze_profiles",
    "analyze_scenario_policy",
    "analyze_scenario_detection",
    "analyze_false_positives",
    "analyze_false_negatives",
    "analyze_execution_time",
    "summarize_results",
    "print_analysis",
]