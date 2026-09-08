from collections import Counter, defaultdict
from statistics import mean, median


SCENARIO_ORDER = [
    "NORMAL",
    "NEW_IP",
    "NEW_DEVICE",
    "NEW_COUNTRY",
    "UNUSUAL_HOUR",
    "RISKY_ASN",
    "IMPOSSIBLE_TRAVEL",
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


def _scores(results):
    return [result.score for result in results]


def _decision_counts(results):
    return dict(
        Counter(result.decision for result in results)
    )


def _percentile(values, percentile):

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

def summarize_results(results):
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

def analyze_scenarios(results):


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


def analyze_policies(results):

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

def analyze_profiles(results):

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

def analyze_scenario_policy(results):

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

def analyze_false_positives(results):

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

def analyze_false_negatives(results):

    high_risk_scenarios = {
        "BRUTE_FORCE",
        "ACCOUNT_TAKEOVER",
        "IMPOSSIBLE_TRAVEL"
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

def analyze_scenario_detection(results):

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


def analyze_execution_time(results):

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


def analyze_results(results):

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

def _format_number(value, digits=2):
    if value is None:
        return "-"

    return f"{value:.{digits}f}"


def print_analysis(data):

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