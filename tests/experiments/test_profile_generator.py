from .profile_generator import generate_profiles
from .scenario_generator import generate_scenarios
from .experiment_runner import (
    run_experiment,
    PERMISSION_LEVELS,
)


SCENARIO_NAMES = {
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
}


def test_full_experiment_pipeline():
    """
    Testuje cały przepływ eksperymentu:

        profile_generator
                ↓
        history_generator
                ↓
        scenario_generator
                ↓
        experiment_runner
                ↓
        ExperimentResult
    """

    profiles = generate_profiles(
    count=1400,
    history_count=50,
    seed=1234,
)

    assert len(profiles) == 1400

    for profile in profiles:
        assert profile.username
        assert profile.profile_type in {
            "STANDARD",
            "REMOTE",
            "TRAVELER",
        }

        assert profile.home_ip
        assert profile.home_country
        assert profile.home_user_agent
        assert profile.home_asn is not None

        assert len(profile.history) == 50

    results = run_experiment(profiles)

    # 1400 profili × 12 scenariuszy × 3 polityki
    assert len(results) == 1400 * 12 * 3

    for result in results:

        assert result.username
        assert result.profile_type in {
            "STANDARD",
            "REMOTE",
            "TRAVELER",
        }

        assert result.scenario in SCENARIO_NAMES

        assert result.permission_level in PERMISSION_LEVELS

        assert result.raw_score is not None
        assert result.score is not None

        assert result.decision in {
            "ALLOW",
            "MFA_REQUIRED",
            "BLOCK",
        }

        assert result.execution_time_ms >= 0


def test_every_profile_has_all_scenarios_and_policies():
    """
    Sprawdza, czy każdy profil został przetestowany
    dla każdego scenariusza i każdej polityki MFA.
    """

    profiles = generate_profiles(
        count=5,
        history_count=20,
        seed=1234,
    )

    results = run_experiment(profiles)

    for profile in profiles:

        profile_results = [
            result
            for result in results
            if result.username == profile.username
        ]

        # 12 scenariuszy × 3 polityki
        assert len(profile_results) == 36

        scenarios = {
            result.scenario
            for result in profile_results
        }

        assert scenarios == SCENARIO_NAMES

        policies = {
            result.permission_level
            for result in profile_results
        }

        assert policies == set(PERMISSION_LEVELS)


def test_every_scenario_is_run_for_every_policy():
    """
    Dla każdego scenariusza sprawdza obecność wszystkich
    trzech poziomów polityki MFA.
    """

    profiles = generate_profiles(
        count=3,
        history_count=20,
        seed=1234,
    )

    results = run_experiment(profiles)

    for profile in profiles:

        for scenario_name in SCENARIO_NAMES:

            scenario_results = [
                result
                for result in results
                if result.username == profile.username
                and result.scenario == scenario_name
            ]

            assert len(scenario_results) == 3

            policies = {
                result.permission_level
                for result in scenario_results
            }

            assert policies == set(PERMISSION_LEVELS)


def test_decision_matches_mfa_policy():
    """
    Sprawdza, czy decyzja zapisana przez runner odpowiada
    progom z policies.py.
    """

    profiles = generate_profiles(
        count=5,
        history_count=20,
        seed=1234,
    )

    results = run_experiment(profiles)

    for result in results:

        if result.permission_level == "LOW_FRICTION":
            if result.score >= 90:
                expected = "BLOCK"
            elif result.score >= 70:
                expected = "MFA_REQUIRED"
            else:
                expected = "ALLOW"

        elif result.permission_level == "STANDARD":
            if result.score >= 80:
                expected = "BLOCK"
            elif result.score >= 60:
                expected = "MFA_REQUIRED"
            else:
                expected = "ALLOW"

        elif result.permission_level == "STRICT":
            if result.score >= 70:
                expected = "BLOCK"
            elif result.score >= 30:
                expected = "MFA_REQUIRED"
            else:
                expected = "ALLOW"

        else:
            raise AssertionError(
                f"Nieznana polityka: {result.permission_level}"
            )

        assert result.decision == expected


def test_normal_scenario_has_low_risk():
    profiles = generate_profiles(
        count=10,
        history_count=20,
        seed=1234,
    )

    results = run_experiment(profiles)

    normal_results = [
        result
        for result in results
        if result.scenario == "NORMAL"
    ]

    assert len(normal_results) == 10 * 3

    # Normalne logowanie powinno w większości
    # prowadzić do decyzji ALLOW.
    allow_count = sum(
        result.decision == "ALLOW"
        for result in normal_results
    )

    assert allow_count / len(normal_results) >= 0.55


def test_brute_force_has_high_risk():
    """
    Brute force powinien generować wysoki poziom ryzyka.
    """

    profiles = generate_profiles(
        count=10,
        history_count=20,
        seed=1234,
    )

    results = run_experiment(profiles)

    brute_force_results = [
        result
        for result in results
        if result.scenario == "BRUTE_FORCE"
    ]

    assert len(brute_force_results) == 10 * 3

    for result in brute_force_results:
        assert result.raw_score >= 70


def test_multi_anomaly_is_riskier_than_normal():
    """
    Dla tego samego użytkownika scenariusz MULTI_ANOMALY
    powinien generować większe ryzyko niż NORMAL.
    """

    profiles = generate_profiles(
        count=10,
        history_count=20,
        seed=1234,
    )

    results = run_experiment(profiles)

    normal = {
        result.username: result.raw_score
        for result in results
        if result.scenario == "NORMAL"
        and result.permission_level == "STANDARD"
    }

    multi = {
        result.username: result.raw_score
        for result in results
        if result.scenario == "MULTI_ANOMALY"
        and result.permission_level == "STANDARD"
    }

    assert set(normal.keys()) == set(multi.keys())

    for username in normal:
        assert multi[username] > normal[username]


def test_runner_does_not_modify_profiles():
    """
    Uruchomienie eksperymentu nie powinno zmieniać
    profili ani ich historii.
    """

    profiles = generate_profiles(
        count=5,
        history_count=20,
        seed=1234,
    )

    original_histories = {
        profile.username: list(profile.history)
        for profile in profiles
    }

    run_experiment(profiles)

    for profile in profiles:
        assert profile.history == original_histories[
            profile.username
        ]