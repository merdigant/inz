import time
import statistics

from app.risk.normalization import normalize
from app.risk.policies import decide_mfa

from .experiment_runner import build_engine
from .profile_generator import generate_profiles
from .scenario_generator import generate_scenarios

from fastapi.testclient import TestClient
from app.app import app

# ============================================================
# KONFIGURACJA
# ============================================================

PROFILE_COUNT = 1000
HISTORY_COUNT = 50
REPETITIONS = 10


# ============================================================
# POMIAR CZASU
# ============================================================

def measure_time(function, repetitions=REPETITIONS):
    """
    Wielokrotnie wykonuje przekazaną funkcję i zwraca
    czasy wykonania poszczególnych powtórzeń w ms.
    """

    times = []

    for _ in range(repetitions):
        start = time.perf_counter()

        function()

        end = time.perf_counter()

        times.append(
            (end - start) * 1000
        )

    return times


# ============================================================
# BASELINE
# ============================================================

def baseline_login(context):


    # Symulacja podstawowej weryfikacji danych logowania.
    #
    # Celowo pozostawiamy operację prostą, ponieważ chcemy
    # wyznaczyć koszt samej dodatkowej analizy ryzyka.
    username = context.username

    return username


# ============================================================
# ADAPTIVE AUTHENTICATION
# ============================================================

def adaptive_login(engine, context):
    """
    Symulacja procesu logowania rozszerzonego o analizę ryzyka.
    """

    # Podstawowe uwierzytelnienie
    username = context.username

    # Analiza ryzyka
    raw_score = engine.calculate(context)

    # Normalizacja
    score = normalize(raw_score)

    # Podjęcie decyzji
    decision = decide_mfa(
        score,
        "STANDARD",
    )

    return username, decision


# ============================================================
# TEST WYDAJNOŚCIOWY
# ============================================================

def test_login_performance():
    """
    Porównuje czas wykonania standardowego logowania
    z czasem logowania rozszerzonego o analizę ryzyka.
    """

    profiles = generate_profiles(
        count=PROFILE_COUNT,
        history_count=HISTORY_COUNT,
        seed=1234,
    )

    engine = build_engine()

    baseline_times = []
    adaptive_times = []

    # --------------------------------------------------------
    # Przygotowanie scenariuszy
    # --------------------------------------------------------

    scenarios = []

    for profile in profiles:
        scenarios.extend(
            generate_scenarios(profile)
        )

    # --------------------------------------------------------
    # Pomiar
    # --------------------------------------------------------

    for scenario in scenarios:

        baseline = measure_time(
            lambda: baseline_login(
                scenario.context
            )
        )

        adaptive = measure_time(
            lambda: adaptive_login(
                engine,
                scenario.context
            )
        )

        baseline_times.extend(baseline)
        adaptive_times.extend(adaptive)

    # --------------------------------------------------------
    # Statystyki
    # --------------------------------------------------------

    baseline_mean = statistics.mean(
        baseline_times
    )

    adaptive_mean = statistics.mean(
        adaptive_times
    )

    baseline_median = statistics.median(
        baseline_times
    )

    adaptive_median = statistics.median(
        adaptive_times
    )

    baseline_sorted = sorted(
        baseline_times
    )

    adaptive_sorted = sorted(
        adaptive_times
    )

    baseline_p95 = baseline_sorted[
        int(len(baseline_sorted) * 0.95)
    ]

    adaptive_p95 = adaptive_sorted[
        int(len(adaptive_sorted) * 0.95)
    ]

    baseline_p99 = baseline_sorted[
        int(len(baseline_sorted) * 0.99)
    ]

    adaptive_p99 = adaptive_sorted[
        int(len(adaptive_sorted) * 0.99)
    ]

    overhead_ms = (
        adaptive_mean
        - baseline_mean
    )

    overhead_percent = (
        overhead_ms
        / baseline_mean
        * 100
    )

    # --------------------------------------------------------
    # Wyniki
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("EKSPERYMENT WYDAJNOŚCIOWY")
    print("=" * 70)

    print()
    print("KONFIGURACJA")
    print("-" * 70)

    print(
        f"Liczba profili:       {PROFILE_COUNT}"
    )

    print(
        f"Historia użytkownika: {HISTORY_COUNT}"
    )

    print(
        f"Liczba scenariuszy:   {len(scenarios)}"
    )

    print(
        f"Liczba pomiarów:      "
        f"{len(baseline_times)}"
    )

    print()
    print("CZAS LOGOWANIA")
    print("-" * 70)

    print(
        f"{'':25}"
        f"{'Baseline':>15}"
        f"{'Adaptive':>15}"
    )

    print(
        f"{'Średnia [ms]':25}"
        f"{baseline_mean:>15.4f}"
        f"{adaptive_mean:>15.4f}"
    )

    print(
        f"{'Mediana [ms]':25}"
        f"{baseline_median:>15.4f}"
        f"{adaptive_median:>15.4f}"
    )

    print(
        f"{'P95 [ms]':25}"
        f"{baseline_p95:>15.4f}"
        f"{adaptive_p95:>15.4f}"
    )

    print(
        f"{'P99 [ms]':25}"
        f"{baseline_p99:>15.4f}"
        f"{adaptive_p99:>15.4f}"
    )

    print()
    print("NARZUT ANALIZY RYZYKA")
    print("-" * 70)

    print(
        f"Narzut czasowy: "
        f"{overhead_ms:.4f} ms"
    )

    print(
        f"Narzut względny: "
        f"{overhead_percent:.2f}%"
    )

    print("=" * 70)

    # --------------------------------------------------------
    # Podstawowa walidacja
    # --------------------------------------------------------

    assert len(baseline_times) == len(
        adaptive_times
    )

    assert baseline_mean >= 0
    assert adaptive_mean >= 0
