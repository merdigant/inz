import statistics
import time

from fastapi.testclient import TestClient

from app.app import app


def percentile(values: list[float], percentile_value: float) -> float:
    values = sorted(values)

    index = (len(values) - 1) * percentile_value
    lower = int(index)
    upper = lower + 1

    if upper >= len(values):
        return values[lower]

    weight = index - lower

    return (
        values[lower] * (1 - weight)
        + values[upper] * weight
    )


def test_endpoint_login_performance():

    username = "endpoint_performance_user"
    password = "PerformanceTest123!"

    payload = {
        "username": username,
        "password": password,
    }

    # Liczba właściwych pomiarów
    measurements = 100

    # Liczba wywołań rozgrzewkowych
    warmup_runs = 10

    with TestClient(app) as client:

        print()
        print("=" * 70)
        print("EKSPERYMENT WYDAJNOŚCIOWY — ENDPOINTY")
        print("=" * 70)

        # ============================================================
        # PRZYGOTOWANIE UŻYTKOWNIKA
        # ============================================================

        response = client.post(
            "/users",
            json=payload,
        )

        assert response.status_code in (201, 409)

        # ============================================================
        # SPRAWDZENIE ENDPOINTÓW
        # ============================================================

        response = client.post(
            "/debug/auth/baseline",
            json=payload,
        )

        assert response.status_code == 200

        response = client.post(
            "/debug/auth/adaptive",
            json=payload,
        )

        assert response.status_code == 200

        # ============================================================
        # ROZGRZEWKA
        # ============================================================

        print()
        print("ROZGRZEWKA")
        print("-" * 70)

        for _ in range(warmup_runs):

            response = client.post(
                "/debug/auth/baseline",
                json=payload,
            )

            assert response.status_code == 200

            response = client.post(
                "/debug/auth/adaptive",
                json=payload,
            )

            assert response.status_code == 200

        # ============================================================
        # POMIARY
        # ============================================================

        print()
        print("POMIARY")
        print("-" * 70)

        baseline_times = []
        adaptive_times = []

        for i in range(measurements):

            # --------------------------------------------------------
            # BASELINE
            # --------------------------------------------------------

            start = time.perf_counter()

            response = client.post(
                "/debug/auth/baseline",
                json=payload,
            )

            end = time.perf_counter()

            assert response.status_code == 200

            baseline_times.append(
                (end - start) * 1000
            )

            # --------------------------------------------------------
            # ADAPTIVE
            # --------------------------------------------------------

            start = time.perf_counter()

            response = client.post(
                "/debug/auth/adaptive",
                json=payload,
            )

            end = time.perf_counter()

            assert response.status_code == 200

            adaptive_times.append(
                (end - start) * 1000
            )

            # Informacja o postępie
            if (i + 1) % 25 == 0:
                print(
                    f"  wykonano {i + 1}/{measurements} pomiarów"
                )

        # ============================================================
        # STATYSTYKI
        # ============================================================

        baseline_mean = statistics.mean(baseline_times)
        baseline_median = statistics.median(baseline_times)

        adaptive_mean = statistics.mean(adaptive_times)
        adaptive_median = statistics.median(adaptive_times)

        baseline_p95 = percentile(
            baseline_times,
            0.95,
        )

        baseline_p99 = percentile(
            baseline_times,
            0.99,
        )

        adaptive_p95 = percentile(
            adaptive_times,
            0.95,
        )

        adaptive_p99 = percentile(
            adaptive_times,
            0.99,
        )

        # ============================================================
        # NARZUT
        # ============================================================

        overhead_ms = adaptive_mean - baseline_mean

        overhead_percent = (
            overhead_ms / baseline_mean * 100
            if baseline_mean > 0
            else 0
        )

        # ============================================================
        # WYNIKI
        # ============================================================

        print()
        print("=" * 70)
        print("WYNIKI")
        print("=" * 70)

        print()

        print(
            f"{'':25}"
            f"{'Baseline':>15}"
            f"{'Adaptive':>15}"
        )

        print("-" * 55)

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

        print("=" * 70)
        print("NARZUT ANALIZY RYZYKA")
        print("=" * 70)

        print()

        print(
            f"Narzut czasowy:   "
            f"{overhead_ms:.4f} ms"
        )

        print(
            f"Narzut względny:  "
            f"{overhead_percent:.2f}%"
        )

        print()

        print("=" * 70)

        # ============================================================
        # WALIDACJA
        # ============================================================

        assert len(baseline_times) == measurements
        assert len(adaptive_times) == measurements