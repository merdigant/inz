from .profile_generator import generate_profiles
from .experiment_runner import run_experiment
from .analyze_results import analyze_results, print_analysis


def test_analysis():

    profiles = generate_profiles(
        count=1400,
        history_count=50,
        seed=5678,
    )

    results = run_experiment(profiles)

    analysis = analyze_results(results)

    print_analysis(analysis)