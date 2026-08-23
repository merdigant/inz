import random

from .experiment_models import UserProfile
from .data_pools import (
    COUNTRIES,
    USER_AGENTS,
    ASNS,
    IP_ADDRESSES,
)
from .history_generator import generate_history


PROFILE_TYPES = [
    "STANDARD",
    "REMOTE",
    "TRAVELER",
]


PROFILE_HOURS = {
    "STANDARD": (8, 17),
    "REMOTE": (7, 21),
    "TRAVELER": (6, 22),
}


def generate_ip(rng=None):
    """
    Zwraca adres IP z puli wykorzystywanej
    w eksperymencie.
    """

    rng = rng or random

    return rng.choice(IP_ADDRESSES)


def generate_typical_hours(profile_type):
    """
    Zwraca typowe godziny logowania
    dla danego typu profilu.
    """

    if profile_type not in PROFILE_HOURS:
        raise ValueError(
            f"Unknown profile type: {profile_type}"
        )

    return PROFILE_HOURS[profile_type]


def generate_profile(
    username,
    profile_type=None,
    history_count=20,
    seed=None,
):
    """
    Generuje pojedynczy profil użytkownika
    wraz z jego historią logowań.
    """

    rng = random.Random(seed)

    # --------------------------------------------------
    # TYP PROFILU
    # --------------------------------------------------

    if profile_type is None:
        profile_type = rng.choice(PROFILE_TYPES)

    if profile_type not in PROFILE_TYPES:
        raise ValueError(
            f"Unknown profile type: {profile_type}"
        )

    # --------------------------------------------------
    # TYPowy KRAJ
    # --------------------------------------------------

    home_country, _ = rng.choice(
        COUNTRIES
    )

    # --------------------------------------------------
    # TYPowy ASN
    # --------------------------------------------------

    home_asn, home_asn_org = rng.choice(
        ASNS
    )

    # --------------------------------------------------
    # TYPowy ADRES IP
    # --------------------------------------------------

    home_ip = generate_ip(rng)

    # --------------------------------------------------
    # TYPowy USER-AGENT
    # --------------------------------------------------

    home_user_agent = rng.choice(
        USER_AGENTS
    )

    # --------------------------------------------------
    # TYPowe GODZINY
    # --------------------------------------------------

    typical_hours = generate_typical_hours(
        profile_type
    )

    # --------------------------------------------------
    # HISTORIA LOGOWAŃ
    # --------------------------------------------------

    history_seed = (
        None
        if seed is None
        else seed + 1
    )

    history = generate_history(
        username=username,
        profile_type=profile_type,
        home_ip=home_ip,
        home_country=home_country,
        home_user_agent=home_user_agent,
        home_asn=home_asn,
        home_asn_org=home_asn_org,
        count=history_count,
        seed=history_seed,
    )

    # --------------------------------------------------
    # PROFIL
    # --------------------------------------------------

    return UserProfile(
        username=username,
        profile_type=profile_type,
        home_country=home_country,
        home_ip=home_ip,
        home_asn=home_asn,
        home_asn_org=home_asn_org,
        home_user_agent=home_user_agent,
        typical_hours=typical_hours,
        history=history,
    )


def generate_profiles(
    count=1000,
    history_count=20,
    seed=None,
):
    """
    Generuje populację użytkowników.

    Każdy użytkownik otrzymuje:
    - typ profilu,
    - typowy kontekst,
    - historię logowań.
    """

    if count <= 0:
        return []

    rng = random.Random(seed)

    profiles = []

    for i in range(count):

        username = f"user_{i:05d}"

        profile_type = rng.choice(
            PROFILE_TYPES
        )

        profile_seed = (
            None
            if seed is None
            else seed + i
        )

        profile = generate_profile(
            username=username,
            profile_type=profile_type,
            history_count=history_count,
            seed=profile_seed,
        )

        profiles.append(profile)

    return profiles