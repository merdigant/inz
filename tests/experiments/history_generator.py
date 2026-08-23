import random
from datetime import datetime, timedelta

from tests.conftest import make_attempt

from .data_pools import (
    COUNTRIES,
    USER_AGENTS,
    ASNS,
    IP_ADDRESSES,
)


PROFILE_CONFIG = {
    "STANDARD": {
        "ip_change_probability": 0.05,
        "country_change_probability": 0.01,
        "user_agent_change_probability": 0.05,
        "asn_change_probability": 0.02,
        "failure_probability": 0.02,
        "hour_range": (8, 17),
    },

    "REMOTE": {
        "ip_change_probability": 0.30,
        "country_change_probability": 0.02,
        "user_agent_change_probability": 0.15,
        "asn_change_probability": 0.15,
        "failure_probability": 0.03,
        "hour_range": (7, 21),
    },

    "TRAVELER": {
        "ip_change_probability": 0.55,
        "country_change_probability": 0.30,
        "user_agent_change_probability": 0.20,
        "asn_change_probability": 0.35,
        "failure_probability": 0.04,
        "hour_range": (6, 22),
    },
}


def generate_history(
    username,
    profile_type,
    home_ip,
    home_country,
    home_user_agent,
    home_asn,
    home_asn_org,
    count=20,
    seed=None,
):
    """
    Generuje syntetyczną historię logowań użytkownika.

    Historia jest zależna od typu profilu:

    STANDARD
        Użytkownik o stabilnym sposobie logowania.
        Zmiany IP, urządzenia, kraju i ASN występują rzadko.

    REMOTE
        Użytkownik pracujący z różnych sieci.
        Częściej zmienia IP, urządzenie i ASN,
        ale zazwyczaj pozostaje w tym samym kraju.

    TRAVELER
        Użytkownik często podróżujący.
        Częste zmiany IP, kraju i ASN są elementem
        jego normalnego zachowania.

    Parametr seed pozwala wygenerować powtarzalny
    eksperyment.
    """

    if profile_type not in PROFILE_CONFIG:
        raise ValueError(
            f"Nieznany typ profilu: {profile_type}"
        )

    if count <= 0:
        return []

    rng = random.Random(seed)

    config = PROFILE_CONFIG[profile_type]

    history = []

    # --------------------------------------------------
    # ZNANE WARTOŚCI KONTEKSTOWE
    # --------------------------------------------------

    known_ips = [home_ip]
    known_countries = [home_country]
    known_user_agents = [home_user_agent]
    known_asns = [(home_asn, home_asn_org)]

    # --------------------------------------------------
    # POCZĄTEK HISTORII
    # --------------------------------------------------

    now = datetime.utcnow()

    start_date = now - timedelta(days=count)

    # --------------------------------------------------
    # GENEROWANIE POSZCZEGÓLNYCH LOGOWAŃ
    # --------------------------------------------------

    for i in range(count):

        login_date = start_date + timedelta(days=i)

        # ==================================================
        # GODZINA LOGOWANIA
        # ==================================================

        hour = rng.randint(
            config["hour_range"][0],
            config["hour_range"][1],
        )

        minute = rng.randint(0, 59)
        second = rng.randint(0, 59)

        timestamp = login_date.replace(
            hour=hour,
            minute=minute,
            second=second,
            microsecond=0,
        )

        # ==================================================
        # IP
        # ==================================================

        if (
            rng.random() < config["ip_change_probability"]
            and len(known_ips) < len(IP_ADDRESSES)
        ):
            available_ips = [
                ip
                for ip in IP_ADDRESSES
                if ip not in known_ips
            ]

            if available_ips:
                ip_address = rng.choice(available_ips)
                known_ips.append(ip_address)
            else:
                ip_address = rng.choice(known_ips)

        else:
            ip_address = rng.choice(known_ips)

        # ==================================================
        # KRAJ
        # ==================================================

        if (
            rng.random()
            < config["country_change_probability"]
        ):
            available_countries = [
                country_code
                for country_code, _ in COUNTRIES
                if country_code not in known_countries
            ]

            if available_countries:
                country = rng.choice(available_countries)
                known_countries.append(country)
            else:
                country = rng.choice(known_countries)

        else:
            country = rng.choice(known_countries)

        # ==================================================
        # USER AGENT
        # ==================================================

        if (
            rng.random()
            < config["user_agent_change_probability"]
        ):
            available_user_agents = [
                user_agent
                for user_agent in USER_AGENTS
                if user_agent not in known_user_agents
            ]

            if available_user_agents:
                user_agent = rng.choice(
                    available_user_agents
                )

                known_user_agents.append(user_agent)

            else:
                user_agent = rng.choice(
                    known_user_agents
                )

        else:
            user_agent = rng.choice(
                known_user_agents
            )

        # ==================================================
        # ASN
        # ==================================================

        if (
            rng.random()
            < config["asn_change_probability"]
        ):
            known_asn_numbers = {
                asn
                for asn, _ in known_asns
            }

            available_asns = [
                asn_data
                for asn_data in ASNS
                if asn_data[0] not in known_asn_numbers
            ]

            if available_asns:
                asn, asn_org = rng.choice(
                    available_asns
                )

                known_asns.append(
                    (asn, asn_org)
                )

            else:
                asn, asn_org = rng.choice(
                    known_asns
                )

        else:
            asn, asn_org = rng.choice(
                known_asns
            )

        # ==================================================
        # SUKCES LOGOWANIA
        # ==================================================

        success = (
            rng.random()
            >= config["failure_probability"]
        )

        # ==================================================
        # UTWORZENIE PRÓBY LOGOWANIA
        # ==================================================
        
        attempt = make_attempt(
            success,
            timestamp=timestamp,
            ip_address=ip_address,
            country=country,
            user_agent=user_agent,
            asn=asn,
            asn_org=asn_org,
        )

        history.append(attempt)

    return history