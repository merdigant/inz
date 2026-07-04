import random

from .experiment_models import UserProfile


USER_AGENTS = [
    "Chrome",
    "Firefox",
    "Edge",
]

COUNTRIES = [
    "PL",
    "DE",
    "FR",
    "CZ",
]

ASN = [
    (5617, "Orange Polska"),
    (12741, "Netia"),
    (6830, "Liberty Global"),
    (15169, "Google"),
]


PROFILE_TYPES = {

    "office": {
        "hours": (8, 17),
        "country": "PL",
        "mobile": False,
    },

    "administrator": {
        "hours": (0, 23),
        "country": "PL",
        "mobile": False,
    },

    "traveller": {
        "hours": (6, 22),
        "country": "PL",
        "mobile": True,
    },

    "remote": {
        "hours": (7, 20),
        "country": "PL",
        "mobile": True,
    },

}


def generate_profiles(count: int):

    users = []

    for i in range(count):

        profile_name = random.choice(list(PROFILE_TYPES.keys()))

        definition = PROFILE_TYPES[profile_name]

        asn, org = random.choice(ASN)

        profile = UserProfile(

            username=f"user{i}",

            profile_type=profile_name,

            home_country=definition["country"],

            home_ip=f"10.0.{i // 255}.{i % 255}",

            home_asn=asn,

            home_asn_org=org,

            home_user_agent=random.choice(USER_AGENTS),

            typical_hours=definition["hours"]

        )

        users.append(profile)

    return users