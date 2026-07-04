from enum import Enum
from copy import deepcopy
from datetime import datetime
import random

from app.risk.context import RiskContext

from .experiment_models import Scenario

class ScenarioType(Enum):

    NORMAL = "NORMAL"

    NEW_IP = "NEW_IP"

    NEW_DEVICE = "NEW_DEVICE"

    NEW_COUNTRY = "NEW_COUNTRY"

    UNUSUAL_HOUR = "UNUSUAL_HOUR"

    RISKY_ASN = "RISKY_ASN"

    IMPOSSIBLE_TRAVEL = "IMPOSSIBLE_TRAVEL"

    MULTI_ANOMALY = "MULTI_ANOMALY"

    BRUTE_FORCE = "BRUTE_FORCE"

    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"

def build_context(profile):

    return RiskContext(

        username=profile.username,

        login_history=deepcopy(profile.history),

        login_time=datetime.utcnow(),

        ip_address=profile.home_ip,

        user_agent=profile.home_user_agent,

        country=profile.home_country,

        asn=profile.home_asn,

        asn_org=profile.home_asn_org,

        risk_history=[]

    )
def generate_normal(profile):

    context = build_context(profile)

    return Scenario(

        profile,

        "NORMAL",

        context,

        "ALLOW"

    )

def generate_new_ip(profile):

    context = build_context(profile)

    context.ip_address = "50.100.20.30"

    return Scenario(

        profile,

        "NEW_IP",

        context,

        "ALLOW"

    )

def generate_new_device(profile):

    context = build_context(profile)

    context.user_agent = "Firefox"

    return Scenario(

        profile,

        "NEW_DEVICE",

        context,

        "ALLOW"

    )

def generate_new_country(profile):

    context = build_context(profile)

    context.country = "US"

    return Scenario(

        profile,

        "NEW_COUNTRY",

        context,

        "ALLOW"

    )

def generate_night_login(profile):

    context = build_context(profile)

    context.login_time = context.login_time.replace(hour=3)

    return Scenario(

        profile,

        "UNUSUAL_HOUR",

        context,

        "ALLOW"

    )

def generate_risky_asn(profile):

    context = build_context(profile)

    context.asn = 15169

    return Scenario(

        profile,

        "RISKY_ASN",

        context,

        "MFA"

    )

def generate_multi(profile):

    context = build_context(profile)

    context.ip_address = "8.8.8.8"

    context.country = "US"

    context.user_agent = "Firefox"

    context.login_time = context.login_time.replace(hour=2)

    context.asn = 15169

    return Scenario(

        profile,

        "MULTI_ANOMALY",

        context,

        "MFA"

    )

from tests.conftest import make_attempt
from datetime import timedelta


def generate_bruteforce(profile):

    context = build_context(profile)

    now = datetime.utcnow()

    context.login_history = [

        make_attempt(
            False,
            timestamp=now - timedelta(seconds=60)
        ),

        make_attempt(
            False,
            timestamp=now - timedelta(seconds=45)
        ),

        make_attempt(
            False,
            timestamp=now - timedelta(seconds=30)
        ),

        make_attempt(
            False,
            timestamp=now - timedelta(seconds=15)
        ),

        make_attempt(
            False,
            timestamp=now
        ),

    ]

    return Scenario(

        profile,

        "BRUTE_FORCE",

        context,

        "MFA"

    )

def generate_dataset(

    profiles,

    normal=5000,

    new_ip=1000,

    new_device=1000,

    new_country=1000,

    unusual_hour=1000,

    risky_asn=500,

    brute_force=500,

    multi=1000,

):