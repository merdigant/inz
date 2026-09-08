from copy import deepcopy
from datetime import datetime, timedelta

from tests.conftest import make_attempt

from .experiment_models import Scenario, UserProfile
from app.models import RiskAssessment
from app.risk.context import RiskContext


# ============================================================
# PARAMETRY EKSPERYMENTU
# ============================================================

# Wartości wykorzystywane wyłącznie do symulowania
# kontrolowanych warunków testowych.

SCENARIO_NEW_IP_CANDIDATES = [
    "50.100.20.30",
    "8.8.8.8",
    "1.1.1.1",
]

SCENARIO_NEW_COUNTRY_CANDIDATES = [
    "US",
    "JP",
    "CA",
]

SCENARIO_NEW_USER_AGENTS = [
    "Firefox",
    "Edge",
    "Safari",
]

# ASN wykorzystywany przez scenariusze ryzykowne.
# Musi odpowiadać wartościom rozpoznawanym przez RiskyASNRule.
RISKY_ASN = 64500
RISKY_ASN_ORG = "Example VPN Hosting"


# ============================================================
# BUDOWANIE BAZOWEGO KONTEKSTU
# ============================================================

def build_context(profile: UserProfile) -> RiskContext:
    """
    Tworzy bazowy RiskContext na podstawie profilu użytkownika.

    Historia jest kopiowana, dzięki czemu późniejsze modyfikacje
    scenariusza nie zmieniają oryginalnego profilu.
    """

    return RiskContext(
        username=profile.username,
        login_history=deepcopy(profile.history),
        login_time=datetime.utcnow(),
        ip_address=profile.home_ip,
        user_agent=profile.home_user_agent,
        country=profile.home_country,
        asn=profile.home_asn,
        asn_org=profile.home_asn_org,
        risk_history=[],
    )


# ============================================================
# POMOCNICZE FUNKCJE
# ============================================================

def get_new_ip(profile: UserProfile) -> str:
    """
    Zwraca adres IP, którego nie ma w historii użytkownika.

    Wartość jest wybierana spośród kontrolowanych wartości
    przygotowanych na potrzeby eksperymentu.
    """

    known_ips = {
        attempt.ip_address
        for attempt in profile.history
        if attempt.ip_address
    }

    # Uwzględniamy również aktualny podstawowy adres profilu.
    if profile.home_ip:
        known_ips.add(profile.home_ip)

    for ip in SCENARIO_NEW_IP_CANDIDATES:
        if ip not in known_ips:
            return ip

    raise ValueError(
        "Nie znaleziono adresu IP, który byłby nowy względem profilu."
    )


def get_new_user_agent(profile: UserProfile) -> str:
    """
    Zwraca User-Agent, który nie jest typowym User-Agentem profilu.

    Funkcja najpierw szuka wartości spośród zdefiniowanych wartości
    scenariuszowych. Jeżeli wszystkie są takie same jak wartości
    występujące w historii, generuje jednoznacznie nową wartość.
    """

    known_agents = {
        attempt.user_agent
        for attempt in profile.history
        if attempt.user_agent
    }

    if profile.home_user_agent:
        known_agents.add(profile.home_user_agent)

    for user_agent in SCENARIO_NEW_USER_AGENTS:
        if user_agent not in known_agents:
            return user_agent

    return "Scenario-New-Device"


def get_new_country(profile: UserProfile) -> str:
    """
    Zwraca kraj, którego nie ma w historii profilu.
    """

    known_countries = {
        attempt.country
        for attempt in profile.history
        if attempt.country
    }

    if profile.home_country:
        known_countries.add(profile.home_country)

    for country in SCENARIO_NEW_COUNTRY_CANDIDATES:
        if country not in known_countries:
            return country

    raise ValueError(
        "Nie znaleziono kraju, który byłby nowy względem profilu."
    )


def make_scenario(
    profile: UserProfile,
    name: str,
    context: RiskContext,
) -> Scenario:
    """
    Jednolite tworzenie obiektu Scenario.
    """

    return Scenario(
        profile=profile,
        name=name,
        context=context,
    )


# ============================================================
# NORMAL
# ============================================================

def generate_normal(profile: UserProfile) -> Scenario:
    """
    Typowe logowanie użytkownika.

    Wszystkie elementy kontekstu odpowiadają profilowi.
    """

    context = build_context(profile)

    context.login_time = context.login_time.replace(
        hour=12,
        minute=0,
        second=0,
        microsecond=0,
    )

    return make_scenario(
        profile,
        "NORMAL",
        context,
    )


# ============================================================
# NEW IP
# ============================================================

def generate_new_ip(profile: UserProfile) -> Scenario:
    """
    Logowanie z nowego adresu IP.

    Pozostałe elementy kontekstu pozostają bez zmian.
    """

    context = build_context(profile)

    context.ip_address = get_new_ip(profile)

    return make_scenario(
        profile,
        "NEW_IP",
        context,
    )


# ============================================================
# NEW DEVICE
# ============================================================

def generate_new_device(profile: UserProfile) -> Scenario:
    """
    Logowanie z nowego urządzenia reprezentowanego przez
    nieznany User-Agent.
    """

    context = build_context(profile)

    context.user_agent = get_new_user_agent(profile)

    return make_scenario(
        profile,
        "NEW_DEVICE",
        context,
    )


# ============================================================
# NEW COUNTRY
# ============================================================

def generate_new_country(profile: UserProfile) -> Scenario:
    """
    Logowanie z kraju, którego użytkownik wcześniej nie używał.
    """

    context = build_context(profile)

    context.country = get_new_country(profile)

    return make_scenario(
        profile,
        "NEW_COUNTRY",
        context,
    )


# ============================================================
# UNUSUAL HOUR
# ============================================================

def generate_unusual_hour(profile: UserProfile) -> Scenario:
    """
    Logowanie o godzinie 03:00.
    """

    context = build_context(profile)

    context.login_time = context.login_time.replace(
        hour=3,
        minute=0,
        second=0,
        microsecond=0,
    )

    return make_scenario(
        profile,
        "UNUSUAL_HOUR",
        context,
    )


# ============================================================
# RISKY ASN
# ============================================================

def generate_risky_asn(profile: UserProfile) -> Scenario:
    """
    Logowanie z ASN należącym do infrastruktury oznaczonej
    jako ryzykowna.

    Wartość ASN oraz organizacji jest kontrolowana przez eksperyment
    i została dobrana tak, aby aktywować RiskyASNRule.
    """

    context = build_context(profile)

    context.asn = RISKY_ASN
    context.asn_org = RISKY_ASN_ORG

    return make_scenario(
        profile,
        "RISKY_ASN",
        context,
    )


# ============================================================
# IMPOSSIBLE TRAVEL
# ============================================================

def generate_impossible_travel(profile: UserProfile) -> Scenario:
    """
    Symuluje niemożliwą podróż.

    W historii umieszczana jest świeża próba z kraju profilu,
    a aktualne logowanie pochodzi z innego kraju.

    Odstęp czasu wynosi 30 minut, dzięki czemu
    ImpossibleTravelRule powinien wykryć anomalię.
    """

    context = build_context(profile)

    now = datetime.utcnow()

    previous_attempt = make_attempt(
        True,
        timestamp=now - timedelta(minutes=30),
        ip_address=profile.home_ip,
        country=profile.home_country,
        user_agent=profile.home_user_agent,
        asn=profile.home_asn,
    )

    context.login_history = [
        previous_attempt,
        *context.login_history,
    ]

    context.login_time = now
    context.country = get_new_country(profile)
    context.ip_address = get_new_ip(profile)

    return make_scenario(
        profile,
        "IMPOSSIBLE_TRAVEL",
        context,
    )


# ============================================================
# ACCOUNT TAKEOVER
# ============================================================

def generate_account_takeover(profile: UserProfile) -> Scenario:
    """
    Symuluje potencjalne przejęcie konta.

    Scenariusz obejmuje:

    - nowe IP,
    - nowy kraj,
    - nowe urządzenie,
    - ryzykowny ASN,
    - nietypową godzinę,
    - serię wcześniejszych nieudanych prób logowania.

    Jest to scenariusz bardziej złożony niż MULTI_ANOMALY
    i reprezentuje sytuację zbliżoną do potencjalnego
    account takeover.
    """

    context = build_context(profile)

    now = datetime.utcnow()

    # ----------------------------------------------
    # NOWE ŚRODOWISKO LOGOWANIA
    # ----------------------------------------------

    new_ip = get_new_ip(profile)
    new_country = get_new_country(profile)
    new_user_agent = get_new_user_agent(profile)

    context.ip_address = new_ip
    context.country = new_country
    context.user_agent = new_user_agent

    # ----------------------------------------------
    # NIETYPOWA GODZINA
    # ----------------------------------------------

    context.login_time = now.replace(
        hour=2,
        minute=0,
        second=0,
        microsecond=0,
    )

    # ----------------------------------------------
    # RYZYKOWNY ASN
    # ----------------------------------------------

    context.asn = RISKY_ASN
    context.asn_org = RISKY_ASN_ORG

    # ----------------------------------------------
    # WCZEŚNIEJSZE NIEUDANE PRÓBY
    # ----------------------------------------------

    failed_attempts = [
        make_attempt(
            False,
            timestamp=now - timedelta(seconds=60),
            ip_address=new_ip,
            country=new_country,
            user_agent=new_user_agent,
            asn=RISKY_ASN,
        ),
        make_attempt(
            False,
            timestamp=now - timedelta(seconds=45),
            ip_address=new_ip,
            country=new_country,
            user_agent=new_user_agent,
            asn=RISKY_ASN,
        ),
        make_attempt(
            False,
            timestamp=now - timedelta(seconds=30),
            ip_address=new_ip,
            country=new_country,
            user_agent=new_user_agent,
            asn=RISKY_ASN,
        ),
    ]

    # Najnowsza próba na początku historii.
    context.login_history = (
        list(reversed(failed_attempts))
        + context.login_history
    )

    return make_scenario(
        profile,
        "ACCOUNT_TAKEOVER",
        context,
    )


# ============================================================
# BRUTE FORCE
# ============================================================

def generate_brute_force(profile: UserProfile) -> Scenario:
    """
    Symuluje serię nieudanych prób logowania w krótkim czasie.

    Najnowsza próba znajduje się na początku login_history,
    ponieważ LastAttemptFailedRule analizuje login_history[0].
    """

    context = build_context(profile)

    now = datetime.utcnow()

    brute_force_attempts = [
        make_attempt(
            False,
            timestamp=now - timedelta(seconds=60),
            ip_address=context.ip_address,
            country=context.country,
            user_agent=context.user_agent,
            asn=context.asn,
        ),
        make_attempt(
            False,
            timestamp=now - timedelta(seconds=45),
            ip_address=context.ip_address,
            country=context.country,
            user_agent=context.user_agent,
            asn=context.asn,
        ),
        make_attempt(
            False,
            timestamp=now - timedelta(seconds=30),
            ip_address=context.ip_address,
            country=context.country,
            user_agent=context.user_agent,
            asn=context.asn,
        ),
        make_attempt(
            False,
            timestamp=now - timedelta(seconds=15),
            ip_address=context.ip_address,
            country=context.country,
            user_agent=context.user_agent,
            asn=context.asn,
        ),
        make_attempt(
            False,
            timestamp=now,
            ip_address=context.ip_address,
            country=context.country,
            user_agent=context.user_agent,
            asn=context.asn,
        ),
    ]

    context.login_history = (
        list(reversed(brute_force_attempts))
        + context.login_history
    )

    context.login_time = now

    return make_scenario(
        profile,
        "BRUTE_FORCE",
        context,
    )


# ============================================================
# CHRONIC RISK
# ============================================================

def generate_chronic_risk(profile: UserProfile) -> Scenario:
    """
    Użytkownik posiadający co najmniej trzy wcześniejsze
    decyzje MFA_REQUIRED.
    """

    context = build_context(profile)

    now = datetime.utcnow()

    context.risk_history = [
        RiskAssessment(
            username=profile.username,
            risk_score=70,
            decision="MFA_REQUIRED",
            timestamp=now - timedelta(days=1),
        ),
        RiskAssessment(
            username=profile.username,
            risk_score=65,
            decision="MFA_REQUIRED",
            timestamp=now - timedelta(days=2),
        ),
        RiskAssessment(
            username=profile.username,
            risk_score=60,
            decision="MFA_REQUIRED",
            timestamp=now - timedelta(days=3),
        ),
    ]

    context.login_time = now

    return make_scenario(
        profile,
        "CHRONIC_RISK",
        context,
    )


# ============================================================
# CONFIDENCE DECAY
# ============================================================

def generate_confidence_decay(profile: UserProfile) -> Scenario:
    """
    Symuluje sytuację, w której od ostatniej oceny ryzyka
    minęło więcej niż 7 dni.
    """

    context = build_context(profile)

    now = datetime.utcnow()

    context.risk_history = [
        RiskAssessment(
            username=profile.username,
            risk_score=60,
            decision="ALLOW",
            timestamp=now - timedelta(days=10),
        )
    ]

    context.login_time = now

    return make_scenario(
        profile,
        "CONFIDENCE_DECAY",
        context,
    )


# ============================================================
# MAPA SCENARIUSZY
# ============================================================

SCENARIO_GENERATORS = {
    "NORMAL": generate_normal,
    "NEW_IP": generate_new_ip,
    "NEW_DEVICE": generate_new_device,
    "NEW_COUNTRY": generate_new_country,
    "UNUSUAL_HOUR": generate_unusual_hour,
    "RISKY_ASN": generate_risky_asn,
    "IMPOSSIBLE_TRAVEL": generate_impossible_travel,
    "BRUTE_FORCE": generate_brute_force,
    "ACCOUNT_TAKEOVER": generate_account_takeover,
    "CHRONIC_RISK": generate_chronic_risk,
    "CONFIDENCE_DECAY": generate_confidence_decay,
}


# ============================================================
# GENEROWANIE SCENARIUSZY DLA PROFILU
# ============================================================

def generate_scenarios(profile: UserProfile) -> list[Scenario]:
    """
    Generuje pełny zestaw scenariuszy dla jednego profilu.
    """

    return [
        generator(profile)
        for generator in SCENARIO_GENERATORS.values()
    ]