import random

from datetime import datetime
from datetime import timedelta

from tests.conftest import make_attempt


def generate_history(profile, count=30):

    history = []

    start_hour, end_hour = profile.typical_hours

    now = datetime.utcnow()

    for i in range(count):

        timestamp = now - timedelta(days=count-i)

        hour = random.randint(start_hour, end_hour)

        timestamp = timestamp.replace(hour=hour)

        success = random.random() < 0.95

        ip = profile.home_ip
        country = profile.home_country
        ua = profile.home_user_agent

        asn = profile.home_asn
        org = profile.home_asn_org

        # 5% lekkich odchyleń

        if random.random() < 0.05:

            if random.random() < 0.4:

                ua = random.choice([
                    "Chrome",
                    "Firefox",
                    "Edge"
                ])

            elif random.random() < 0.7:

                ip = f"10.1.{random.randint(0,255)}.{random.randint(0,255)}"

            else:

                hour = random.randint(0,23)

                timestamp = timestamp.replace(hour=hour)

        history.append(

            make_attempt(

                success,

                ip_address=ip,

                country=country,

                user_agent=ua,

                asn=asn,

                asn_org=org,

                timestamp=timestamp

            )

        )

    profile.history = history

    return history