import geoip2.database


class GeoLookup:
    def __init__(self, country_db: str, asn_db: str):
        self.country_reader = geoip2.database.Reader(country_db)
        self.asn_reader = geoip2.database.Reader(asn_db)

    def get_country(self, ip: str) -> str | None:
        try:
            return self.country_reader.country(ip).country.iso_code
        except Exception:
            return None

    def get_asn(self, ip: str) -> int | None:
        try:
            return self.asn_reader.asn(ip).autonomous_system_number
        except Exception:
            return None

    def get_asn_org(self, ip: str) -> str | None:
        try:
            return self.asn_reader.asn(ip).autonomous_system_organization
        except Exception:
            return None
