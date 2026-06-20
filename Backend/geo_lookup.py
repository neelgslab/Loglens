from pathlib import Path
from ipaddress import ip_address


try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
except ImportError:
    geoip2 = None

    class AddressNotFoundError(Exception):
        pass


DATABASE_FILE = Path(__file__).with_name("GeoLite2-City.mmdb")

reader = None
geo_cache = {}


def get_geoip_status():
    if geoip2 is None:
        return "geoip2 package missing"

    if not DATABASE_FILE.exists():
        return "GeoLite2-City.mmdb missing"

    return "MaxMind GeoLite2 City database active"


def get_reader():
    global reader

    if geoip2 is None:
        return None

    if not DATABASE_FILE.exists():
        return None

    if reader is None:
        reader = geoip2.database.Reader(str(DATABASE_FILE))

    return reader


def is_public_ip(ip):
    try:
        parsed_ip = ip_address(ip)

        if parsed_ip.is_private:
            return False

        if parsed_ip.is_loopback:
            return False

        if parsed_ip.is_reserved:
            return False

        if parsed_ip.is_multicast:
            return False

        return True

    except ValueError:
        return False


def blank_location(reason):
    return {
        "city": reason,
        "country": "Unknown",
        "latitude": 0,
        "longitude": 0
    }


def get_geo_info(ip):
    if ip in geo_cache:
        return geo_cache[ip]

    if not is_public_ip(ip):
        location = blank_location("Private/Reserved IP")
        geo_cache[ip] = location
        return location

    database_reader = get_reader()

    if database_reader is None:
        location = blank_location("GeoIP unavailable")
        geo_cache[ip] = location
        return location

    try:
        response = database_reader.city(ip)

        location = {
            "city": response.city.name or "Unknown City",
            "country": response.country.name or "Unknown Country",
            "latitude": response.location.latitude or 0,
            "longitude": response.location.longitude or 0
        }

        geo_cache[ip] = location
        return location

    except AddressNotFoundError:
        location = blank_location("Not Found")
        geo_cache[ip] = location
        return location
    