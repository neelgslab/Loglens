import ipaddress
import os

try:
    import geoip2.database
except ImportError:
    geoip2 = None


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")

_reader = None
_cache = {}

DEMO_GEO_FALLBACK = {
    "185.220.101.1": {
        "ip": "185.220.101.1",
        "city": "Brandenburg an der Havel",
        "country": "Germany",
        "latitude": 52.6171,
        "longitude": 13.1207,
    },
    "51.15.76.10": {
        "ip": "51.15.76.10",
        "city": "Haarlem",
        "country": "The Netherlands",
        "latitude": 52.3803,
        "longitude": 4.6422,
    },
    "45.33.32.156": {
        "ip": "45.33.32.156",
        "city": "Fremont",
        "country": "United States",
        "latitude": 37.5483,
        "longitude": -121.9886,
    },
    "103.48.198.141": {
        "ip": "103.48.198.141",
        "city": "New Delhi",
        "country": "India",
        "latitude": 28.6139,
        "longitude": 77.209,
    },
    "45.79.118.42": {
        "ip": "45.79.118.42",
        "city": "Sydney",
        "country": "Australia",
        "latitude": -33.8688,
        "longitude": 151.2093,
    },
}


def empty_location(ip_address, city="GeoIP unavailable", country="Unknown"):
    return {
        "ip": ip_address,
        "city": city,
        "country": country,
        "latitude": 0,
        "longitude": 0,
    }


def get_reader():
    global _reader

    if _reader is not None:
        return _reader

    if geoip2 is None:
        return None

    if not os.path.exists(DB_PATH):
        return None

    _reader = geoip2.database.Reader(DB_PATH)
    return _reader


def get_geoip_status():
    if geoip2 is not None and os.path.exists(DB_PATH):
        return "MaxMind GeoLite2 City database active"

    return "Demo fallback GeoIP locations active"


def get_geo_info(ip_address):
    ip_address = str(ip_address).strip()

    if ip_address in _cache:
        return _cache[ip_address]

    if ip_address in DEMO_GEO_FALLBACK:
        result = dict(DEMO_GEO_FALLBACK[ip_address])
        _cache[ip_address] = result
        return result

    try:
        ip_object = ipaddress.ip_address(ip_address)

        if (
            ip_object.is_private
            or ip_object.is_loopback
            or ip_object.is_reserved
            or ip_object.is_multicast
            or ip_object.is_link_local
        ):
            result = empty_location(ip_address, "Private/Reserved IP", "N/A")
            _cache[ip_address] = result
            return result
    except ValueError:
        result = empty_location(ip_address, "Invalid IP", "N/A")
        _cache[ip_address] = result
        return result

    try:
        reader = get_reader()

        if reader is None:
            result = empty_location(ip_address)
            _cache[ip_address] = result
            return result

        response = reader.city(ip_address)

        city = response.city.name or "Unknown City"
        country = response.country.name or "Unknown Country"
        latitude = response.location.latitude or 0
        longitude = response.location.longitude or 0

        result = {
            "ip": ip_address,
            "city": city,
            "country": country,
            "latitude": latitude,
            "longitude": longitude,
        }

        _cache[ip_address] = result
        return result

    except Exception:
        result = empty_location(ip_address)
        _cache[ip_address] = result
        return result


def lookup_ip(ip_address):
    return get_geo_info(ip_address)


def get_location(ip_address):
    return get_geo_info(ip_address)


def geoip_status():
    return get_geoip_status()


def is_geoip_available():
    return geoip2 is not None and os.path.exists(DB_PATH)
