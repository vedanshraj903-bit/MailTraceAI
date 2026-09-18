import json
import ipaddress
import os
import ssl
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


# ============================================================
# IPINFO CONFIGURATION
# ============================================================
#
# ipinfo.io: HTTPS, works without a token (rate-limited per
# client IP). Set IPINFO_TOKEN for the free 50k lookups/month
# tier, which is recommended on shared hosts such as Vercel.
#
# ipinfo places infrastructure IPs where the server actually
# is (e.g. Google mail servers in their data centres) rather
# than at the owner's registered head office.

IPINFO_URL = "https://ipinfo.io/{ip}/json"

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

REQUEST_TIMEOUT = 10

MAX_PARALLEL_LOOKUPS = 8


# ipinfo only returns an ISO country code. Names and continents
# come from ipinfo's own reference data (ipinfo/python, Apache-2.0).
COUNTRIES = json.loads(
    (Path(__file__).parent / "countries.json").read_text(encoding="utf-8")
)


def _ssl_context():
    """
    Use certifi's CA bundle when available: python.org builds on
    macOS ship without system certificates, so HTTPS would fail.
    """

    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


SSL_CONTEXT = _ssl_context()


# ============================================================
# VALIDATE ONE IP
# ============================================================

def validate_ip(ip):
    """
    Return an error result for invalid / non-public IPs,
    or None when the IP can be geolocated.
    """

    try:
        ip_object = ipaddress.ip_address(ip)

    except ValueError:
        return {
            "ip": ip,
            "status": "INVALID_IP",
            "error": "Invalid IP address."
        }

    if not ip_object.is_global:
        return {
            "ip": ip,
            "status": "NON_PUBLIC_IP",
            "error": "Only public IP addresses are geolocated."
        }

    return None


# ============================================================
# CONVERT IPINFO RESPONSE INTO MAILTRACEAI FORMAT
# ============================================================

def convert_result(ip, data):

    if data.get("bogon"):
        return {
            "ip": ip,
            "status": "NON_PUBLIC_IP",
            "error": "Only public IP addresses are geolocated."
        }

    if not data.get("country"):
        return {
            "ip": ip,
            "status": "API_ERROR",
            "error": "ipinfo.io has no location for this IP."
        }

    latitude = longitude = None

    try:
        latitude, longitude = (
            float(part) for part in data.get("loc", "").split(",")
        )
    except ValueError:
        pass

    # "org" looks like "AS15169 Google LLC"
    org_parts = (data.get("org") or "").split(" ", 1)
    asn = org_parts[0] if org_parts[0].startswith("AS") else None
    as_name = org_parts[1] if asn and len(org_parts) > 1 else None

    country_code = data.get("country")
    country = COUNTRIES.get(country_code, {})

    return {
        "ip": data.get("ip", ip),
        "status": "SUCCESS",
        "hostname": data.get("hostname"),
        "country": country.get("name") or country_code,
        "country_code": country_code,
        "continent": country.get("continent"),
        "continent_code": country.get("continent_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "postal_code": data.get("postal"),
        "latitude": latitude,
        "longitude": longitude,
        "timezone": data.get("timezone"),
        "isp": as_name,
        "organization": as_name or data.get("org"),
        "asn": asn,
        "asn_name": as_name,
        "asn_domain": None,
        "anycast": bool(data.get("anycast")),
        "source": "ipinfo.io"
    }


# ============================================================
# QUERY IPINFO FOR ONE IP
# ============================================================

def query_ip(ip):
    """
    Look up one IP on ipinfo.io and return a MailTraceAI result.
    Network and API failures are returned as error results.
    """

    headers = {"Accept": "application/json"}

    if IPINFO_TOKEN:
        headers["Authorization"] = f"Bearer {IPINFO_TOKEN}"

    request = urllib.request.Request(
        IPINFO_URL.format(ip=ip),
        headers=headers
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
            context=SSL_CONTEXT
        ) as response:
            data = json.loads(response.read().decode("utf-8"))

    except urllib.error.HTTPError as error:
        if error.code == 429:
            message = (
                "ipinfo.io rate limit reached. "
                "Set IPINFO_TOKEN for a higher limit."
            )
        else:
            message = f"ipinfo.io returned HTTP {error.code}."

        return {"ip": ip, "status": "API_ERROR", "error": message}

    except urllib.error.URLError as error:
        return {
            "ip": ip,
            "status": "NETWORK_ERROR",
            "error": str(error.reason)
        }

    except (json.JSONDecodeError, TimeoutError):
        return {
            "ip": ip,
            "status": "INVALID_RESPONSE",
            "error": "ipinfo.io returned an invalid response."
        }

    return convert_result(ip, data)


# ============================================================
# GEOLOCATE MULTIPLE IPs
# ============================================================

def geolocate_ips(ips):
    """
    Geolocate multiple IP addresses.

    Invalid and non-public IPs are rejected locally;
    public IPs are looked up on ipinfo.io in parallel.
    Output order matches input order.
    """

    results = [validate_ip(ip) for ip in ips]

    pending = [
        index for index, result in enumerate(results)
        if result is None
    ]

    if pending:
        with ThreadPoolExecutor(
            max_workers=min(MAX_PARALLEL_LOOKUPS, len(pending))
        ) as pool:
            lookups = pool.map(
                query_ip,
                [ips[index] for index in pending]
            )

            for index, result in zip(pending, lookups):
                results[index] = result

    return results


def geolocate_ip(ip):
    """
    Geolocate one IP address.
    """

    return geolocate_ips([ip])[0]


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    test_ips = [
        "193.120.211.219",
        "209.63.151.251",
        "127.0.0.1",
        "999.999.999.999"
    ]

    results = geolocate_ips(test_ips)

    print(json.dumps(results, indent=4))
