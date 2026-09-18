import os
import json
import ipaddress
import urllib.request
import urllib.error


# ============================================================
# IPINFO CONFIGURATION
# ============================================================

IPINFO_API_TOKEN = os.getenv("IPINFO_API_TOKEN")


# ============================================================
# GEOLocate ONE IP
# ============================================================

def geolocate_ip(ip):
    """
    Geolocate one public IP address using IPinfo Lite.
    """

    # --------------------------------------------------------
    # 1. Validate IP address
    # --------------------------------------------------------

    try:
        ip_object = ipaddress.ip_address(ip)

    except ValueError:
        return {
            "ip": ip,
            "status": "INVALID_IP",
            "error": "Invalid IP address."
        }


    # --------------------------------------------------------
    # 2. Reject non-public IP addresses
    # --------------------------------------------------------

    if not ip_object.is_global:
        return {
            "ip": ip,
            "status": "NON_PUBLIC_IP",
            "error": "Only public IP addresses are geolocated."
        }


    # --------------------------------------------------------
    # 3. Check API token
    # --------------------------------------------------------

    if not IPINFO_API_TOKEN:
        return {
            "ip": ip,
            "status": "NOT_CONFIGURED",
            "error": "IPinfo API token is not configured."
        }


    # --------------------------------------------------------
    # 4. Create IPinfo API request
    # --------------------------------------------------------

    url = f"https://api.ipinfo.io/lite/{ip}"

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {IPINFO_API_TOKEN}"
        },
        method="GET"
    )


    # --------------------------------------------------------
    # 5. Send request to IPinfo
    # --------------------------------------------------------

    try:

        with urllib.request.urlopen(request, timeout=10) as response:

            response_data = response.read().decode("utf-8")

            data = json.loads(response_data)


    except urllib.error.HTTPError as error:

        return {
            "ip": ip,
            "status": "API_ERROR",
            "error": f"IPinfo returned HTTP {error.code}."
        }


    except urllib.error.URLError as error:

        return {
            "ip": ip,
            "status": "NETWORK_ERROR",
            "error": str(error.reason)
        }


    except json.JSONDecodeError:

        return {
            "ip": ip,
            "status": "INVALID_RESPONSE",
            "error": "IPinfo returned invalid JSON."
        }


    # --------------------------------------------------------
    # 6. Convert IPinfo response into MailTraceAI format
    # --------------------------------------------------------

    return {
        "ip": data.get("ip", ip),
        "status": "SUCCESS",
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "continent": data.get("continent"),
        "continent_code": data.get("continent_code"),
        "asn": data.get("asn"),
        "asn_name": data.get("as_name"),
        "asn_domain": data.get("as_domain"),
        "source": "IPinfo Lite"
    }


# ============================================================
# GEOLocate MULTIPLE IPs
# ============================================================

def geolocate_ips(ips):
    """
    Geolocate multiple IP addresses.

    Each IP is processed using geolocate_ip().
    """

    results = []

    for ip in ips:

        result = geolocate_ip(ip)

        results.append(result)

    return results


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