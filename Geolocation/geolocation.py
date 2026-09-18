import json
import ipaddress
import urllib.request
import urllib.error


# ============================================================
# IP-API CONFIGURATION
# ============================================================
#
# ip-api.com free tier: no token required, HTTP only,
# 15 batch requests/minute, up to 100 IPs per batch,
# non-commercial use only.

IP_API_BATCH_URL = "http://ip-api.com/batch"

IP_API_FIELDS = (
    "status,message,query,"
    "continent,continentCode,country,countryCode,"
    "regionName,city,zip,lat,lon,timezone,"
    "isp,org,as"
)

IP_API_BATCH_LIMIT = 100


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
# CONVERT IP-API RESPONSE INTO MAILTRACEAI FORMAT
# ============================================================

def convert_result(ip, data):

    if data.get("status") != "success":
        return {
            "ip": ip,
            "status": "API_ERROR",
            "error": data.get("message", "Lookup failed.")
        }

    # "as" looks like "AS15169 Google LLC"
    as_parts = (data.get("as") or "").split(" ", 1)
    asn = as_parts[0] if as_parts[0].startswith("AS") else None
    as_name = as_parts[1] if asn and len(as_parts) > 1 else None

    return {
        "ip": data.get("query", ip),
        "status": "SUCCESS",
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "continent": data.get("continent"),
        "continent_code": data.get("continentCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "postal_code": data.get("zip"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "organization": data.get("org"),
        "asn": asn,
        "asn_name": as_name or data.get("isp"),
        "asn_domain": None,
        "source": "ip-api.com"
    }


# ============================================================
# QUERY IP-API FOR A BATCH OF IPs
# ============================================================

def query_batch(ips):
    """
    Send up to 100 IPs to ip-api.com in one request.
    Returns a list of raw responses in the same order,
    or raises the underlying error.
    """

    payload = json.dumps(
        [{"query": ip} for ip in ips]
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{IP_API_BATCH_URL}?fields={IP_API_FIELDS}",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


# ============================================================
# GEOLOCATE MULTIPLE IPs
# ============================================================

def geolocate_ips(ips):
    """
    Geolocate multiple IP addresses.

    Invalid and non-public IPs are rejected locally;
    public IPs are resolved in batches via ip-api.com.
    Output order matches input order.
    """

    results = [validate_ip(ip) for ip in ips]

    pending = [
        index for index, result in enumerate(results)
        if result is None
    ]

    for start in range(0, len(pending), IP_API_BATCH_LIMIT):

        chunk = pending[start:start + IP_API_BATCH_LIMIT]
        chunk_ips = [ips[index] for index in chunk]

        try:
            responses = query_batch(chunk_ips)

        except urllib.error.HTTPError as error:
            failure = {
                "status": "API_ERROR",
                "error": f"ip-api.com returned HTTP {error.code}."
            }
            responses = None

        except urllib.error.URLError as error:
            failure = {
                "status": "NETWORK_ERROR",
                "error": str(error.reason)
            }
            responses = None

        except (json.JSONDecodeError, TimeoutError):
            failure = {
                "status": "INVALID_RESPONSE",
                "error": "ip-api.com returned an invalid response."
            }
            responses = None

        for position, index in enumerate(chunk):

            ip = ips[index]

            if responses is None:
                results[index] = {"ip": ip, **failure}
            elif position >= len(responses):
                results[index] = {
                    "ip": ip,
                    "status": "INVALID_RESPONSE",
                    "error": "Missing result from ip-api.com."
                }
            else:
                results[index] = convert_result(ip, responses[position])

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
