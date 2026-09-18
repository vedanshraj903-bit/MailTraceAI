# ============================================================
# MAILTRACEAI - THREAT INTELLIGENCE ENGINE
# VERSION 3.0
# ============================================================

from pathlib import Path
import json
import os
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
import base64
from datetime import datetime, timezone


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

SECURITY_FILE = BASE_DIR / "security_analysis.json"

OUTPUT_FILE = BASE_DIR / "threat_intelligence.json"


# ============================================================
# API CONFIGURATION
# ============================================================

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY"
)


# ============================================================
# HTTP REQUEST HELPER
# ============================================================

def make_request(
    url,
    headers=None,
    timeout=15
):

    request = urllib.request.Request(
        url,
        headers=headers or {},
        method="GET"
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout
        ) as response:

            status_code = response.status

            response_data = response.read()

            decoded = json.loads(
                response_data.decode("utf-8")
            )

            return {
                "success": True,
                "status_code": status_code,
                "data": decoded
            }

    except urllib.error.HTTPError as error:

        return {
            "success": False,
            "status_code": error.code,
            "error": f"HTTP error {error.code}"
        }

    except urllib.error.URLError as error:

        return {
            "success": False,
            "status_code": None,
            "error": f"Connection error: {error.reason}"
        }

    except json.JSONDecodeError:

        return {
            "success": False,
            "status_code": None,
            "error": "Invalid JSON response"
        }

    except Exception as error:

        return {
            "success": False,
            "status_code": None,
            "error": str(error)
        }


# ============================================================
# CHECK WHETHER IP IS PUBLIC
# ============================================================

def is_public_ip(ip):

    try:

        address = ipaddress.ip_address(ip)

        return address.is_global

    except ValueError:

        return False


# ============================================================
# VIRUSTOTAL - IP LOOKUP
# ============================================================

def virustotal_ip_lookup(ip):

    if not VIRUSTOTAL_API_KEY:

        return {
            "status": "NOT_CONFIGURED",
            "ip": ip
        }

    url = (
        "https://www.virustotal.com"
        f"/api/v3/ip_addresses/{ip}"
    )

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    result = make_request(
        url,
        headers=headers
    )

    if not result["success"]:

        return {
            "status": "ERROR",
            "ip": ip,
            "error": result["error"],
            "status_code": result["status_code"]
        }

    data = (
        result["data"]
        .get("data", {})
    )

    attributes = (
        data
        .get("attributes", {})
    )

    analysis_stats = (
        attributes
        .get(
            "last_analysis_stats",
            {}
        )
    )

    return {
        "status": "FOUND",
        "ip": ip,
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "reputation": attributes.get("reputation"),
        "last_analysis_stats": analysis_stats
    }


# ============================================================
# ABUSEIPDB - IP LOOKUP
# ============================================================

def abuseipdb_ip_lookup(ip):

    if not ABUSEIPDB_API_KEY:

        return {
            "status": "NOT_CONFIGURED",
            "ip": ip
        }

    endpoint = (
        "https://api.abuseipdb.com"
        "/api/v2/check"
    )

    parameters = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": "90"
    })

    url = (
        endpoint
        + "?"
        + parameters
    )

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    result = make_request(
        url,
        headers=headers
    )

    if not result["success"]:

        return {
            "status": "ERROR",
            "ip": ip,
            "error": result["error"],
            "status_code": result["status_code"]
        }

    data = (
        result["data"]
        .get("data", {})
    )

    return {
        "status": "FOUND",
        "ip": ip,
        "abuse_confidence_score": data.get(
            "abuseConfidenceScore"
        ),
        "total_reports": data.get(
            "totalReports"
        ),
        "country_code": data.get(
            "countryCode"
        ),
        "country_name": data.get(
            "countryName"
        ),
        "isp": data.get("isp"),
        "usage_type": data.get(
            "usageType"
        ),
        "domain": data.get(
            "domain"
        ),
        "last_reported_at": data.get(
            "lastReportedAt"
        )
    }


# ============================================================
# VIRUSTOTAL - DOMAIN LOOKUP
# ============================================================

def virustotal_domain_lookup(domain):

    if not VIRUSTOTAL_API_KEY:

        return {
            "status": "NOT_CONFIGURED",
            "domain": domain
        }

    encoded_domain = urllib.parse.quote(
        domain,
        safe=""
    )

    url = (
        "https://www.virustotal.com"
        f"/api/v3/domains/{encoded_domain}"
    )

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    result = make_request(
        url,
        headers=headers
    )

    if not result["success"]:

        return {
            "status": "ERROR",
            "domain": domain,
            "error": result["error"],
            "status_code": result["status_code"]
        }

    data = (
        result["data"]
        .get("data", {})
    )

    attributes = (
        data
        .get("attributes", {})
    )

    analysis_stats = (
        attributes
        .get(
            "last_analysis_stats",
            {}
        )
    )

    return {
        "status": "FOUND",
        "domain": domain,
        "reputation": attributes.get(
            "reputation"
        ),
        "registrar": attributes.get(
            "registrar"
        ),
        "creation_date": attributes.get(
            "creation_date"
        ),
        "last_analysis_stats": analysis_stats,
        "total_votes": attributes.get(
            "total_votes"
        ),
        "categories": attributes.get(
            "categories"
        ),
        "tags": attributes.get(
            "tags"
        )
    }


# ============================================================
# VIRUSTOTAL - URL LOOKUP
# ============================================================

def virustotal_url_lookup(url_value):

    if not VIRUSTOTAL_API_KEY:

        return {
            "status": "NOT_CONFIGURED",
            "url": url_value
        }

    # --------------------------------------------------------
    # VirusTotal URL identifiers use URL-safe Base64
    # without "=" padding.
    # --------------------------------------------------------

    encoded_url = (
        base64.urlsafe_b64encode(
            url_value.encode("utf-8")
        )
        .decode("utf-8")
        .rstrip("=")
    )

    endpoint = (
        "https://www.virustotal.com"
        f"/api/v3/urls/{encoded_url}"
    )

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    result = make_request(
        endpoint,
        headers=headers
    )

    if not result["success"]:

        return {
            "status": "ERROR",
            "url": url_value,
            "error": result["error"],
            "status_code": result["status_code"]
        }

    data = (
        result["data"]
        .get("data", {})
    )

    attributes = (
        data
        .get("attributes", {})
    )

    analysis_stats = (
        attributes
        .get(
            "last_analysis_stats",
            {}
        )
    )

    return {
        "status": "FOUND",
        "url": url_value,
        "reputation": attributes.get(
            "reputation"
        ),
        "last_analysis_stats": analysis_stats,
        "categories": attributes.get(
            "categories"
        ),
        "tags": attributes.get(
            "tags"
        ),
        "title": attributes.get(
            "title"
        ),
        "last_final_url": attributes.get(
            "last_final_url"
        )
    }


# ============================================================
# EXTRACT PUBLIC IPs
# ============================================================

def extract_public_ips(security_data):

    routing = security_data.get(
        "routing",
        {}
    )

    ip_entries = routing.get(
        "ips",
        []
    )

    public_ips = []

    for entry in ip_entries:

        if not isinstance(entry, dict):
            continue

        ip = entry.get("ip")

        classification = entry.get(
            "classification"
        )

        if (
            ip
            and classification == "PUBLIC"
            and is_public_ip(ip)
        ):

            public_ips.append(ip)

    # Remove duplicates while preserving order.

    return list(
        dict.fromkeys(public_ips)
    )


# ============================================================
# EXTRACT DOMAINS
# ============================================================

def extract_domains(security_data):

    urls_data = security_data.get(
        "urls",
        {}
    )

    url_domains = urls_data.get(
        "domains",
        []
    )

    all_domains = security_data.get(
        "domains",
        []
    )

    domains = list(
        dict.fromkeys(
            url_domains
            + all_domains
        )
    )

    return domains


# ============================================================
# EXTRACT URLs
# ============================================================

def extract_urls(security_data):

    urls_data = security_data.get(
        "urls",
        {}
    )

    # Security Analyzer stores URLs as:
    #
    # "urls": {
    #     "total": 6,
    #     "details": [
    #         {
    #             "url": "http://example.com"
    #         }
    #     ]
    # }

    url_details = urls_data.get(
        "details",
        []
    )

    urls = []

    for entry in url_details:

        if not isinstance(
            entry,
            dict
        ):
            continue

        url_value = entry.get(
            "url"
        )

        if url_value:

            urls.append(
                url_value
            )

    # Remove duplicates.

    return list(
        dict.fromkeys(urls)
    )


# ============================================================
# MAIN THREAT INTELLIGENCE FUNCTION
# ============================================================

def analyze_threat_intelligence(
    security_data,
    verbose=False
):

    if not isinstance(
        security_data,
        dict
    ):

        raise TypeError(
            "security_data must be a dictionary."
        )

    # --------------------------------------------------------
    # Extract indicators
    # --------------------------------------------------------

    public_ips = extract_public_ips(
        security_data
    )

    domains = extract_domains(
        security_data
    )

    urls = extract_urls(
        security_data
    )

    # --------------------------------------------------------
    # Results containers
    # --------------------------------------------------------

    ip_results = []

    domain_results = []

    url_results = []

    # ========================================================
    # IP INTELLIGENCE
    # ========================================================

    for ip in public_ips:

        if verbose:

            print()
            print(
                f"Checking IP: {ip}"
            )

        vt_result = (
            virustotal_ip_lookup(
                ip
            )
        )

        abuse_result = (
            abuseipdb_ip_lookup(
                ip
            )
        )

        ip_results.append({

            "ip": ip,

            "virustotal":
                vt_result,

            "abuseipdb":
                abuse_result

        })

    # ========================================================
    # DOMAIN INTELLIGENCE
    # ========================================================

    for domain in domains:

        if verbose:

            print()
            print(
                f"Checking domain: {domain}"
            )

        vt_result = (
            virustotal_domain_lookup(
                domain
            )
        )

        domain_results.append({

            "domain": domain,

            "virustotal":
                vt_result

        })

    # ========================================================
    # URL INTELLIGENCE
    # ========================================================

    for url_value in urls:

        if verbose:

            print()
            print(
                f"Checking URL: {url_value}"
            )

        vt_result = (
            virustotal_url_lookup(
                url_value
            )
        )

        url_results.append({

            "url": url_value,

            "virustotal":
                vt_result

        })

    # ========================================================
    # BUILD OUTPUT
    # ========================================================

    threat_intelligence = {

        "tool":
            "MailTraceAI",

        "threat_intelligence_version":
            "3.0",

        "analysis_timestamp":
            datetime.now(
                timezone.utc
            ).isoformat(),

        "email": {

            "file":
                security_data.get(
                    "email_file"
                ),

            "sha256":
                security_data
                .get(
                    "evidence",
                    {}
                )
                .get(
                    "original_email_sha256"
                )

        },

        # ----------------------------------------------------
        # IP intelligence
        # ----------------------------------------------------

        "ip_intelligence": {

            "total_ips_checked":
                len(public_ips),

            "results":
                ip_results

        },

        # ----------------------------------------------------
        # Domain intelligence
        # ----------------------------------------------------

        "domain_intelligence": {

            "total_domains_checked":
                len(domains),

            "results":
                domain_results

        },

        # ----------------------------------------------------
        # URL intelligence
        # ----------------------------------------------------

        "url_intelligence": {

            "total_urls_checked":
                len(urls),

            "results":
                url_results

        }

    }

    return threat_intelligence


# ============================================================
# LOAD SECURITY ANALYSIS FROM FILE
# ============================================================

def load_security_analysis():

    if not SECURITY_FILE.exists():

        raise FileNotFoundError(
            f"Security analysis file not found:\n"
            f"{SECURITY_FILE}"
        )

    try:

        with open(
            SECURITY_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            security_data = json.load(f)

    except json.JSONDecodeError as error:

        raise ValueError(
            "security_analysis.json contains invalid JSON.\n"
            f"Error: {error}"
        )

    return security_data


# ============================================================
# SAVE THREAT INTELLIGENCE
# ============================================================

def save_threat_intelligence(
    threat_intelligence,
    output_file=None
):

    if output_file is None:

        output_file = OUTPUT_FILE

    output_file = Path(
        output_file
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            threat_intelligence,
            f,
            indent=4,
            ensure_ascii=False
        )

    return output_file


# ============================================================
# PRINT THREAT INTELLIGENCE REPORT
# ============================================================

def print_threat_intelligence(
    threat_intelligence
):

    ip_results = (
        threat_intelligence
        .get(
            "ip_intelligence",
            {}
        )
        .get(
            "results",
            []
        )
    )

    domain_results = (
        threat_intelligence
        .get(
            "domain_intelligence",
            {}
        )
        .get(
            "results",
            []
        )
    )

    url_results = (
        threat_intelligence
        .get(
            "url_intelligence",
            {}
        )
        .get(
            "results",
            []
        )
    )

    print()
    print("=" * 60)
    print(
        "MAILTRACEAI - THREAT INTELLIGENCE"
    )
    print("=" * 60)

    # ========================================================
    # IP RESULTS
    # ========================================================

    print()
    print("IP INTELLIGENCE")
    print("=" * 60)

    if ip_results:

        for result in ip_results:

            ip = result["ip"]

            vt = result["virustotal"]

            abuse = result["abuseipdb"]

            print()
            print(
                "IP:",
                ip
            )

            # ------------------------------------------------
            # VirusTotal
            # ------------------------------------------------

            print()
            print("VirusTotal:")

            if vt["status"] == "FOUND":

                print(
                    "Status: FOUND"
                )

                print(
                    "Country:",
                    vt.get("country")
                )

                print(
                    "ASN:",
                    vt.get("asn")
                )

                print(
                    "AS Owner:",
                    vt.get("as_owner")
                )

                print(
                    "Reputation:",
                    vt.get("reputation")
                )

                print(
                    "Analysis:",
                    vt.get(
                        "last_analysis_stats"
                    )
                )

            elif vt["status"] == "NOT_CONFIGURED":

                print(
                    "API key not configured."
                )

            else:

                print(
                    "Error:",
                    vt.get("error")
                )

            # ------------------------------------------------
            # AbuseIPDB
            # ------------------------------------------------

            print()
            print("AbuseIPDB:")

            if abuse["status"] == "FOUND":

                print(
                    "Status: FOUND"
                )

                print(
                    "Abuse Confidence:",
                    abuse.get(
                        "abuse_confidence_score"
                    )
                )

                print(
                    "Total Reports:",
                    abuse.get(
                        "total_reports"
                    )
                )

                print(
                    "Country:",
                    abuse.get(
                        "country_name"
                    )
                )

                print(
                    "ISP:",
                    abuse.get(
                        "isp"
                    )
                )

                print(
                    "Usage Type:",
                    abuse.get(
                        "usage_type"
                    )
                )

            elif abuse["status"] == "NOT_CONFIGURED":

                print(
                    "API key not configured."
                )

            else:

                print(
                    "Error:",
                    abuse.get("error")
                )

    else:

        print(
            "No public IPs available."
        )

    # ========================================================
    # DOMAIN RESULTS
    # ========================================================

    print()
    print("=" * 60)
    print("DOMAIN INTELLIGENCE")
    print("=" * 60)

    if domain_results:

        for result in domain_results:

            domain = result["domain"]

            vt = result["virustotal"]

            print()
            print(
                "Domain:",
                domain
            )

            if vt["status"] == "FOUND":

                print(
                    "Status: FOUND"
                )

                print(
                    "Reputation:",
                    vt.get(
                        "reputation"
                    )
                )

                print(
                    "Registrar:",
                    vt.get(
                        "registrar"
                    )
                )

                print(
                    "Analysis:",
                    vt.get(
                        "last_analysis_stats"
                    )
                )

                print(
                    "Tags:",
                    vt.get(
                        "tags"
                    )
                )

            elif vt["status"] == "NOT_CONFIGURED":

                print(
                    "VirusTotal API key "
                    "not configured."
                )

            else:

                print(
                    "Error:",
                    vt.get("error")
                )

    else:

        print(
            "No domains available."
        )

    # ========================================================
    # URL RESULTS
    # ========================================================

    print()
    print("=" * 60)
    print("URL INTELLIGENCE")
    print("=" * 60)

    if url_results:

        for result in url_results:

            url_value = result["url"]

            vt = result["virustotal"]

            print()
            print(
                "URL:",
                url_value
            )

            if vt["status"] == "FOUND":

                print(
                    "Status: FOUND"
                )

                print(
                    "Reputation:",
                    vt.get(
                        "reputation"
                    )
                )

                print(
                    "Analysis:",
                    vt.get(
                        "last_analysis_stats"
                    )
                )

                print(
                    "Categories:",
                    vt.get(
                        "categories"
                    )
                )

                print(
                    "Tags:",
                    vt.get(
                        "tags"
                    )
                )

                print(
                    "Title:",
                    vt.get(
                        "title"
                    )
                )

                print(
                    "Last Final URL:",
                    vt.get(
                        "last_final_url"
                    )
                )

            elif vt["status"] == "NOT_CONFIGURED":

                print(
                    "VirusTotal API key "
                    "not configured."
                )

            else:

                print(
                    "Error:",
                    vt.get("error")
                )

    else:

        print(
            "No URLs available."
        )

    # ========================================================
    # FINAL OUTPUT
    # ========================================================

    print()
    print("=" * 60)
    print("STRUCTURED OUTPUT")
    print("=" * 60)

    print()

    print(
        "Public IPs checked:",
        len(
            ip_results
        )
    )

    print(
        "Domains checked:",
        len(
            domain_results
        )
    )

    print(
        "URLs checked:",
        len(
            url_results
        )
    )


# ============================================================
# STANDALONE TEST MODE
# ============================================================

if __name__ == "__main__":

    print()
    print(
        "Loading security analysis..."
    )

    security_data = (
        load_security_analysis()
    )

    print(
        "Running threat intelligence..."
    )

    threat_intelligence = (
        analyze_threat_intelligence(
            security_data,
            verbose=True
        )
    )

    output_path = (
        save_threat_intelligence(
            threat_intelligence
        )
    )

    print_threat_intelligence(
        threat_intelligence
    )

    print()
    print(
        "Threat intelligence saved to:"
    )

    print(
        output_path
    )

    print()
    print("=" * 60)
    print(
        "THREAT INTELLIGENCE COMPLETE"
    )
    print("=" * 60)