from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from pathlib import Path
from datetime import datetime, timezone
import re
import hashlib
import json
import ipaddress


# ============================================================
# 1. PROJECT PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# 2. IP CLASSIFICATION
# ============================================================

def classify_ip(ip):
    try:
        address = ipaddress.ip_address(ip)

        if address.is_loopback:
            return "LOOPBACK"

        if address.is_link_local:
            return "LINK-LOCAL"

        if address.is_private:
            return "PRIVATE"

        if address.is_multicast:
            return "MULTICAST"

        if address.is_reserved:
            return "RESERVED"

        if address.is_unspecified:
            return "UNSPECIFIED"

        return "PUBLIC"

    except ValueError:
        return "INVALID"


# ============================================================
# 2b. RECEIVED HEADER → CONNECTING IP
# ============================================================
#
# A Received header reads "from <sender> (<rDNS> [<ip>]) by <receiver> ...".
# The geolocatable hop is the connecting IP in the "from" clause;
# IPs after "by", in "id"/"for" clauses or in the date are ignored.

RECEIVED_BY_PATTERN = re.compile(r"\bby\b", re.IGNORECASE)

BRACKETED_IP_PATTERN = re.compile(
    r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]"
)

IP_TOKEN_PATTERN = re.compile(r"[0-9A-Fa-f:.]{7,}")


def extract_utc_offset(date_header):
    """
    Return the sender's clock offset from the Date header
    as "+05:30", or None when it cannot be parsed. Mail
    providers usually keep this even when they strip the
    sender's IP, so it is a (spoofable) hint to their region.
    """

    try:
        offset = parsedate_to_datetime(str(date_header)).utcoffset()
    except (TypeError, ValueError, IndexError):
        return None

    if offset is None:
        return None

    minutes = int(offset.total_seconds() // 60)
    sign = "+" if minutes >= 0 else "-"
    hours, minutes = divmod(abs(minutes), 60)

    return f"{sign}{hours:02d}:{minutes:02d}"


def parse_ip(candidate):
    try:
        return str(ipaddress.ip_address(candidate.strip("[]().;")))
    except ValueError:
        return None


def extract_received_ip(received):
    """
    Return the connecting IP from a Received header's
    "from" clause, or None when there is none.
    """

    header = " ".join(received.split())

    if not header.lower().startswith("from"):
        return None

    from_clause = RECEIVED_BY_PATTERN.split(header, maxsplit=1)[0]

    # Prefer the bracketed IP written by the receiving server.
    for candidate in BRACKETED_IP_PATTERN.findall(from_clause):
        ip = parse_ip(candidate)
        if ip:
            return ip

    # Fall back to a bare IP, e.g. Outlook's "(2603:10b6:...)".
    for candidate in IP_TOKEN_PATTERN.findall(from_clause):
        ip = parse_ip(candidate)
        if ip:
            return ip

    return None


# ============================================================
# 3. EXTRACT EMAIL ADDRESS
# ============================================================

def extract_email_address(header_value):
    if not header_value:
        return None

    match = re.search(
        r'[\w.+-]+@[\w.-]+\.\w+',
        str(header_value)
    )

    if match:
        return match.group(0).lower()

    return None


# ============================================================
# 4. ANALYZE EMAIL
# ============================================================

def analyze_email(email_file):
    """
    Analyze any .eml file and return structured
    security-analysis data.
    """

    email_file = Path(email_file)

    # --------------------------------------------------------
    # READ RAW EMAIL
    # --------------------------------------------------------

    with open(email_file, "rb") as file:
        raw_email = file.read()

    # --------------------------------------------------------
    # PARSE EMAIL
    # --------------------------------------------------------

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    # --------------------------------------------------------
    # BASIC IDENTITY
    # --------------------------------------------------------

    from_header = message.get("From")
    to_header = message.get("To")
    cc_header = message.get("Cc")
    reply_to = message.get("Reply-To")
    return_path = message.get("Return-Path")
    subject = message.get("Subject")
    message_id = message.get("Message-ID")
    date_header = message.get("Date")

    from_email = extract_email_address(from_header)
    reply_email = extract_email_address(reply_to)
    return_email = extract_email_address(return_path)

    # --------------------------------------------------------
    # RECEIVED HEADERS
    # --------------------------------------------------------

    received_headers = [
        str(value)
        for value in message.get_all("Received", [])
    ]

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    authentication_results = message.get(
        "Authentication-Results"
    )

    spf_status = "NOT_AVAILABLE"
    dkim_status = "NOT_AVAILABLE"
    dmarc_status = "NOT_AVAILABLE"

    if authentication_results:

        authentication_results = str(
            authentication_results
        )

        spf_match = re.search(
            r"\bspf\s*=\s*(\w+)",
            authentication_results,
            flags=re.IGNORECASE
        )

        dkim_match = re.search(
            r"\bdkim\s*=\s*(\w+)",
            authentication_results,
            flags=re.IGNORECASE
        )

        dmarc_match = re.search(
            r"\bdmarc\s*=\s*(\w+)",
            authentication_results,
            flags=re.IGNORECASE
        )

        if spf_match:
            spf_status = spf_match.group(1).upper()

        if dkim_match:
            dkim_status = dkim_match.group(1).upper()

        if dmarc_match:
            dmarc_status = dmarc_match.group(1).upper()

    # --------------------------------------------------------
    # ARC
    # --------------------------------------------------------

    arc_headers = []

    for header_name, header_value in message.items():

        if header_name.lower().startswith("arc-"):
            arc_headers.append(str(header_value))

    if arc_headers:
        arc_status = "AVAILABLE"
    else:
        arc_status = "NOT_AVAILABLE"

    # --------------------------------------------------------
    # SENDER CONSISTENCY
    # --------------------------------------------------------

    sender_consistency = {
        "from_reply_to": "NOT_AVAILABLE",
        "from_return_path": "NOT_AVAILABLE"
    }

    if from_email and reply_email:

        from_domain = from_email.split("@")[-1].lower()
        reply_domain = reply_email.split("@")[-1].lower()

        if from_domain == reply_domain:
            sender_consistency["from_reply_to"] = "MATCH"
        else:
            sender_consistency["from_reply_to"] = "MISMATCH"

    if from_email and return_email:

        from_domain = from_email.split("@")[-1].lower()
        return_domain = return_email.split("@")[-1].lower()

        if from_domain == return_domain:
            sender_consistency["from_return_path"] = "MATCH"
        else:
            sender_consistency["from_return_path"] = "MISMATCH"

    # --------------------------------------------------------
    # RAW TEXT
    # --------------------------------------------------------

    full_text = raw_email.decode(
        "utf-8",
        errors="ignore"
    )

    # --------------------------------------------------------
    # IP EXTRACTION
    # --------------------------------------------------------

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    ips = sorted(
        set(
            re.findall(
                ip_pattern,
                full_text
            )
        )
    )

    # --------------------------------------------------------
    # URL EXTRACTION
    # --------------------------------------------------------

    url_pattern = r'https?://[^\s<>"\']+'

    urls = sorted(
        set(
            re.findall(
                url_pattern,
                full_text
            )
        )
    )

    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    url_details = []

    http_urls = []
    https_urls = []
    at_symbol_urls = []
    url_domains = set()

    for url in urls:

        scheme_match = re.match(
            r"^(https?)://",
            url,
            flags=re.IGNORECASE
        )

        if scheme_match:
            scheme = scheme_match.group(1).lower()
        else:
            scheme = "unknown"

        domain_match = re.search(
            r"^https?://([^/:?#]+)",
            url,
            flags=re.IGNORECASE
        )

        if domain_match:
            domain = domain_match.group(1).lower()
            url_domains.add(domain)
        else:
            domain = None

        contains_at_symbol = "@" in url

        if scheme == "http":
            http_urls.append(url)

        elif scheme == "https":
            https_urls.append(url)

        if contains_at_symbol:
            at_symbol_urls.append(url)

        url_details.append({
            "url": url,
            "scheme": scheme,
            "domain": domain,
            "contains_at_symbol": contains_at_symbol
        })

    # --------------------------------------------------------
    # DOMAIN EXTRACTION
    # --------------------------------------------------------

    email_pattern = r'[\w\.-]+@([\w\.-]+\.\w+)'

    domains = sorted(
        set(
            re.findall(
                email_pattern,
                full_text
            )
        )
    )

    # Include URL domains
    domains = sorted(
        set(domains) | url_domains
    )

    # --------------------------------------------------------
    # ATTACHMENT ANALYSIS
    # --------------------------------------------------------

    attachments = []

    for part in message.walk():

        filename = part.get_filename()

        if filename:

            try:

                payload = part.get_payload(
                    decode=True
                )

                if payload is None:
                    payload = b""

                attachment_hash = hashlib.sha256(
                    payload
                ).hexdigest()

                attachment_size = len(payload)

            except Exception:

                attachment_hash = None
                attachment_size = 0

            attachments.append({
                "filename": filename,
                "mime_type": part.get_content_type(),
                "size": attachment_size,
                "sha256": attachment_hash
            })

    # --------------------------------------------------------
    # RELAY PATH
    # --------------------------------------------------------

    # One hop per Received header, oldest first. The hop
    # number is the header's position, so headers without a
    # connecting IP (e.g. "by"-only) leave a gap.

    relay_path = []

    for hop_number, received in enumerate(
        reversed(received_headers),
        start=1
    ):

        ip = extract_received_ip(received)

        if not ip:
            continue

        relay_path.append({
            "hop": hop_number,
            "ip": ip,
            "classification": classify_ip(ip),
            "may_be_forged": "forged" in received.lower(),
            "raw": received
        })

    # Webmail clients often record the sender's own IP here.
    # It precedes every Received hop, so it is hop 0.

    for header_name in ("X-Originating-IP", "X-Sender-IP"):

        ip = parse_ip(str(message.get(header_name) or ""))

        if ip:
            relay_path.insert(0, {
                "hop": 0,
                "ip": ip,
                "classification": classify_ip(ip),
                "may_be_forged": False,
                "raw": f"{header_name}: {message.get(header_name)}"
            })
            break

    # Public infrastructure = public relay IPs in hop order.
    # IPs from the body or URLs are indicators, not routing.

    public_ips = list(dict.fromkeys(
        hop["ip"]
        for hop in relay_path
        if hop["classification"] == "PUBLIC"
    ))

    # --------------------------------------------------------
    # SECURITY SIGNALS
    # --------------------------------------------------------

    signals = []

    if http_urls:

        signals.append({
            "type": "HTTP_URLS",
            "severity": "LOW",
            "description": (
                f"{len(http_urls)} URL(s) "
                "use HTTP instead of HTTPS."
            ),
            "count": len(http_urls)
        })

    if at_symbol_urls:

        signals.append({
            "type": "URL_AT_SYMBOL",
            "severity": "MEDIUM",
            "description": (
                f"{len(at_symbol_urls)} URL(s) "
                "contain an @ character."
            ),
            "count": len(at_symbol_urls)
        })

    if (
        sender_consistency["from_reply_to"]
        == "MISMATCH"
    ):

        signals.append({
            "type": "FROM_REPLY_TO_MISMATCH",
            "severity": "MEDIUM",
            "description": (
                "From and Reply-To domains do not match."
            ),
            "count": 1
        })

    if (
        sender_consistency["from_return_path"]
        == "MISMATCH"
    ):

        signals.append({
            "type": "FROM_RETURN_PATH_MISMATCH",
            "severity": "MEDIUM",
            "description": (
                "From and Return-Path domains do not match."
            ),
            "count": 1
        })

    # --------------------------------------------------------
    # EVIDENCE HASH
    # --------------------------------------------------------

    sha256_hash = hashlib.sha256(
        raw_email
    ).hexdigest()

    # --------------------------------------------------------
    # TIMESTAMP
    # --------------------------------------------------------

    analysis_timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    # --------------------------------------------------------
    # FINAL STRUCTURED ANALYSIS
    # --------------------------------------------------------

    security_analysis = {

        "tool": "MailTraceAI",

        "analysis_version": "2.0",

        "analysis_timestamp": analysis_timestamp,

        "email_file": str(email_file),

        "evidence": {
            "original_email_sha256": sha256_hash
        },

        "identity": {

            "from": from_header,

            "from_email": from_email,

            "to": to_header,

            "cc": cc_header,

            "reply_to": reply_to,

            "return_path": return_path,

            "subject": subject,

            "message_id": message_id,

            "date": date_header,

            "date_utc_offset": extract_utc_offset(date_header)
        },

        "routing": {

            "received_header_count":
                len(received_headers),

            "received_headers":
                received_headers,

            "relay_path":
                relay_path,

            "ips": [

                {
                    "ip": ip,
                    "classification":
                        classify_ip(ip)
                }

                for ip in ips
                if classify_ip(ip) != "INVALID"
            ],

            "public_infrastructure_ips":
                public_ips
        },

        "authentication": {

            "authentication_results":
                authentication_results,

            "spf":
                spf_status,

            "dkim":
                dkim_status,

            "dmarc":
                dmarc_status,

            "arc":
                arc_status
        },

        "sender_consistency":
            sender_consistency,

        "urls": {

            "total":
                len(urls),

            "http_count":
                len(http_urls),

            "https_count":
                len(https_urls),

            "at_symbol_count":
                len(at_symbol_urls),

            "details":
                url_details,

            "domains":
                sorted(url_domains)
        },

        "domains":
            domains,

        "attachments": {

            "count":
                len(attachments),

            "items":
                attachments
        },

        "security_signals": {

            "total":
                len(signals),

            "signals":
                signals
        }
    }

    return security_analysis


# ============================================================
# 5. SAVE SECURITY ANALYSIS
# ============================================================

def save_security_analysis(
    security_analysis,
    output_file=None
):

    if output_file is None:
        output_file = (
            BASE_DIR /
            "security_analysis.json"
        )

    output_file = Path(output_file)

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            security_analysis,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_file


# ============================================================
# 6. PRINT TERMINAL REPORT
# ============================================================

def print_security_analysis(
    security_analysis
):

    print()

    print("=" * 60)
    print("MAILTRACEAI - SECURITY ANALYSIS")
    print("=" * 60)

    # --------------------------------------------------------
    # IDENTITY
    # --------------------------------------------------------

    identity = security_analysis["identity"]

    print()
    print("IDENTITY")
    print("=" * 60)

    print("\nFrom:")
    print(identity["from"])

    print("\nTo:")
    print(identity["to"])

    print("\nReply-To:")
    print(identity["reply_to"])

    print("\nReturn-Path:")
    print(identity["return_path"])

    print("\nSubject:")
    print(identity["subject"])

    print("\nMessage-ID:")
    print(identity["message_id"])

    # --------------------------------------------------------
    # ROUTING
    # --------------------------------------------------------

    routing = security_analysis["routing"]

    print()
    print("=" * 60)
    print("ROUTING ANALYSIS")
    print("=" * 60)

    print(
        "\nReceived headers:",
        routing["received_header_count"]
    )

    for index, received in enumerate(
        routing["received_headers"],
        start=1
    ):

        print()
        print(
            f"--- Received #{index} ---"
        )

        print(received)

    # --------------------------------------------------------
    # RELAY PATH
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("RELAY PATH")
    print("=" * 60)

    relay_path = routing["relay_path"]

    if relay_path:

        for hop in relay_path:

            print(
                f"Hop {hop['hop']}: "
                f"{hop['ip']} "
                f"[{hop['classification']}]"
            )

    else:

        print(
            "No relay information available."
        )

    # --------------------------------------------------------
    # PUBLIC INFRASTRUCTURE
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("PUBLIC INFRASTRUCTURE")
    print("=" * 60)

    public_ips = routing[
        "public_infrastructure_ips"
    ]

    if public_ips:

        for ip in public_ips:
            print(
                f"Public IP: {ip}"
            )

    else:

        print(
            "No public infrastructure IPs found."
        )

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    authentication = (
        security_analysis["authentication"]
    )

    print()
    print("=" * 60)
    print("AUTHENTICATION")
    print("=" * 60)

    print(
        "\nAuthentication-Results:"
    )

    if authentication[
        "authentication_results"
    ]:

        print(
            authentication[
                "authentication_results"
            ]
        )

    else:

        print("Not available")

    print(
        "\nSPF:",
        authentication["spf"]
    )

    print(
        "DKIM:",
        authentication["dkim"]
    )

    print(
        "DMARC:",
        authentication["dmarc"]
    )

    print(
        "ARC:",
        authentication["arc"]
    )

    # --------------------------------------------------------
    # SENDER CONSISTENCY
    # --------------------------------------------------------

    consistency = (
        security_analysis[
            "sender_consistency"
        ]
    )

    print()
    print("=" * 60)
    print("SENDER CONSISTENCY")
    print("=" * 60)

    print(
        "\nFrom vs Reply-To:",
        consistency["from_reply_to"]
    )

    print(
        "From vs Return-Path:",
        consistency["from_return_path"]
    )

    # --------------------------------------------------------
    # URL ANALYSIS
    # --------------------------------------------------------

    urls = security_analysis["urls"]

    print()
    print("=" * 60)
    print("URL ANALYSIS")
    print("=" * 60)

    print(
        "\nURLs found:",
        urls["total"]
    )

    for detail in urls["details"]:

        print("\nURL:")
        print(detail["url"])

        print(
            "Scheme:",
            detail["scheme"]
        )

        print(
            "Domain:",
            detail["domain"]
        )

        if detail["scheme"] == "http":

            print(
                "Warning: URL uses "
                "unencrypted HTTP"
            )

        if detail["contains_at_symbol"]:

            print(
                "Warning: URL contains @ character"
            )

    # --------------------------------------------------------
    # IP ANALYSIS
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("IP ANALYSIS")
    print("=" * 60)

    ips = routing["ips"]

    print(
        "\nIPs found:",
        len(ips)
    )

    for item in ips:

        print(
            f"- {item['ip']} "
            f"-> {item['classification']}"
        )

    # --------------------------------------------------------
    # DOMAIN ANALYSIS
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("DOMAIN ANALYSIS")
    print("=" * 60)

    domains = security_analysis[
        "domains"
    ]

    print(
        "\nDomains found:",
        len(domains)
    )

    for domain in domains:

        print(
            "-",
            domain
        )

    # --------------------------------------------------------
    # ATTACHMENTS
    # --------------------------------------------------------

    attachments = (
        security_analysis[
            "attachments"
        ]
    )

    print()
    print("=" * 60)
    print("ATTACHMENT ANALYSIS")
    print("=" * 60)

    print(
        "\nAttachments found:",
        attachments["count"]
    )

    if attachments["items"]:

        for attachment in attachments[
            "items"
        ]:

            print(
                "-",
                attachment["filename"]
            )

            print(
                "  MIME:",
                attachment["mime_type"]
            )

            print(
                "  Size:",
                attachment["size"],
                "bytes"
            )

            print(
                "  SHA-256:",
                attachment["sha256"]
            )

    else:

        print(
            "No attachments found."
        )

    # --------------------------------------------------------
    # SECURITY SUMMARY
    # --------------------------------------------------------

    signals = (
        security_analysis[
            "security_signals"
        ]
    )

    print()
    print("=" * 60)
    print("SECURITY SUMMARY")
    print("=" * 60)

    print(
        "\nTotal security signals:",
        signals["total"]
    )

    if signals["signals"]:

        for index, signal in enumerate(
            signals["signals"],
            start=1
        ):

            print()

            print(
                f"{index}. "
                f"[{signal['severity']}] "
                f"{signal['type']}"
            )

            print(
                "   ",
                signal["description"]
            )

    else:

        print(
            "\nNo security signals detected."
        )

    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("EVIDENCE INTEGRITY")
    print("=" * 60)

    print(
        "\nOriginal email SHA-256:"
    )

    print(
        security_analysis[
            "evidence"
        ]["original_email_sha256"]
    )

    print(
        "\nThis hash identifies the exact "
        "email bytes analyzed by MailTraceAI."
    )


# ============================================================
# 7. STANDALONE EXECUTION
# ============================================================

if __name__ == "__main__":

    EMAIL_FILE = (
        BASE_DIR /
        "samples" /
        "spam_test"
    )

    security_analysis = analyze_email(
        EMAIL_FILE
    )

    print_security_analysis(
        security_analysis
    )

    output_file = save_security_analysis(
        security_analysis
    )

    print()
    print("=" * 60)
    print("STRUCTURED OUTPUT")
    print("=" * 60)

    print(
        "\nSecurity analysis saved to:"
    )

    print(output_file)

    print()
    print("=" * 60)
    print("SECURITY ANALYSIS COMPLETE")
    print("=" * 60)