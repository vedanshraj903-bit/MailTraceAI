from email import policy
from email.parser import BytesParser
from pathlib import Path
from datetime import datetime, timezone
import re
import hashlib
import json


# ============================================================
# 1. PROJECT PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# 2. PARSE EMAIL FUNCTION
# ============================================================

def parse_email(email_file):
    """
    Parse an .eml file and return structured email information.
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

    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    # --------------------------------------------------------
    # BASIC EMAIL INFORMATION
    # --------------------------------------------------------

    email_data = {
        "from": message.get("From"),
        "to": message.get("To"),
        "cc": message.get("Cc"),
        "reply_to": message.get("Reply-To"),
        "return_path": message.get("Return-Path"),
        "subject": message.get("Subject"),
        "date": message.get("Date"),
        "message_id": message.get("Message-ID"),
    }

    # --------------------------------------------------------
    # COLLECT ALL HEADERS
    # --------------------------------------------------------

    headers = []

    for name, value in message.items():
        headers.append({
            "name": name,
            "value": str(value)
        })

    email_data["headers"] = headers

    # --------------------------------------------------------
    # EXTRACT RECEIVED HEADERS
    # --------------------------------------------------------

    received_headers = []

    for value in message.get_all("Received", []):
        received_headers.append(str(value))

    email_data["received"] = received_headers

    # --------------------------------------------------------
    # AUTHENTICATION INFORMATION
    # --------------------------------------------------------

    email_data["authentication"] = {
        "authentication_results": message.get("Authentication-Results"),
        "dkim_signature": message.get("DKIM-Signature"),
        "arc_seal": message.get("ARC-Seal"),
        "arc_message_signature": message.get(
            "ARC-Message-Signature"
        ),
        "arc_authentication_results": message.get(
            "ARC-Authentication-Results"
        ),
    }

    # --------------------------------------------------------
    # EXTRACT EMAIL BODY
    # --------------------------------------------------------

    plain_text = ""
    html_text = ""

    if message.is_multipart():

        for part in message.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":

                try:
                    plain_text += part.get_content()
                except Exception:
                    pass

            elif content_type == "text/html":

                try:
                    html_text += part.get_content()
                except Exception:
                    pass

    else:

        content_type = message.get_content_type()

        try:

            content = message.get_content()

            if content_type == "text/plain":
                plain_text = content

            elif content_type == "text/html":
                html_text = content

        except Exception:
            pass

    email_data["body"] = {
        "plain_text": plain_text,
        "html": html_text
    }

    # --------------------------------------------------------
    # EXTRACT IP ADDRESSES
    # --------------------------------------------------------

    full_text = raw_email.decode(
        "utf-8",
        errors="ignore"
    )

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
    # EXTRACT URLs
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
    # EXTRACT DOMAINS FROM EMAIL ADDRESSES
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

    email_data["indicators"] = {
        "ips": ips,
        "urls": urls,
        "domains": domains
    }

    # --------------------------------------------------------
    # ATTACHMENT INFORMATION
    # --------------------------------------------------------

    attachments = []

    for part in message.walk():

        filename = part.get_filename()

        if filename:

            try:

                payload = part.get_payload(
                    decode=True
                )

                if payload:

                    file_hash = hashlib.sha256(
                        payload
                    ).hexdigest()

                    file_size = len(payload)

                else:

                    file_hash = None
                    file_size = 0

            except Exception:

                file_hash = None
                file_size = 0

            attachments.append({
                "filename": filename,
                "mime_type": part.get_content_type(),
                "size": file_size,
                "sha256": file_hash
            })

    email_data["attachments"] = attachments

    # --------------------------------------------------------
    # HASH ORIGINAL EMAIL + PARSER TIMESTAMP
    # --------------------------------------------------------

    email_hash = hashlib.sha256(
        raw_email
    ).hexdigest()

    parser_timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    email_data["evidence"] = {
        "original_email_sha256": email_hash,
        "parser_timestamp": parser_timestamp
    }

    # --------------------------------------------------------
    # RETURN STRUCTURED DATA
    # --------------------------------------------------------

    return email_data


# ============================================================
# 3. PRINT EMAIL ANALYSIS
# ============================================================

def print_email_analysis(email_data):

    print("\n" + "=" * 60)
    print("MAILTRACEAI - EMAIL ANALYSIS")
    print("=" * 60)

    print("\n[IDENTITY]")

    print("From:", email_data["from"])
    print("To:", email_data["to"])
    print("Cc:", email_data["cc"])
    print("Reply-To:", email_data["reply_to"])
    print("Return-Path:", email_data["return_path"])
    print("Subject:", email_data["subject"])
    print("Date:", email_data["date"])
    print("Message-ID:", email_data["message_id"])

    print("\n[ROUTING]")

    received_headers = email_data["received"]

    print(
        "Received headers:",
        len(received_headers)
    )

    for i, received in enumerate(
        received_headers,
        start=1
    ):

        print(f"\n--- Received #{i} ---")
        print(received)

    print("\n[AUTHENTICATION]")

    authentication = email_data[
        "authentication"
    ]

    print(
        "Authentication-Results:",
        authentication[
            "authentication_results"
        ]
    )

    print(
        "DKIM-Signature:",
        "Present"
        if authentication["dkim_signature"]
        else "Not available"
    )

    print(
        "ARC:",
        "Present"
        if authentication["arc_seal"]
        else "Not available"
    )

    print("\n[INDICATORS]")

    print(
        "IPs:",
        email_data["indicators"]["ips"]
    )

    print(
        "Domains:",
        email_data["indicators"]["domains"]
    )

    print("\nURLs:")

    for url in email_data["indicators"]["urls"]:
        print(" ", url)

    print("\n[ATTACHMENTS]")

    attachments = email_data["attachments"]

    if attachments:

        for attachment in attachments:

            print(
                f"{attachment['filename']} | "
                f"{attachment['mime_type']} | "
                f"{attachment['size']} bytes | "
                f"{attachment['sha256']}"
            )

    else:

        print("No attachments found.")

    print("\n[EVIDENCE]")

    print(
        "SHA-256:",
        email_data[
            "evidence"
        ]["original_email_sha256"]
    )

    print(
        "Parser Timestamp:",
        email_data[
            "evidence"
        ]["parser_timestamp"]
    )

    print("\n" + "=" * 60)


# ============================================================
# 4. SAVE STRUCTURED RESULT
# ============================================================

def save_email_analysis(
    email_data,
    output_file=None
):

    if output_file is None:
        output_file = (
            BASE_DIR /
            "parsed_email.json"
        )

    output_file = Path(output_file)

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            email_data,
            file,
            indent=4,
            ensure_ascii=False,
            default=str
        )

    return output_file


# ============================================================
# 5. STANDALONE EXECUTION
# ============================================================

if __name__ == "__main__":

    EMAIL_FILE = (
        BASE_DIR /
        "samples" /
        "1"
    )

    email_data = parse_email(
        EMAIL_FILE
    )

    print_email_analysis(
        email_data
    )

    output_file = save_email_analysis(
        email_data
    )

    print(
        "\nStructured analysis saved to:"
    )

    print(output_file)