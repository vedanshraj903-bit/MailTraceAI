from pathlib import Path
from datetime import datetime, timezone
import json

from joblib import load

from Parser.email_parser import parse_email
from Parser.security_analyzer import analyze_email
from model.features import MIN_BODY_CHARS, body_length, build_model_text
from model.verdict import label_from_probabilities
from Risk.trusted_senders import check_sender


# ============================================================
# 1. PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_FILE = (
    BASE_DIR
    / "model"
    / "mailtraceai_detector.joblib"
)

THREAT_INTEL_FILE = (
    BASE_DIR
    / "threat_intelligence.json"
)

OUTPUT_FILE = (
    BASE_DIR
    / "risk_assessment.json"
)


# ============================================================
# 2. LOAD ML MODEL
# ============================================================

def load_model():

    return load(MODEL_FILE)


# ============================================================
# 3. BUILD ML INPUT
# ============================================================

def build_ml_input(parsed_email):
    """
    Must match training exactly, so it goes through the same
    model/features.py function used by model/build_dataset.py.
    """

    body_data = (
        parsed_email.get("body")
        or {}
    )

    if isinstance(body_data, dict):
        plain_text = body_data.get("plain_text") or ""
        html = body_data.get("html") or ""
    else:
        plain_text = str(body_data)
        html = ""

    return build_model_text(
        subject=parsed_email.get("subject") or "",
        sender=parsed_email.get("from") or "",
        reply_to=parsed_email.get("reply_to") or "",
        plain_text=plain_text,
        html=html,
    )


# ============================================================
# 4. ML PREDICTION
# ============================================================

def run_ml_detection(parsed_email, model):

    email_text = build_ml_input(
        parsed_email
    )

    prediction = model.predict(
        [email_text]
    )[0]

    probabilities = model.predict_proba(
        [email_text]
    )[0]

    classes = model.classes_

    class_probabilities = dict(
        zip(
            classes,
            probabilities
        )
    )

    spam_probability = float(
        class_probabilities.get(
            "spam",
            0
        )
    )

    ham_probability = float(
        class_probabilities.get(
            "ham",
            0
        )
    )

    phishing_probability = float(
        class_probabilities.get(
            "phishing",
            0
        )
    )

    # Anything that is not a genuine email.
    threat_probability = 1.0 - ham_probability

    # Too little text to judge (e.g. a one-word body): the model
    # never saw emails like this in training.
    low_information = body_length(email_text) < MIN_BODY_CHARS

    ml_confidence = float(
        max(probabilities)
    )

    return {
        # Shown label from the phishing / spam probabilities
        # (model/verdict.py). model_prediction is the model's own
        # most-likely class, kept for reference.
        "prediction": label_from_probabilities(
            phishing_probability,
            spam_probability
        ),
        "model_prediction": str(prediction),
        "confidence": ml_confidence,
        "spam_probability": spam_probability,
        "phishing_probability": phishing_probability,
        "threat_probability": threat_probability,
        "ham_probability": ham_probability,
        "low_information": low_information
    }


# ============================================================
# 5. THREAT INTELLIGENCE STATUS
# ============================================================

def determine_threat_intel_status(
    threat_intel_data
):

    if not threat_intel_data:
        return "NOT_AVAILABLE"

    ti_ip_results = (
        threat_intel_data
        .get("ip_intelligence", {})
        .get("results", [])
    )

    ti_domain_results = (
        threat_intel_data
        .get("domain_intelligence", {})
        .get("results", [])
    )

    ti_url_results = (
        threat_intel_data
        .get("url_intelligence", {})
        .get("results", [])
    )

    ti_statuses = []

    for result in ti_ip_results:

        ti_statuses.append(
            result
            .get("virustotal", {})
            .get("status")
        )

        ti_statuses.append(
            result
            .get("abuseipdb", {})
            .get("status")
        )

    for result in ti_domain_results:

        ti_statuses.append(
            result
            .get("virustotal", {})
            .get("status")
        )

    for result in ti_url_results:

        ti_statuses.append(
            result
            .get("virustotal", {})
            .get("status")
        )

    ti_statuses = [
        status
        for status in ti_statuses
        if status
    ]

    if not ti_statuses:

        return "NO_IOCS"

    if all(
        status == "NOT_CONFIGURED"
        for status in ti_statuses
    ):

        return "NOT_CONFIGURED"

    if "FOUND" in ti_statuses:

        return "AVAILABLE"

    return "PARTIAL"


# ============================================================
# 6. VIRUSTOTAL HELPER
# ============================================================

def get_vt_malicious_count(vt_result):

    if vt_result.get("status") != "FOUND":
        return None

    stats = vt_result.get(
        "last_analysis_stats",
        {}
    )

    return stats.get(
        "malicious",
        0
    )


# ============================================================
# 7. CALCULATE RISK
# ============================================================

def calculate_risk(
    parsed_email,
    security_data,
    threat_intel_data=None
):

    # --------------------------------------------------------
    # ML
    # --------------------------------------------------------

    model = load_model()

    ml_detection = run_ml_detection(
        parsed_email,
        model
    )

    prediction = ml_detection[
        "prediction"
    ]

    # Sender verification runs for every email. Only a TRUSTED
    # sender (authenticated bank / payments domain) overrides the
    # wording-based ML verdict (see Risk/trusted_senders.py).
    # Other checks still run.
    sender_verification = check_sender(security_data)

    trusted_sender = sender_verification["status"] == "TRUSTED"

    if trusted_sender:
        prediction = "ham"

    ml_confidence = ml_detection[
        "confidence"
    ]

    spam_probability = ml_detection[
        "spam_probability"
    ]

    ham_probability = ml_detection[
        "ham_probability"
    ]

    phishing_probability = ml_detection[
        "phishing_probability"
    ]

    threat_probability = ml_detection[
        "threat_probability"
    ]

    # --------------------------------------------------------
    # INITIAL SCORE
    # --------------------------------------------------------

    risk_score = 0

    risk_reasons = []

    # ========================================================
    # 1. ML EVIDENCE
    # ========================================================

    # Points follow the shown label (model/verdict.py). A confident
    # phishing verdict alone reaches MEDIUM RISK; one independent
    # red flag on top of it reaches HIGH RISK. Spam is unwanted but
    # rarely dangerous, so it only adds a little.

    ml_points = {
        "phishing": (
            (60, "HIGH_PHISHING_PROBABILITY")
            if phishing_probability >= 0.90
            else (50, "ELEVATED_PHISHING_PROBABILITY")
        ),
        "spam": (15, "SPAM_CLASSIFICATION"),
        "ham": (0, None),
    }

    if trusted_sender:

        risk_reasons.append({

            "source": "SENDER_VERIFICATION",

            "type":
                "TRUSTED_SENDER",

            "points":
                0,

            "description":
                sender_verification["reason"]
                + f" ML phishing score "
                  f"({phishing_probability * 100:.2f}%) not applied."
        })

    elif ml_detection["low_information"]:

        risk_reasons.append({

            "source": "ML",

            "type":
                "ML_INSUFFICIENT_TEXT",

            "points":
                0,

            "description":
                "Email body is too short for the ML model to "
                "judge reliably; ML score not applied."
        })

    else:

        points, reason_type = ml_points[prediction]

        if points:

            risk_score += points

            risk_reasons.append({

                "source": "ML",

                "type":
                    reason_type,

                "points":
                    points,

                "description":
                    f"ML model classifies this email as "
                    f"{prediction} "
                    f"(phishing probability "
                    f"{phishing_probability * 100:.2f}%)."
            })

    # ========================================================
    # 2. SECURITY SIGNALS
    # ========================================================

    security_signals = (
        security_data
        .get("security_signals", {})
        .get("signals", [])
    )

    for signal in security_signals:

        signal_type = signal.get(
            "type"
        )

        points = 0

        if signal_type == "HTTP_URLS":

            points = 5

        elif signal_type == "URL_AT_SYMBOL":

            points = 10

        # FROM_REPLY_TO_MISMATCH / FROM_RETURN_PATH_MISMATCH are
        # scored once, in SENDER CONSISTENCY below.

        if points > 0:

            risk_score += points

            risk_reasons.append({

                "source":
                    "SECURITY_ANALYZER",

                "type":
                    signal_type,

                "points":
                    points,

                "description":
                    signal.get(
                        "description"
                    )
            })

    # ========================================================
    # 3. AUTHENTICATION
    # ========================================================

    authentication = (
        security_data
        .get("authentication", {})
    )

    spf = authentication.get(
        "spf"
    )

    dkim = authentication.get(
        "dkim"
    )

    dmarc = authentication.get(
        "dmarc"
    )

    # Missing results (NOT_AVAILABLE) score nothing: many exported
    # emails simply lack an Authentication-Results header.

    auth_points = [
        ("SPF", spf, {"FAIL": 15, "SOFTFAIL": 5}),
        ("DKIM", dkim, {"FAIL": 10}),
        ("DMARC", dmarc, {"FAIL": 20}),
    ]

    for mechanism, result, table in auth_points:

        points = table.get(result, 0)

        if not points:
            continue

        risk_score += points

        risk_reasons.append({

            "source":
                "AUTHENTICATION",

            "type":
                f"{mechanism}_{result}",

            "points":
                points,

            "description":
                f"{mechanism} result is {result}."
        })

    authentication_failed = (
        spf in ("FAIL", "SOFTFAIL")
        or dkim == "FAIL"
        or dmarc == "FAIL"
    )

    # ========================================================
    # 4. SENDER CONSISTENCY
    # ========================================================

    sender_consistency = (
        security_data
        .get("sender_consistency", {})
    )

    from_reply_to = sender_consistency.get(
        "from_reply_to"
    )

    from_return_path = sender_consistency.get(
        "from_return_path"
    )

    if from_reply_to == "MISMATCH":

        points = 15

        risk_score += points

        risk_reasons.append({

            "source":
                "SENDER_CONSISTENCY",

            "type":
                "FROM_REPLY_TO_MISMATCH",

            "points":
                points,

            "description":
                "Replies go to a different domain than the sender's."
        })

    # A different Return-Path domain is normal for genuine bulk mail
    # (banks and newsletters send through Amazon SES, SendGrid, ...),
    # so it only counts when authentication also failed.

    if from_return_path == "MISMATCH":

        points = 10 if authentication_failed else 0

        risk_score += points

        risk_reasons.append({

            "source":
                "SENDER_CONSISTENCY",

            "type":
                "FROM_RETURN_PATH_MISMATCH",

            "points":
                points,

            "description":
                "From and Return-Path domains do not match"
                + (
                    " and authentication failed."
                    if authentication_failed
                    else " (common for bulk mail senders; "
                         "not scored on its own)."
                )
        })

    # ========================================================
    # 5. ATTACHMENTS
    # ========================================================

    attachments = (
        security_data
        .get("attachments", {})
    )

    attachment_count = attachments.get(
        "count",
        0
    )

    if attachment_count > 0:

        points = 5

        risk_score += points

        risk_reasons.append({

            "source":
                "ATTACHMENT_ANALYSIS",

            "type":
                "ATTACHMENT_PRESENT",

            "points":
                points,

            "description":
                f"{attachment_count} "
                f"attachment(s) detected. "
                f"Presence alone is not proof "
                f"of maliciousness."
        })

    # ========================================================
    # 6. THREAT INTELLIGENCE
    # ========================================================

    if threat_intel_data:

        ti_ip_results = (
            threat_intel_data
            .get("ip_intelligence", {})
            .get("results", [])
        )

        ti_domain_results = (
            threat_intel_data
            .get("domain_intelligence", {})
            .get("results", [])
        )

        ti_url_results = (
            threat_intel_data
            .get("url_intelligence", {})
            .get("results", [])
        )

    else:

        ti_ip_results = []
        ti_domain_results = []
        ti_url_results = []

    # --------------------------------------------------------
    # IP INTELLIGENCE
    # --------------------------------------------------------

    for result in ti_ip_results:

        ip = result.get("ip")

        vt = result.get(
            "virustotal",
            {}
        )

        abuse = result.get(
            "abuseipdb",
            {}
        )

        malicious_count = (
            get_vt_malicious_count(vt)
        )

        if (
            malicious_count is not None
            and malicious_count > 0
        ):

            points = min(
                25,
                malicious_count * 5
            )

            risk_score += points

            risk_reasons.append({

                "source":
                    "VIRUSTOTAL",

                "type":
                    "MALICIOUS_IP",

                "indicator":
                    ip,

                "points":
                    points,

                "description":
                    f"VirusTotal reports "
                    f"{malicious_count} "
                    f"malicious detection(s) "
                    f"for IP {ip}."
            })

        abuse_score = abuse.get(
            "abuse_confidence_score"
        )

        if (
            isinstance(
                abuse_score,
                (int, float)
            )
            and abuse_score >= 50
        ):

            points = 20

            risk_score += points

            risk_reasons.append({

                "source":
                    "ABUSEIPDB",

                "type":
                    "HIGH_ABUSE_CONFIDENCE",

                "indicator":
                    ip,

                "points":
                    points,

                "description":
                    f"AbuseIPDB abuse "
                    f"confidence score is "
                    f"{abuse_score}."
            })

    # --------------------------------------------------------
    # DOMAIN INTELLIGENCE
    # --------------------------------------------------------

    for result in ti_domain_results:

        domain = result.get(
            "domain"
        )

        vt = result.get(
            "virustotal",
            {}
        )

        malicious_count = (
            get_vt_malicious_count(vt)
        )

        if (
            malicious_count is not None
            and malicious_count > 0
        ):

            points = min(
                20,
                malicious_count * 5
            )

            risk_score += points

            risk_reasons.append({

                "source":
                    "VIRUSTOTAL",

                "type":
                    "MALICIOUS_DOMAIN",

                "indicator":
                    domain,

                "points":
                    points,

                "description":
                    f"VirusTotal reports "
                    f"{malicious_count} "
                    f"malicious detection(s) "
                    f"for domain {domain}."
            })

    # --------------------------------------------------------
    # URL INTELLIGENCE
    # --------------------------------------------------------

    for result in ti_url_results:

        url_value = result.get(
            "url"
        )

        vt = result.get(
            "virustotal",
            {}
        )

        malicious_count = (
            get_vt_malicious_count(vt)
        )

        if (
            malicious_count is not None
            and malicious_count > 0
        ):

            points = min(
                25,
                malicious_count * 5
            )

            risk_score += points

            risk_reasons.append({

                "source":
                    "VIRUSTOTAL",

                "type":
                    "MALICIOUS_URL",

                "indicator":
                    url_value,

                "points":
                    points,

                "description":
                    f"VirusTotal reports "
                    f"{malicious_count} "
                    f"malicious detection(s) "
                    f"for URL."
            })

    # ========================================================
    # CAP SCORE
    # ========================================================

    risk_score = min(
        risk_score,
        100
    )

    # ========================================================
    # VERDICT
    # ========================================================

    if risk_score >= 75:

        verdict = "HIGH RISK"

    elif risk_score >= 50:

        verdict = "MEDIUM RISK"

    elif risk_score >= 25:

        verdict = "LOW RISK"

    else:

        verdict = "MINIMAL RISK"

    # ========================================================
    # THREAT INTELLIGENCE STATUS
    # ========================================================

    threat_intel_status = (
        determine_threat_intel_status(
            threat_intel_data
        )
    )

    # ========================================================
    # BUILD RESULT
    # ========================================================

    return {

        "tool":
            "MailTraceAI",

        "risk_engine_version":
            "3.1",

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
                .get("evidence", {})
                .get(
                    "original_email_sha256"
                )
        },

        "sender_verification":
            sender_verification,

        "ml_detection": {

            "prediction":
                prediction,

            "model_prediction":
                ml_detection["model_prediction"],


            "confidence":
                ml_confidence,

            "spam_probability":
                spam_probability,

            "phishing_probability":
                phishing_probability,

            "threat_probability":
                threat_probability,

            "ham_probability":
                ham_probability,

            "low_information":
                ml_detection["low_information"]
        },

        "threat_intelligence": {

            "status":
                threat_intel_status,

            "ips_checked":
                len(ti_ip_results),

            "domains_checked":
                len(ti_domain_results),

            "urls_checked":
                len(ti_url_results)
        },

        "risk": {

            "score":
                risk_score,

            "verdict":
                verdict,

            "reasons":
                risk_reasons
        }
    }


# ============================================================
# 8. LOAD THREAT INTELLIGENCE
# ============================================================

def load_threat_intelligence():

    if not THREAT_INTEL_FILE.exists():

        return None

    try:

        with open(
            THREAT_INTEL_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (
        json.JSONDecodeError,
        OSError
    ):

        return None


# ============================================================
# 9. SAVE RISK ASSESSMENT
# ============================================================

def save_risk_assessment(
    risk_assessment,
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
    ) as file:

        json.dump(
            risk_assessment,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_file


# ============================================================
# 10. TERMINAL REPORT
# ============================================================

def print_risk_assessment(
    risk_assessment
):

    ml = risk_assessment[
        "ml_detection"
    ]

    ti = risk_assessment[
        "threat_intelligence"
    ]

    risk = risk_assessment[
        "risk"
    ]

    print()

    print("=" * 60)
    print("MAILTRACEAI - RISK ENGINE V3")
    print("=" * 60)

    print()

    print(
        "Prediction:",
        ml["prediction"]
    )

    print(
        "ML Confidence:",
        f"{ml['confidence'] * 100:.2f}%"
    )

    print(
        "PHISHING Probability:",
        f"{ml['phishing_probability'] * 100:.2f}%"
    )

    print()

    print(
        "Threat Intelligence:",
        ti["status"]
    )

    print(
        "IPs checked:",
        ti["ips_checked"]
    )

    print(
        "Domains checked:",
        ti["domains_checked"]
    )

    print(
        "URLs checked:",
        ti["urls_checked"]
    )

    print()

    print("RISK REASONS")
    print("=" * 60)

    reasons = risk["reasons"]

    if reasons:

        for reason in reasons:

            print()

            print(
                f"[{reason['source']}] "
                f"{reason['type']}"
            )

            print(
                "Points:",
                reason["points"]
            )

            print(
                "Description:",
                reason["description"]
            )

    else:

        print(
            "No risk factors detected."
        )

    print()

    print("=" * 60)

    print(
        "RISK SCORE:",
        f"{risk['score']}/100"
    )

    print(
        "VERDICT:",
        risk["verdict"]
    )

    print("=" * 60)


# ============================================================
# 11. STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Test email
    # --------------------------------------------------------

    EMAIL_FILE = (
        BASE_DIR
        / "samples"
        / "spam_test"
    )

    # --------------------------------------------------------
    # Parse email
    # --------------------------------------------------------

    parsed_email = parse_email(
        EMAIL_FILE
    )

    # --------------------------------------------------------
    # Security analysis
    # --------------------------------------------------------

    security_data = analyze_email(
        EMAIL_FILE
    )

    # --------------------------------------------------------
    # Threat intelligence
    # --------------------------------------------------------

    threat_intel_data = (
        load_threat_intelligence()
    )

    # --------------------------------------------------------
    # Calculate risk
    # --------------------------------------------------------

    risk_assessment = calculate_risk(
        parsed_email,
        security_data,
        threat_intel_data
    )

    # --------------------------------------------------------
    # Save result
    # --------------------------------------------------------

    output_file = save_risk_assessment(
        risk_assessment
    )

    # --------------------------------------------------------
    # Print result
    # --------------------------------------------------------

    print_risk_assessment(
        risk_assessment
    )

    print()

    print(
        "Risk assessment saved to:"
    )

    print(output_file)

    print()

    print("=" * 60)
    print("RISK ENGINE V3 COMPLETE")
    print("=" * 60)