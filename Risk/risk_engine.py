from pathlib import Path
from datetime import datetime, timezone
import json

from joblib import load

from Parser.email_parser import parse_email
from Parser.security_analyzer import analyze_email


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

    subject = (
        parsed_email.get("subject")
        or ""
    )

    sender = (
        parsed_email.get("from")
        or ""
    )

    reply_to = (
        parsed_email.get("reply_to")
        or ""
    )

    body_data = (
        parsed_email.get("body")
        or {}
    )

    if isinstance(body_data, dict):

        body = (
            body_data.get("plain_text")
            or ""
        )

        html_body = (
            body_data.get("html")
            or ""
        )

    else:

        body = str(body_data)
        html_body = ""

    email_text = (
        f"SUBJECT: {subject}\n"
        f"FROM: {sender}\n"
        f"REPLY-TO: {reply_to}\n"
        f"BODY: {body}\n"
        f"HTML: {html_body}"
    )

    return email_text


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

    ml_confidence = float(
        max(probabilities)
    )

    return {
        "prediction": str(prediction),
        "confidence": ml_confidence,
        "spam_probability": spam_probability,
        "ham_probability": ham_probability
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

    ml_confidence = ml_detection[
        "confidence"
    ]

    spam_probability = ml_detection[
        "spam_probability"
    ]

    ham_probability = ml_detection[
        "ham_probability"
    ]

    # --------------------------------------------------------
    # INITIAL SCORE
    # --------------------------------------------------------

    risk_score = 0

    risk_reasons = []

    # ========================================================
    # 1. ML EVIDENCE
    # ========================================================

    if spam_probability >= 0.90:

        points = 35

        risk_score += points

        risk_reasons.append({

            "source": "ML",

            "type":
                "HIGH_SPAM_PROBABILITY",

            "points":
                points,

            "description":
                f"ML model assigned "
                f"{spam_probability * 100:.2f}% "
                f"spam probability."
        })

    elif spam_probability >= 0.70:

        points = 28

        risk_score += points

        risk_reasons.append({

            "source": "ML",

            "type":
                "ELEVATED_SPAM_PROBABILITY",

            "points":
                points,

            "description":
                f"ML model assigned "
                f"{spam_probability * 100:.2f}% "
                f"spam probability."
        })

    elif spam_probability >= 0.50:

        points = 15

        risk_score += points

        risk_reasons.append({

            "source": "ML",

            "type":
                "MODERATE_SPAM_PROBABILITY",

            "points":
                points,

            "description":
                f"ML model assigned "
                f"{spam_probability * 100:.2f}% "
                f"spam probability."
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

        elif signal_type == "FROM_REPLY_TO_MISMATCH":

            points = 20

        elif signal_type == "FROM_RETURN_PATH_MISMATCH":

            points = 15

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

    # --------------------------------------------------------
    # SPF
    # --------------------------------------------------------

    if spf in [
        "FAIL",
        "SOFTFAIL",
        "NEUTRAL"
    ]:

        points = 10

        risk_score += points

        risk_reasons.append({

            "source":
                "AUTHENTICATION",

            "type":
                "SPF_" + spf,

            "points":
                points,

            "description":
                f"SPF result is {spf}."
        })

    # --------------------------------------------------------
    # DKIM
    # --------------------------------------------------------

    if dkim == "FAIL":

        points = 10

        risk_score += points

        risk_reasons.append({

            "source":
                "AUTHENTICATION",

            "type":
                "DKIM_FAIL",

            "points":
                points,

            "description":
                "DKIM authentication failed."
        })

    # --------------------------------------------------------
    # DMARC
    # --------------------------------------------------------

    if dmarc == "FAIL":

        points = 15

        risk_score += points

        risk_reasons.append({

            "source":
                "AUTHENTICATION",

            "type":
                "DMARC_FAIL",

            "points":
                points,

            "description":
                "DMARC authentication failed."
        })

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

        points = 20

        risk_score += points

        risk_reasons.append({

            "source":
                "SENDER_CONSISTENCY",

            "type":
                "FROM_REPLY_TO_MISMATCH",

            "points":
                points,

            "description":
                "From and Reply-To "
                "addresses do not match."
        })

    if from_return_path == "MISMATCH":

        points = 15

        risk_score += points

        risk_reasons.append({

            "source":
                "SENDER_CONSISTENCY",

            "type":
                "FROM_RETURN_PATH_MISMATCH",

            "points":
                points,

            "description":
                "From and Return-Path "
                "domains do not match."
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
                .get("evidence", {})
                .get(
                    "original_email_sha256"
                )
        },

        "ml_detection": {

            "prediction":
                prediction,

            "confidence":
                ml_confidence,

            "spam_probability":
                spam_probability,

            "ham_probability":
                ham_probability
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
        "SPAM Probability:",
        f"{ml['spam_probability'] * 100:.2f}%"
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