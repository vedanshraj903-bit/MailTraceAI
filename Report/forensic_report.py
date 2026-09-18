from pathlib import Path
from datetime import datetime, timezone
import html
import json


# ============================================================
# MAILTRACEAI FORENSIC REPORT GENERATOR
# ============================================================

REPORT_VERSION = "1.1"


# ============================================================
# HELPERS
# ============================================================

def safe(value, default="N/A"):
    if value is None:
        return default
    if isinstance(value, str) and not value.strip():
        return default
    return value


def escape(value):
    return html.escape(str(safe(value)))


def first_value(*values, default="N/A"):
    for value in values:
        if value is not None and not (
            isinstance(value, str) and not value.strip()
        ):
            return value
    return default


def normalize_list(value):
    if value is None:
        return []
    if isinstance(value, dict):
        return value.get("details", value.get("results", [])) or []
    if isinstance(value, list):
        return value
    return [value]


# ============================================================
# CASE SUMMARY
# ============================================================

def build_case_summary(analysis):
    parsed = analysis.get("parsed_email", {})
    security = analysis.get("security_analysis", {})
    risk_assessment = analysis.get("risk_assessment", {})
    risk = risk_assessment.get("risk", {})
    ml = risk_assessment.get("ml_detection", {})

    parsed_identity = parsed.get("identity", {})
    security_identity = security.get("identity", {})
    parsed_content = parsed.get("content", {})

    # Current parser stores these directly under parsed_email.
    sender = first_value(
        parsed_identity.get("from"),
        parsed.get("from"),
        security_identity.get("from"),
        security.get("from"),
    )

    recipient = first_value(
        parsed_identity.get("to"),
        parsed.get("to"),
        security_identity.get("to"),
        security.get("to"),
    )

    subject = first_value(
        parsed_identity.get("subject"),
        parsed.get("subject"),
        parsed_content.get("subject"),
        security_identity.get("subject"),
        security.get("subject"),
    )

    message_id = first_value(
        parsed_identity.get("message_id"),
        parsed.get("message_id"),
        security_identity.get("message_id"),
        security.get("message_id"),
    )

    prediction = first_value(
        ml.get("prediction"),
        risk_assessment.get("prediction"),
        analysis.get("prediction"),
    )

    spam_probability = first_value(
        ml.get("spam_probability"),
        risk_assessment.get("spam_probability"),
        analysis.get("spam_probability"),
        default=None,
    )

    return {
        "sender": safe(sender),
        "recipient": safe(recipient),
        "subject": safe(subject),
        "message_id": safe(message_id),
        "risk_score": first_value(
            risk.get("score"),
            risk_assessment.get("score"),
        ),
        "verdict": first_value(
            risk.get("verdict"),
            risk_assessment.get("verdict"),
        ),
        "prediction": safe(prediction),
        "confidence": ml.get("confidence"),
        "spam_probability": spam_probability,
    }


# ============================================================
# AUTHENTICATION
# ============================================================

def build_authentication_summary(analysis):
    security = analysis.get("security_analysis", {})
    authentication = security.get("authentication", {})
    parsed = analysis.get("parsed_email", {})
    parsed_auth = parsed.get("authentication", {})

    authentication_results = first_value(
        authentication.get("Authentication-Results"),
        authentication.get("authentication_results"),
        parsed_auth.get("Authentication-Results"),
        parsed_auth.get("authentication_results"),
        default="NOT_AVAILABLE",
    )

    return {
        "SPF": first_value(
            authentication.get("SPF"),
            authentication.get("spf"),
            parsed_auth.get("SPF"),
            parsed_auth.get("spf"),
            default="NOT_AVAILABLE",
        ),
        "DKIM": first_value(
            authentication.get("DKIM"),
            authentication.get("dkim"),
            parsed_auth.get("DKIM"),
            parsed_auth.get("dkim"),
            default="NOT_AVAILABLE",
        ),
        "DMARC": first_value(
            authentication.get("DMARC"),
            authentication.get("dmarc"),
            parsed_auth.get("DMARC"),
            parsed_auth.get("dmarc"),
            default="NOT_AVAILABLE",
        ),
        "ARC": first_value(
            authentication.get("ARC"),
            authentication.get("arc"),
            parsed_auth.get("ARC"),
            parsed_auth.get("arc"),
            default="NOT_AVAILABLE",
        ),
        "Authentication-Results": authentication_results,
    }


# ============================================================
# SECURITY FINDINGS
# ============================================================

def build_security_findings(analysis):
    security = analysis.get("security_analysis", {})
    security_signals = security.get("security_signals", {})

    if isinstance(security_signals, list):
        signals = security_signals
    else:
        signals = security_signals.get("signals", [])

    findings = []

    for signal in signals:
        if not isinstance(signal, dict):
            continue

        findings.append({
            "type": first_value(
                signal.get("type"),
                signal.get("signal"),
                default="N/A",
            ),
            "severity": first_value(
                signal.get("severity"),
                default="N/A",
            ),
            "description": first_value(
                signal.get("description"),
                signal.get("message"),
                default="N/A",
            ),
        })

    return findings


# ============================================================
# INDICATORS OF COMPROMISE
# ============================================================

def build_ioc_summary(analysis):
    security = analysis.get("security_analysis", {})
    parsed = analysis.get("parsed_email", {})
    routing = security.get("routing", {})

    public_ips = routing.get("public_infrastructure_ips", [])

    if not public_ips:
        public_ips = parsed.get("indicators", {}).get("ips", [])

    urls = security.get("urls", [])
    domains = security.get("domains", [])

    if not urls:
        urls = parsed.get("indicators", {}).get("urls", [])

    if not domains:
        domains = parsed.get("indicators", {}).get("domains", [])

    def normalize_items(items, keys):
        result = []
        for item in normalize_list(items):
            if isinstance(item, dict):
                value = first_value(
                    *(item.get(key) for key in keys),
                    default=None,
                )
                if value is not None:
                    result.append(value)
            elif item is not None:
                result.append(item)
        return result

    return {
        "ips": normalize_items(
            public_ips,
            ["ip", "value"],
        ),
        "domains": normalize_items(
            domains,
            ["domain", "value", "name"],
        ),
        "urls": normalize_items(
            urls,
            ["url", "value", "raw"],
        ),
    }


# ============================================================
# INFRASTRUCTURE / GEOLOCATION
# ============================================================

def build_infrastructure_summary(analysis):
    geolocation = normalize_list(
        analysis.get("geolocation", [])
    )

    infrastructure = []

    for item in geolocation:
        if not isinstance(item, dict):
            continue

        infrastructure.append({
            "ip": safe(item.get("ip")),
            "status": safe(item.get("status")),
            "country": safe(item.get("country")),
            "country_code": safe(item.get("country_code")),
            "continent": safe(item.get("continent")),
            "asn": safe(item.get("asn")),
            "asn_name": safe(item.get("asn_name")),
            "asn_domain": safe(item.get("asn_domain")),
        })

    return infrastructure


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

def build_threat_intelligence_summary(analysis):
    threat_intel = analysis.get(
        "threat_intelligence",
        {}
    )

    # The Risk Engine also stores a compact TI summary.
    risk_ti = analysis.get(
        "risk_assessment",
        {}
    ).get(
        "threat_intelligence",
        {}
    )

    ip_intel = threat_intel.get(
        "ip_intelligence",
        {}
    )

    domain_intel = threat_intel.get(
        "domain_intelligence",
        {}
    )

    url_intel = threat_intel.get(
        "url_intelligence",
        {}
    )

    ips_checked = first_value(
        ip_intel.get("total_ips_checked"),
        risk_ti.get("ips_checked"),
        default=0,
    )

    domains_checked = first_value(
        domain_intel.get("total_domains_checked"),
        risk_ti.get("domains_checked"),
        default=0,
    )

    urls_checked = first_value(
        url_intel.get("total_urls_checked"),
        risk_ti.get("urls_checked"),
        default=0,
    )

    status = first_value(
        threat_intel.get("status"),
        risk_ti.get("status"),
        default=None,
    )

    if status is None:
        statuses = []

        for group in (
            ip_intel,
            domain_intel,
            url_intel,
        ):
            for result in normalize_list(
                group.get("results", [])
            ):
                if not isinstance(result, dict):
                    continue

                for provider_value in result.values():
                    if isinstance(provider_value, dict):
                        provider_status = provider_value.get("status")
                        if provider_status:
                            statuses.append(provider_status)

        if statuses and all(
            s == "NOT_CONFIGURED" for s in statuses
        ):
            status = "NOT_CONFIGURED"
        elif statuses:
            status = "COMPLETE"
        else:
            status = "NO_RESULTS"

    return {
        "status": status,
        "ips_checked": ips_checked,
        "domains_checked": domains_checked,
        "urls_checked": urls_checked,
    }


# ============================================================
# INVESTIGATION GRAPH
# ============================================================

def build_investigation_summary(analysis):
    graph = analysis.get(
        "investigation_graph",
        {}
    )

    return {
        "graph_version": safe(
            graph.get("graph_version")
        ),
        "node_count": graph.get(
            "node_count",
            0
        ),
        "edge_count": graph.get(
            "edge_count",
            0
        ),
    }


# ============================================================
# EVIDENCE
# ============================================================

def build_evidence_summary(analysis):
    parsed = analysis.get(
        "parsed_email",
        {}
    )

    parsed_evidence = parsed.get(
        "evidence",
        {}
    )

    security = analysis.get(
        "security_analysis",
        {}
    )

    security_evidence = security.get(
        "evidence",
        {}
    )

    email_hash = first_value(
        parsed_evidence.get("original_email_sha256"),
        security_evidence.get("original_email_sha256"),
        default="N/A",
    )

    parser_timestamp = first_value(
        parsed_evidence.get("parser_timestamp"),
        security_evidence.get("parser_timestamp"),
        default="NOT_RECORDED",
    )

    return {
        "original_email_sha256": email_hash,
        "parser_timestamp": parser_timestamp,
    }


# ============================================================
# RISK
# ============================================================

def build_risk_summary(analysis):
    risk_assessment = analysis.get(
        "risk_assessment",
        {}
    )

    risk = risk_assessment.get(
        "risk",
        {}
    )

    reasons = risk.get(
        "reasons",
        risk_assessment.get("reasons", [])
    )

    return {
        "score": first_value(
            risk.get("score"),
            risk_assessment.get("score"),
            default=0,
        ),
        "verdict": first_value(
            risk.get("verdict"),
            risk_assessment.get("verdict"),
            default="N/A",
        ),
        "reasons": reasons or [],
    }


# ============================================================
# STRUCTURED REPORT
# ============================================================

def build_forensic_report(analysis):
    if not isinstance(analysis, dict):
        raise TypeError(
            "analysis must be a dictionary."
        )

    return {
        "report": {
            "tool": "MailTraceAI",
            "report_version": REPORT_VERSION,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
        },
        "case_summary": build_case_summary(analysis),
        "authentication": build_authentication_summary(analysis),
        "security_findings": build_security_findings(analysis),
        "indicators": build_ioc_summary(analysis),
        "infrastructure": build_infrastructure_summary(analysis),
        "threat_intelligence": build_threat_intelligence_summary(analysis),
        "investigation": build_investigation_summary(analysis),
        "evidence": build_evidence_summary(analysis),
        "risk": build_risk_summary(analysis),
    }


# ============================================================
# HTML HELPERS
# ============================================================

def html_table(rows, headers):
    if not rows:
        return (
            '<p class="muted">'
            'No data available.'
            '</p>'
        )

    header_html = "".join(
        f"<th>{escape(header)}</th>"
        for header in headers
    )

    body_html = ""

    for row in rows:
        body_html += "<tr>"
        for value in row:
            body_html += (
                f"<td>{escape(value)}</td>"
            )
        body_html += "</tr>"

    return f"""
    <table>
        <thead>
            <tr>{header_html}</tr>
        </thead>
        <tbody>
            {body_html}
        </tbody>
    </table>
    """


def format_probability(value):
    if value is None:
        return "N/A"

    if isinstance(value, (int, float)):
        if 0 <= value <= 1:
            return f"{value * 100:.2f}%"
        return f"{value:.2f}%"

    return str(value)


# ============================================================
# HTML REPORT
# ============================================================

def generate_html_report(analysis):
    report = build_forensic_report(analysis)

    case = report["case_summary"]
    authentication = report["authentication"]
    findings = report["security_findings"]
    indicators = report["indicators"]
    infrastructure = report["infrastructure"]
    threat_intel = report["threat_intelligence"]
    investigation = report["investigation"]
    evidence = report["evidence"]
    risk = report["risk"]

    # --------------------------------------------------------
    # Security findings
    # --------------------------------------------------------

    findings_rows = [
        [
            item["type"],
            item["severity"],
            item["description"],
        ]
        for item in findings
    ]

    findings_table = html_table(
        findings_rows,
        [
            "Signal",
            "Severity",
            "Description",
        ],
    )

    # --------------------------------------------------------
    # IOC tables
    # --------------------------------------------------------

    ip_rows = [[item] for item in indicators["ips"]]
    domain_rows = [[item] for item in indicators["domains"]]
    url_rows = [[item] for item in indicators["urls"]]

    # --------------------------------------------------------
    # Infrastructure
    # --------------------------------------------------------

    infrastructure_rows = []

    for item in infrastructure:
        infrastructure_rows.append([
            item["ip"],
            item["country"],
            item["country_code"],
            item["asn"],
            item["asn_name"],
        ])

    infrastructure_table = html_table(
        infrastructure_rows,
        [
            "IP Address",
            "Country",
            "Code",
            "ASN",
            "Network",
        ],
    )

    # --------------------------------------------------------
    # Risk reasons
    # --------------------------------------------------------

    if risk["reasons"]:
        risk_reasons_html = "<ul>"

        for reason in risk["reasons"]:
            if isinstance(reason, dict):
                source = first_value(
                    reason.get("source"),
                    reason.get("category"),
                    reason.get("module"),
                    default="N/A",
                )

                signal = first_value(
                    reason.get("type"),
                    reason.get("signal"),
                    reason.get("code"),
                    default="N/A",
                )

                points = first_value(
                    reason.get("points"),
                    reason.get("score"),
                    default=0,
                )

                description = first_value(
                    reason.get("description"),
                    reason.get("message"),
                    reason.get("details"),
                    default="",
                )

                risk_reasons_html += (
                    "<li>"
                    f"<strong>{escape(source)}"
                    f" — {escape(signal)}"
                    f" ({escape(points)} points)"
                    "</strong>"
                    "<br>"
                    f"{escape(description)}"
                    "</li>"
                )

            else:
                risk_reasons_html += (
                    f"<li>{escape(reason)}</li>"
                )

        risk_reasons_html += "</ul>"

    else:
        risk_reasons_html = (
            '<p class="muted">'
            'No risk reasons available.'
            '</p>'
        )

    # --------------------------------------------------------
    # HTML
    # --------------------------------------------------------

    document = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MailTraceAI Forensic Report</title>
<style>
* {{ box-sizing: border-box; }}
body {{
    margin: 0;
    padding: 40px;
    background: #080b12;
    color: #e8edf5;
    font-family: Arial, Helvetica, sans-serif;
    line-height: 1.5;
}}
.report {{ max-width: 1100px; margin: 0 auto; }}
.header {{
    padding: 30px;
    margin-bottom: 25px;
    border: 1px solid #263447;
    border-radius: 14px;
    background: #0d131d;
}}
.header h1 {{ margin: 0; font-size: 30px; }}
.header p {{ margin: 8px 0 0; color: #8795a9; }}
.section {{
    margin-top: 20px;
    padding: 25px;
    border: 1px solid #263447;
    border-radius: 14px;
    background: #0d131d;
}}
.section h2 {{ margin-top: 0; margin-bottom: 18px; font-size: 19px; }}
.section h3 {{ margin-top: 25px; }}
.grid {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 15px;
}}
.card {{
    padding: 15px;
    border-radius: 10px;
    background: #111a26;
    border: 1px solid #202e40;
}}
.label {{
    display: block;
    margin-bottom: 5px;
    color: #718197;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 1px;
    text-transform: uppercase;
}}
.value {{ word-break: break-word; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{
    padding: 12px;
    text-align: left;
    color: #718197;
    font-size: 10px;
    letter-spacing: 1px;
    border-bottom: 1px solid #263447;
}}
td {{
    padding: 12px;
    font-size: 13px;
    border-bottom: 1px solid #192535;
    word-break: break-word;
}}
.muted {{ color: #718197; }}
.hash {{
    padding: 12px;
    border-radius: 8px;
    background: #111a26;
    border: 1px solid #202e40;
    font-family: Consolas, "Courier New", monospace;
    word-break: break-all;
}}
ul {{ padding-left: 20px; }}
li {{ margin-bottom: 12px; }}
@media print {{
    body {{ padding: 0; background: white; color: black; }}
    .section, .header {{ background: white; border-color: #cccccc; color: black; }}
}}
@media (max-width: 700px) {{
    body {{ padding: 15px; }}
    .grid {{ grid-template-columns: 1fr; }}
    table {{ display: block; overflow-x: auto; }}
}}
</style>
</head>
<body>
<div class="report">

<div class="header">
    <h1>MailTraceAI</h1>
    <p>AI-Powered Email Threat Detection &amp; Forensic Intelligence Report</p>
    <p>Report Version: {escape(report['report']['report_version'])}</p>
    <p>Generated: {escape(report['report']['generated_at'])}</p>
</div>

<section class="section">
    <h2>1. Case Summary</h2>
    <div class="grid">
        <div class="card">
            <span class="label">Sender</span>
            <div class="value">{escape(case['sender'])}</div>
        </div>
        <div class="card">
            <span class="label">Recipient</span>
            <div class="value">{escape(case['recipient'])}</div>
        </div>
        <div class="card">
            <span class="label">Subject</span>
            <div class="value">{escape(case['subject'])}</div>
        </div>
        <div class="card">
            <span class="label">Message ID</span>
            <div class="value">{escape(case['message_id'])}</div>
        </div>
        <div class="card">
            <span class="label">Risk Score</span>
            <div class="value">{escape(case['risk_score'])} / 100</div>
        </div>
        <div class="card">
            <span class="label">Verdict</span>
            <div class="value">{escape(case['verdict'])}</div>
        </div>
        <div class="card">
            <span class="label">AI Prediction</span>
            <div class="value">{escape(case['prediction'])}</div>
        </div>
        <div class="card">
            <span class="label">Spam Probability</span>
            <div class="value">{escape(format_probability(case['spam_probability']))}</div>
        </div>
    </div>
</section>

<section class="section">
    <h2>2. Email Authentication</h2>
    {html_table([
        ['SPF', authentication['SPF']],
        ['DKIM', authentication['DKIM']],
        ['DMARC', authentication['DMARC']],
        ['ARC', authentication['ARC']],
        ['Authentication-Results', authentication['Authentication-Results']],
    ], ['Mechanism', 'Result'])}
</section>

<section class="section">
    <h2>3. Security Findings</h2>
    {findings_table}
</section>

<section class="section">
    <h2>4. Indicators of Compromise</h2>
    <h3>IP Addresses</h3>
    {html_table(ip_rows, ['IP Address'])}
    <h3>Domains</h3>
    {html_table(domain_rows, ['Domain'])}
    <h3>URLs</h3>
    {html_table(url_rows, ['URL'])}
</section>

<section class="section">
    <h2>5. Infrastructure Intelligence</h2>
    {infrastructure_table}
    <p class="muted">
        Infrastructure geolocation represents observable network infrastructure
        and should not be interpreted as proof of an attacker's physical location
        or identity.
    </p>
</section>

<section class="section">
    <h2>6. Threat Intelligence</h2>
    {html_table([
        ['Status', threat_intel['status']],
        ['IPs Checked', threat_intel['ips_checked']],
        ['Domains Checked', threat_intel['domains_checked']],
        ['URLs Checked', threat_intel['urls_checked']],
    ], ['Metric', 'Value'])}
    <p class="muted">
        Threat intelligence provider results depend on the availability and
        configuration of external API credentials.
    </p>
</section>

<section class="section">
    <h2>7. Investigation Graph</h2>
    {html_table([
        ['Graph Version', investigation['graph_version']],
        ['Nodes', investigation['node_count']],
        ['Relationships', investigation['edge_count']],
    ], ['Metric', 'Value'])}
</section>

<section class="section">
    <h2>8. Risk Assessment</h2>
    <div class="grid">
        <div class="card">
            <span class="label">Risk Score</span>
            <div class="value">{escape(risk['score'])} / 100</div>
        </div>
        <div class="card">
            <span class="label">Verdict</span>
            <div class="value">{escape(risk['verdict'])}</div>
        </div>
    </div>
    <h3>Risk Reasons</h3>
    {risk_reasons_html}
</section>

<section class="section">
    <h2>9. Evidence Integrity</h2>
    <p>Original Email SHA-256</p>
    <div class="hash">{escape(evidence['original_email_sha256'])}</div>
    <p>Parser Timestamp: {escape(evidence['parser_timestamp'])}</p>
</section>

<section class="section">
    <p class="muted">
        This report summarizes automated analysis performed by MailTraceAI.
        Infrastructure geolocation represents observable network infrastructure
        and should not be interpreted as proof of an attacker's physical location
        or identity.
    </p>
</section>

</div>
</body>
</html>
"""

    return document


# ============================================================
# SAVE REPORT
# ============================================================

def save_html_report(
    analysis,
    output_file="forensic_report.html"
):
    document = generate_html_report(analysis)
    output_path = Path(output_file)

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as file:
        file.write(document)

    return output_path


# ============================================================
# LOAD FINAL ANALYSIS
# ============================================================

def load_final_analysis(
    input_file="final_analysis.json"
):
    input_path = Path(input_file)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Analysis file not found: {input_path}"
        )

    with input_path.open(
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("MAILTRACEAI FORENSIC REPORT GENERATOR")
    print("=" * 60)

    analysis = load_final_analysis()
    report = build_forensic_report(analysis)

    print(
        f"\nReport Version: "
        f"{report['report']['report_version']}"
    )

    print(
        f"Risk Score: "
        f"{report['risk']['score']}/100"
    )

    print(
        f"Verdict: "
        f"{report['risk']['verdict']}"
    )

    print(
        f"Sender: "
        f"{report['case_summary']['sender']}"
    )

    print(
        f"Recipient: "
        f"{report['case_summary']['recipient']}"
    )

    print(
        f"Subject: "
        f"{report['case_summary']['subject']}"
    )

    print(
        f"IOCs: "
        f"{len(report['indicators']['ips'])} IPs, "
        f"{len(report['indicators']['domains'])} domains, "
        f"{len(report['indicators']['urls'])} URLs"
    )

    print(
        f"Infrastructure records: "
        f"{len(report['infrastructure'])}"
    )

    output = save_html_report(analysis)

    print(
        f"\nForensic report saved to: {output}"
    )

    print("\nREPORT GENERATION COMPLETE")
