from pathlib import Path
import json

from Parser.email_parser import parse_email
from Parser.security_analyzer import analyze_email
from ThreatIntel.threat_intel import analyze_threat_intelligence
from Geolocation.geolocation import geolocate_ips
from Investigation.correlation_engine import build_investigation_graph
from Risk.risk_engine import calculate_risk
from Report.forensic_report import save_html_report


# ============================================================
# MAILTRACEAI ORCHESTRATOR
# ============================================================

def run_pipeline(email_file):
    """
    Run the complete MailTraceAI analysis pipeline.

    Flow:

        Email
          ↓
        Parser
          ↓
        Security Analyzer
          ↓
        Threat Intelligence
          ↓
        Geolocation
          ↓
        Investigation Graph
          ↓
        Risk Engine
          ↓
        Final Analysis
          ↓
        Forensic Report
    """

    email_file = Path(email_file)

    # ========================================================
    # CHECK EMAIL FILE
    # ========================================================

    if not email_file.exists():
        raise FileNotFoundError(
            f"Email file not found: {email_file}"
        )

    print("=" * 60)
    print("MAILTRACEAI ANALYSIS PIPELINE")
    print("=" * 60)

    # ========================================================
    # STEP 1 — PARSE EMAIL
    # ========================================================

    print("\n[1/7] Parsing email...")

    parsed_email = parse_email(email_file)

    print("Parser: COMPLETE")

    # ========================================================
    # STEP 2 — SECURITY ANALYSIS
    # ========================================================

    print("\n[2/7] Running security analysis...")

    security_analysis = analyze_email(email_file)

    print("Security Analyzer: COMPLETE")

    # ========================================================
    # STEP 3 — THREAT INTELLIGENCE
    # ========================================================

    print("\n[3/7] Running threat intelligence...")

    threat_intelligence = analyze_threat_intelligence(
        security_analysis
    )

    print("Threat Intelligence: COMPLETE")

    # ========================================================
    # STEP 4 — GEOLOCATION
    # ========================================================

    print("\n[4/7] Geolocating public infrastructure IPs...")

    public_ips = (
        security_analysis
        .get("routing", {})
        .get("public_infrastructure_ips", [])
    )

    geolocation = geolocate_ips(public_ips)

    print(
        f"Geolocation: COMPLETE "
        f"({len(geolocation)} IPs processed)"
    )

    # ========================================================
    # STEP 5 — INVESTIGATION GRAPH
    # ========================================================

    print("\n[5/7] Building investigation graph...")

    # IMPORTANT:
    #
    # build_investigation_graph() accepts EXACTLY
    # three arguments:
    #
    #   1. parsed_email
    #   2. security_analysis
    #   3. geolocation
    #
    # Threat intelligence is NOT passed here.

    investigation_graph = build_investigation_graph(
        parsed_email,
        security_analysis,
        geolocation
    )

    print(
        "Investigation Graph: COMPLETE "
        f"({investigation_graph.get('node_count', 0)} nodes, "
        f"{investigation_graph.get('edge_count', 0)} edges)"
    )

    # ========================================================
    # STEP 6 — RISK ENGINE
    # ========================================================

    print("\n[6/7] Calculating risk...")

    risk_assessment = calculate_risk(
        parsed_email,
        security_analysis,
        threat_intelligence
    )

    print("Risk Engine: COMPLETE")

    # ========================================================
    # BUILD FINAL ANALYSIS
    # ========================================================

    final_analysis = {
        "tool": "MailTraceAI",
        "analysis_version": "1.0",

        "parsed_email": parsed_email,

        "security_analysis": security_analysis,

        "threat_intelligence": threat_intelligence,

        "geolocation": geolocation,

        "investigation_graph": investigation_graph,

        "risk_assessment": risk_assessment
    }

    # ========================================================
    # SAVE FINAL ANALYSIS
    # ========================================================

    output_file = Path(
        "final_analysis.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            final_analysis,
            file,
            indent=4,
            default=str
        )

    print(
        f"\nFinal analysis saved to: "
        f"{output_file}"
    )

    # ========================================================
    # STEP 7 — FORENSIC REPORT
    # ========================================================

    print("\n[7/7] Generating forensic report...")

    # IMPORTANT:
    #
    # Pass the ORIGINAL final_analysis directly.
    #
    # save_html_report()
    #       ↓
    # generate_html_report()
    #       ↓
    # build_forensic_report()
    #
    # Therefore we must NOT call
    # build_forensic_report() here ourselves.

    report_file = save_html_report(
        final_analysis,
        "forensic_report.html"
    )

    print(
        f"Forensic Report: COMPLETE "
        f"({report_file})"
    )

    # ========================================================
    # PIPELINE SUMMARY
    # ========================================================

    risk = (
        risk_assessment
        .get("risk", {})
    )

    risk_score = risk.get(
        "score",
        0
    )

    verdict = risk.get(
        "verdict",
        "N/A"
    )

    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)

    print(
        f"Risk Score : "
        f"{risk_score}/100"
    )

    print(
        f"Verdict    : "
        f"{verdict}"
    )

    print(
        f"Geolocated : "
        f"{len(geolocation)} IPs"
    )

    print(
        f"Graph      : "
        f"{investigation_graph.get('node_count', 0)} nodes / "
        f"{investigation_graph.get('edge_count', 0)} edges"
    )

    print(
        f"Report     : "
        f"{report_file}"
    )

    print(
        f"\nSaved result to: "
        f"{output_file}"
    )

    return final_analysis


# ============================================================
# STANDALONE TEST
# ============================================================

if __name__ == "__main__":

    # Your actual test email
    test_email = Path(
        "samples/spam_test.eml"
    )

    try:

        run_pipeline(test_email)

    except Exception as error:

        print("\n" + "=" * 60)
        print("PIPELINE ERROR")
        print("=" * 60)

        print(
            f"{type(error).__name__}: "
            f"{error}"
        )

        raise