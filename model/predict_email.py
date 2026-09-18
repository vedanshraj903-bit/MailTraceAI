"""
Classify one email file with the trained MailTraceAI model.

Usage:
    python model/predict_email.py path/to/email.eml
    python model/predict_email.py            # defaults to samples/spam_test.eml
"""

import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path

import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent))

from features import build_model_text, extract_fields  # noqa: E402
from verdict import label_from_probabilities  # noqa: E402


# ============================================================
# 1. PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_FILE = BASE_DIR / "model" / "mailtraceai_detector.joblib"

DEFAULT_EMAIL = BASE_DIR / "samples" / "spam_test.eml"


# ============================================================
# 2. CLASSIFY
# ============================================================

def classify(email_file, model):
    with open(email_file, "rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    fields = extract_fields(message)

    # Same conversion the model was trained on.
    email_text = build_model_text(**fields)

    probabilities = dict(zip(
        model.classes_,
        model.predict_proba([email_text])[0],
    ))

    prediction = label_from_probabilities(
        probabilities.get("phishing", 0.0),
        probabilities.get("spam", 0.0),
    )

    return fields, prediction, probabilities


def risk_level(prediction):
    return {"phishing": "HIGH", "spam": "MEDIUM"}.get(prediction, "LOW")


# ============================================================
# 3. MAIN
# ============================================================

def main():
    email_file = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_EMAIL

    print("=" * 60)
    print("MAILTRACEAI - EMAIL THREAT DETECTION")
    print("=" * 60)

    model = joblib.load(MODEL_FILE)

    fields, prediction, probabilities = classify(email_file, model)

    print(f"\nFile      : {email_file}")
    print(f"From      : {fields['sender']}")
    print(f"Subject   : {fields['subject']}")

    print(f"\nPrediction: {prediction.upper()}")

    print(f"Phishing probability: {probabilities.get('phishing', 0.0) * 100:.2f}%")

    print(f"\nRisk Level: {risk_level(prediction)}")

    print("=" * 60)


if __name__ == "__main__":
    main()
