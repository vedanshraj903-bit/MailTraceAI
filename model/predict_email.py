from email import policy
from email.parser import BytesParser
from pathlib import Path

import joblib


# ============================================================
# 1. PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_FILE = BASE_DIR / "model" / "mailtraceai_detector.joblib"
EMAIL_FILE = BASE_DIR / "samples" / "spam_test"


# ============================================================
# 2. LOAD TRAINED MODEL
# ============================================================

print("=" * 60)
print("MAILTRACEAI - EMAIL THREAT DETECTION")
print("=" * 60)

print("\nLoading trained model...")

model = joblib.load(MODEL_FILE)

print("Model loaded successfully.")


# ============================================================
# 3. READ EMAIL
# ============================================================

with open(EMAIL_FILE, "rb") as file:
    message = BytesParser(
        policy=policy.default
    ).parse(file)


# ============================================================
# 4. EXTRACT EMAIL INFORMATION
# ============================================================

subject = message.get("Subject", "")
sender = message.get("From", "")
reply_to = message.get("Reply-To", "")

body = ""


if message.is_multipart():

    for part in message.walk():

        if part.get_content_type() == "text/plain":

            try:
                body += part.get_content()

            except Exception:
                pass

else:

    try:
        body = message.get_content()

    except Exception:
        pass


# ============================================================
# 5. CREATE THE SAME TEXT FORMAT USED DURING TRAINING
# ============================================================

email_text = (
    f"SUBJECT: {subject}\n"
    f"FROM: {sender}\n"
    f"REPLY-TO: {reply_to}\n"
    f"BODY: {body}"
)


# ============================================================
# 6. RUN THE MODEL
# ============================================================

prediction = model.predict([email_text])[0]

probabilities = model.predict_proba([email_text])[0]

classes = model.classes_


# ============================================================
# 7. FIND CONFIDENCE
# ============================================================

prediction_index = list(classes).index(prediction)

confidence = probabilities[prediction_index]


# ============================================================
# 8. DISPLAY RESULT
# ============================================================

print("\n" + "=" * 60)
print("ANALYSIS RESULT")
print("=" * 60)

print("\nFrom:")
print(sender)

print("\nSubject:")
print(subject)

print("\nPrediction:")
print(prediction.upper())

print("\nConfidence:")
print(f"{confidence * 100:.2f}%")


# ============================================================
# 9. SIMPLE RISK LEVEL
# ============================================================

if prediction == "spam":

    if confidence >= 0.90:
        risk = "HIGH"

    elif confidence >= 0.70:
        risk = "MEDIUM"

    else:
        risk = "LOW"

else:

    if confidence >= 0.90:
        risk = "LOW"

    else:
        risk = "MEDIUM"


print("\nRisk Level:")
print(risk)

print("\n" + "=" * 60)