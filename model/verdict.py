"""
Turn the model's probabilities into the label MailTraceAI shows.

Checked in order:
    phishing probability ≥ 60%          → phishing
    spam probability ≥ 50%              → spam   (confident junk mail)
    phishing probability ≥ 20%          → spam
    otherwise                           → ham

Used by Risk/risk_engine.py (app + report) and predict_email.py so
every place shows the same label.
"""

HAM_BELOW = 0.20
SPAM_BELOW = 0.60
CONFIDENT_SPAM = 0.50


def label_from_probabilities(phishing_probability, spam_probability=0.0):
    if phishing_probability >= SPAM_BELOW:
        return "phishing"

    if spam_probability >= CONFIDENT_SPAM:
        return "spam"

    if phishing_probability >= HAM_BELOW:
        return "spam"

    return "ham"
