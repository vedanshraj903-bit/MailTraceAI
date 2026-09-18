"""
Shared email → model-text conversion.

Training (build_dataset.py / train_model.py) and inference
(Risk/risk_engine.py, predict_email.py) must turn an email into
text in exactly the same way, otherwise the model is scored on
input it never saw. Everything goes through build_model_text().
"""

import re
from email.header import decode_header, make_header
from html import unescape
from html.parser import HTMLParser
from urllib.parse import urlparse


# ============================================================
# LIMITS
# ============================================================

# Long bodies (newsletters, forwarded threads) add little signal
# and slow character n-grams down a lot.
MAX_BODY_CHARS = 6000

# Bodies shorter than this carry too little text to classify; they
# are left out of training and the app ignores the model for them.
MIN_BODY_CHARS = 40


# ============================================================
# HTML → TEXT
# ============================================================

class _TextExtractor(HTMLParser):

    SKIP_TAGS = {"script", "style", "head", "title", "noscript"}

    BLOCK_TAGS = {
        "p", "div", "br", "tr", "li", "table",
        "h1", "h2", "h3", "h4", "h5", "h6",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP_TAGS:
            self.skip_depth += 1
            return

        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")

        # Keep link targets: where a link really goes is one of the
        # strongest phishing signals.
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.parts.append(f" {href} ")

    def handle_endtag(self, tag):
        if tag in self.SKIP_TAGS and self.skip_depth:
            self.skip_depth -= 1

    def handle_data(self, data):
        if not self.skip_depth:
            self.parts.append(data)


def html_to_text(html):
    if not html:
        return ""

    extractor = _TextExtractor()

    try:
        extractor.feed(html)
        extractor.close()
    except Exception:
        return unescape(re.sub(r"<[^>]+>", " ", html))

    return "".join(extractor.parts)


# ============================================================
# NORMALISATION
# ============================================================

URL_PATTERN = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)

EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

IP_URL_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

YEAR_PATTERN = re.compile(r"\b(?:19|20)\d{2}\b")

LONG_NUMBER_PATTERN = re.compile(r"\b\d{5,}\b")

WHITESPACE_PATTERN = re.compile(r"\s+")


def _url_token(match):
    url = match.group(0)

    if url.lower().startswith("www."):
        url = "http://" + url

    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        host = ""

    if not host:
        return " urltoken "

    if IP_URL_HOST.match(host):
        return " urltoken urlipaddress "

    # Keep the registrable-looking tail (e.g. "hdfcbank.com") so the
    # model can learn brand / lookalike domains, not full paths.
    tail = ".".join(host.split(".")[-2:])

    return f" urltoken urldomain_{tail.replace('.', '_').replace('-', '_')} "


def normalise_text(text):
    """
    Collapse volatile details (full URLs, addresses, years, long
    numbers) into stable tokens so the model learns patterns, not
    specific strings or the era a corpus was collected in.
    """

    text = URL_PATTERN.sub(_url_token, text)
    text = EMAIL_PATTERN.sub(" emailtoken ", text)
    text = YEAR_PATTERN.sub(" yeartoken ", text)
    text = LONG_NUMBER_PATTERN.sub(" numbertoken ", text)

    return WHITESPACE_PATTERN.sub(" ", text).strip()


def decode_header_value(value):
    """
    Decode RFC 2047 encoded words ("=?utf-8?Q?Dear=20Client?=") the
    way a mail client displays them. Some datasets store headers
    still encoded while the live parser decodes them, so without
    this the model would learn the encoding instead of the words.
    """

    value = str(value or "")

    if "=?" not in value:
        return value

    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _sender_domain(sender):
    match = EMAIL_PATTERN.search(sender or "")

    if not match:
        return ""

    return match.group(0).rsplit("@", 1)[-1].lower()


# ============================================================
# PUBLIC API
# ============================================================

def build_model_text(subject="", sender="", reply_to="", plain_text="", html=""):
    """
    Turn email fields into the single text string the model sees.
    """

    subject = decode_header_value(subject)
    sender = decode_header_value(sender)
    reply_to = decode_header_value(reply_to)

    body = plain_text or ""

    # Use the HTML part when there is no usable plain-text part
    # (HTML-only phishing is common).
    if len(body.strip()) < 20 and html:
        body = html_to_text(html)

    body = normalise_text(unescape(body))[:MAX_BODY_CHARS]

    sender_domain = _sender_domain(sender)
    reply_domain = _sender_domain(reply_to)

    reply_mismatch = (
        "replytomismatch"
        if reply_domain and sender_domain and reply_domain != sender_domain
        else ""
    )

    display_name = EMAIL_PATTERN.sub("", sender or "").strip(" <>\"'")

    # The sender's domain itself is deliberately NOT a feature: in the
    # public corpora it mostly encodes the era (2002 ham predates
    # Gmail, so "gmail.com" looked like phishing). Domain reputation
    # and lookalike checks live in the rule-based security analyzer.
    return (
        f"SUBJECT: {normalise_text(str(subject or ''))}\n"
        f"FROM: {display_name} {reply_mismatch}\n"
        f"BODY: {body}"
    )


def body_length(model_text):
    """
    Characters of body text the model actually sees. Very short
    bodies are outside what the model was trained on (training
    drops bodies under MIN_BODY_CHARS), so predictions there are
    unreliable.
    """

    return len(model_text.split("BODY:", 1)[-1].strip())



def extract_fields(message):
    """
    Pull subject / sender / reply-to / plain / html out of an
    email.message.EmailMessage, the same way Parser/email_parser.py
    does for the live app.
    """

    plain_parts = []
    html_parts = []

    parts = message.walk() if message.is_multipart() else [message]

    for part in parts:
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="ignore")

        if not isinstance(content, str):
            continue

        if content_type == "text/plain":
            plain_parts.append(content)
        else:
            html_parts.append(content)

    def header(name):
        try:
            return str(message.get(name, "") or "")
        except Exception:
            return ""

    return {
        "subject": header("Subject"),
        "sender": header("From"),
        "reply_to": header("Reply-To"),
        "plain_text": "\n".join(plain_parts),
        "html": "\n".join(html_parts),
    }
