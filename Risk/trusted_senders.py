"""
Sender verification for every email.

Status levels
-------------
TRUSTED        The From domain is authenticated AND is a known bank /
               payments domain. Overrides the wording-based ML verdict,
               because genuine bank alerts use the same words as fakes
               ("Dear Customer", "your account", "transaction").
AUTHENTICATED  The email really comes from the From domain (DMARC pass,
               or a DKIM signature aligned with it). This proves WHO
               sent it, not that they are honest: a scammer's own
               lookalike domain can be authenticated too.
NOT_VERIFIED   Authentication failed or is missing, so the From address
               could be forged.

Results come from the Authentication-Results header added by the
receiving provider (Gmail, Outlook, ...).

Trusted domains: anything ending in ".bank.in" (reserved by the RBI for
regulated Indian banks — scammers cannot register one) or, or a
subdomain of, an entry in TRUSTED_DOMAINS. Lookalikes such as
"hdfcbank-kyc-update.info" or "hdfcbank.com.secure-login.xyz" never
match.
"""

import re


TRUSTED_SUFFIXES = (
    ".bank.in",
)

# Official sending domains of major Indian banks and payment apps.
# Exact domain or subdomain match only.
TRUSTED_DOMAINS = {
    "hdfcbank.com",
    "hdfcbank.net",
    "icicibank.com",
    "sbi.co.in",
    "onlinesbi.sbi",
    "axisbank.com",
    "kotak.com",
    "yesbank.in",
    "indusind.com",
    "pnb.co.in",
    "bankofbaroda.com",
    "canarabank.com",
    "unionbankofindia.co.in",
    "idfcfirstbank.com",
    "npci.org.in",
    "paytm.com",
    "phonepe.com",
}

DMARC_PATTERN = re.compile(
    r"\bdmarc\s*=\s*(\w+)(?P<rest>[^;]*)",
    re.IGNORECASE,
)

HEADER_FROM_PATTERN = re.compile(r"\bheader\.from\s*=\s*([\w.-]+)", re.IGNORECASE)

DKIM_PASS_PATTERN = re.compile(
    r"\bdkim\s*=\s*pass\b[^;]*?\bheader\.[di]\s*=\s*([^\s;]+)",
    re.IGNORECASE,
)


def _clean(domain):
    return domain.rsplit("@", 1)[-1].lower().strip(" .;")


def _aligned(signing_domain, from_domain):
    """Relaxed alignment: same domain, or one is a subdomain of the other."""
    return (
        signing_domain == from_domain
        or from_domain.endswith("." + signing_domain)
        or signing_domain.endswith("." + from_domain)
    )


def is_trusted_domain(domain):
    domain = _clean(domain)

    if any(domain.endswith(suffix) for suffix in TRUSTED_SUFFIXES):
        return True

    return any(
        domain == trusted or domain.endswith("." + trusted)
        for trusted in TRUSTED_DOMAINS
    )


def check_sender(security_data):
    """
    Return {"status", "domain", "method", "reason"} for any email.
    """

    identity = security_data.get("identity", {})
    authentication = security_data.get("authentication", {})

    from_email = identity.get("from_email") or ""

    if "@" not in from_email:
        return {
            "status": "NOT_VERIFIED",
            "domain": None,
            "method": None,
            "reason": "No sender address found in the From header.",
        }

    from_domain = _clean(from_email)

    results = str(authentication.get("authentication_results") or "")

    def not_verified(reason):
        return {
            "status": "NOT_VERIFIED",
            "domain": from_domain,
            "method": None,
            "reason": reason,
        }

    if not results.strip():
        return not_verified(
            "No authentication results in the headers, so the sender "
            "cannot be confirmed."
        )

    method = None

    dmarc = DMARC_PATTERN.search(results)

    if dmarc:
        dmarc_result = dmarc.group(1).lower()
        header_from = HEADER_FROM_PATTERN.search(dmarc.group("rest"))
        checked_domain = _clean(header_from.group(1)) if header_from else from_domain

        if dmarc_result == "pass" and checked_domain == from_domain:
            method = "DMARC"
        elif dmarc_result == "fail":
            return not_verified(
                f"DMARC failed for {from_domain}: the From address "
                "may be forged."
            )

    if method is None:
        for signer in DKIM_PASS_PATTERN.findall(results):
            if _aligned(_clean(signer), from_domain):
                method = "DKIM"
                break

    if method is None:
        return not_verified(
            f"Neither DMARC nor a DKIM signature from {from_domain} "
            "passed, so the From address could be forged."
        )

    if is_trusted_domain(from_domain):
        kind = (
            "a reserved .bank.in domain (RBI-regulated banks only)"
            if from_domain.endswith(".bank.in")
            else "a known official bank / payments domain"
        )
        return {
            "status": "TRUSTED",
            "domain": from_domain,
            "method": method,
            "reason": f"{method} passed for {from_domain}, {kind}.",
        }

    return {
        "status": "AUTHENTICATED",
        "domain": from_domain,
        "method": method,
        "reason": (
            f"{method} passed: the email really comes from "
            f"{from_domain}. Check that this is the company you expect "
            "— lookalike domains can be authenticated too."
        ),
    }
