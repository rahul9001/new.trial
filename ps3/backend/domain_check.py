"""
Sender Domain Verification Module — SENTINEL AI
=================================================
Performs structural and allowlist-based checks on the sender's email address
BEFORE final risk scoring.  The result is passed into the scoring pipeline so
domain trust (or suspicion) can adjust the final verdict.

Domain statuses:
  TRUSTED    — exact match against the configured TRUSTED_DOMAINS allowlist.
  UNKNOWN    — structurally valid domain not present in the allowlist.
  SUSPICIOUS — lookalike / homograph domain, or structural anomaly.
  INVALID    — missing, blank, or structurally unparseable address.

This module is intentionally free of external network calls; all checks are
local so they never block the request or expose internal DNS topology.
"""

import re
from typing import Optional
from dataclasses import dataclass

from backend.config import TRUSTED_DOMAINS


# ---------------------------------------------------------------------------
# Data Transfer Object
# ---------------------------------------------------------------------------

@dataclass
class DomainCheckResult:
    sender_email: str          # Exactly what was submitted (may be empty string)
    sender_domain: str         # Extracted domain, or "" if extraction failed
    domain_status: str         # TRUSTED | UNKNOWN | SUSPICIOUS | INVALID
    domain_reason: str         # Human-readable explanation for UI display
    risk_adjustment: int       # Score delta applied to content risk (-10..+20)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# RFC-5322 simplified email regex — good enough for structural validation.
# Does not validate DNS, MX records, or SMTP connectivity.
_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})$"
)

# Suspicious lookalike TLD or domain patterns — these flag domains that
# mimic well-known brands with slight misspellings or unusual TLDs.
_LOOKALIKE_PATTERNS = re.compile(
    r"(paypa[l1]|app[l1]e|arnazon|g00gle|microso[f1]t|netf[l1]ix|"
    r"ch[a@]se|we[l1][l1]s|c[i!]t[i!]bank|[a@]mazon|secure-[a-z]+\.[a-z]{2,}|"
    r"[a-z]+-secure\.[a-z]{2,}|[a-z]+-verify\.[a-z]{2,}|"
    r"[a-z]+-account\.[a-z]{2,}|[a-z]+-login\.[a-z]{2,}|"
    r"[a-z]+-update\.[a-z]{2,}|[a-z]+-alert\.[a-z]{2,})",
    re.IGNORECASE,
)

# Domains with unusual TLDs often used in scams (.tk, .ml, .ga, .cf, .gq, .xyz used suspiciously)
_SCAM_TLD_PATTERN = re.compile(
    r"\.(tk|ml|ga|cf|gq|xyz|top|click|link|download|zip|loan|win|bid|stream|review)$",
    re.IGNORECASE,
)

# IP-literal addresses masquerading as domains  (e.g. 192.168.1.1)
_IP_DOMAIN_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _extract_domain(email: str) -> Optional[str]:
    """Return the domain portion of an email, or None if unparseable."""
    email = email.strip()
    m = _EMAIL_RE.match(email)
    if m:
        return m.group(1).lower()
    return None


def _is_suspicious_domain(domain: str) -> tuple[bool, str]:
    """
    Check structural indicators that suggest a lookalike / scam domain.
    Returns (is_suspicious, reason_text).
    """
    if _IP_DOMAIN_RE.match(domain):
        return True, f"Sender domain is a raw IP address ({domain}), not a legitimate hostname."

    if _SCAM_TLD_PATTERN.search(domain):
        tld = domain.rsplit(".", 1)[-1]
        return True, (
            f"Sender domain uses TLD '.{tld}' which is frequently abused in "
            "phishing and scam campaigns."
        )

    if _LOOKALIKE_PATTERNS.search(domain):
        return True, (
            f"Sender domain '{domain}' matches a known brand-impersonation or "
            "lookalike pattern (homograph / typosquatting)."
        )

    # Excessive hyphens or numeric substitutions in domain labels
    labels = domain.split(".")
    for label in labels:
        if label.count("-") >= 3:
            return True, (
                f"Sender domain label '{label}' contains an unusual number of "
                "hyphens — common in generated phishing domains."
            )

    return False, ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_sender_domain(sender_email: Optional[str]) -> DomainCheckResult:
    """
    Validate the sender's email address and classify the domain.

    Args:
        sender_email: The raw sender address string from the request.
                      May be None, empty, or malformed.

    Returns:
        DomainCheckResult with status, reason, and a risk_adjustment delta.

    This function ALWAYS returns a result — it never raises.
    """
    # --- INVALID: missing or blank ---
    if not sender_email or not sender_email.strip():
        return DomainCheckResult(
            sender_email="",
            sender_domain="",
            domain_status="INVALID",
            domain_reason=(
                "No sender email address was provided. "
                "Domain verification was skipped; risk score is not adjusted."
            ),
            risk_adjustment=0,
        )

    raw = sender_email.strip()

    # --- INVALID: structurally unparseable ---
    domain = _extract_domain(raw)
    if domain is None:
        return DomainCheckResult(
            sender_email=raw,
            sender_domain="",
            domain_status="INVALID",
            domain_reason=(
                f"'{raw}' is not a valid email address format. "
                "Expected format: localpart@domain.tld"
            ),
            risk_adjustment=+5,  # mild penalty for submitting garbage
        )

    # --- SUSPICIOUS: lookalike / structural anomaly ---
    is_sus, sus_reason = _is_suspicious_domain(domain)
    if is_sus:
        return DomainCheckResult(
            sender_email=raw,
            sender_domain=domain,
            domain_status="SUSPICIOUS",
            domain_reason=sus_reason,
            risk_adjustment=+20,  # significant upward pressure on score
        )

    # --- TRUSTED: exact allowlist match ---
    if domain in TRUSTED_DOMAINS:
        return DomainCheckResult(
            sender_email=raw,
            sender_domain=domain,
            domain_status="TRUSTED",
            domain_reason=(
                f"Domain '{domain}' is present in the configured trusted-domain "
                "allowlist. Note: trusted domain status does not override content "
                "analysis — phishing content is still flagged regardless."
            ),
            risk_adjustment=-10,  # mild downward pressure on score
        )

    # --- UNKNOWN: valid but not in allowlist ---
    return DomainCheckResult(
        sender_email=raw,
        sender_domain=domain,
        domain_status="UNKNOWN",
        domain_reason=(
            f"Domain '{domain}' is not in the trusted-domain allowlist. "
            "This does not automatically indicate spam — the final verdict "
            "is based on combined content and domain signals."
        ),
        risk_adjustment=0,  # neutral — content analysis drives verdict
    )
