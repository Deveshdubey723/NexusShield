"""Deterministic scam indicators. Scores are heuristic points, not probabilities."""

from __future__ import annotations

import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlsplit

from app.schemas import AnalysisResult

_URL_PATTERN = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")
_SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "is.gd",
    "rebrand.ly",
    "tiny.cc",
    "tinyurl.com",
}
_URGENT_TERMS = (
    "act now",
    "account suspended",
    "immediately",
    "limited time",
    "verify your account",
    "within 24 hours",
    "urgent",
)
_PAYMENT_TERMS = (
    "gift card",
    "wire transfer",
    "cryptocurrency",
    "crypto",
    "payment",
    "bank details",
    "password",
    "one-time code",
    "otp",
)
_PRIZE_TERMS = (
    "claim your prize",
    "you have won",
    "you won",
    "winner",
    "lottery",
    "free gift",
    "prize",
)
_IMPERSONATION_TERMS = (
    "bank support",
    "customer service",
    "government agency",
    "official support",
    "security team",
    "tax office",
    "technical support",
)


def _verdict(score: int) -> str:
    if score >= 60:
        return "high_risk"
    if score >= 30:
        return "suspicious"
    return "low_risk"


def _risk_level(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _result(scan_type: str, score: int, reasons: list[str], indicators: list[str]) -> AnalysisResult:
    risk_score = min(score, 100)
    risk_level = _risk_level(risk_score)
    if risk_level == "high":
        actions = [
            "Do not click the link, reply, pay, or share sensitive information.",
            "Verify the request through a contact method you already trust.",
            "If you already shared credentials or payment details, contact the provider using an official channel.",
        ]
    elif risk_level == "medium":
        actions = [
            "Pause and independently verify the request before acting.",
            "Do not share passwords, one-time codes, or payment details in response to an unexpected message.",
        ]
    else:
        actions = [
            "No configured risk indicators were found; this does not prove the content is safe.",
            "Verify unexpected requests independently and never share passwords or one-time codes.",
        ]
    explanation = (
        f"The rule-based baseline matched {len(indicators)} configured signal(s) and assigned "
        f"a {risk_level}-risk heuristic score. This score is not a probability or proof of fraud. "
        + " ".join(reasons)
    )
    limitations = [
        "Matched indicators can also occur in legitimate content; this result is an estimate, not proof of fraud.",
        "No live domain reputation, DNS, sender authentication, or threat-feed checks were performed.",
        "A low-risk result does not guarantee that a message, email, or website is safe.",
        "The score is a deterministic rule-based severity score, not a calibrated probability.",
    ]
    return AnalysisResult(
        scan_type=scan_type,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=_verdict(risk_score),
        detected_signals=indicators,
        evidence=reasons,
        explanation=explanation,
        recommended_actions=actions,
        analysis_limitations=limitations,
        reasons=reasons,
        indicators=indicators,
    )


def _normalize_url(value: str) -> str:
    candidate = value.strip().rstrip(".,);]}!?")
    if not re.match(r"(?i)^https?://", candidate):
        return f"http://{candidate}"
    return candidate


def is_valid_url(value: str) -> bool:
    candidate = _normalize_url(value)
    if any(character.isspace() or ord(character) < 32 for character in candidate):
        return False
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").rstrip(".")
        if parts.scheme.lower() not in {"http", "https"} or not host or not parts.netloc:
            return False
        parts.port
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            ascii_host = host.encode("idna").decode("ascii")
        labels = ascii_host.split(".")
        return (
            len(ascii_host) <= 253
            and all(
                0 < len(label) <= 63
                and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
                for label in labels
            )
        )
    except ValueError:
        return False


def _url_signals(value: str) -> tuple[int, list[str], list[str]]:
    if not is_valid_url(value):
        return 0, ["Could not identify a valid web address."], []
    has_explicit_http_scheme = bool(re.match(r"(?i)^https?://", value.strip()))
    normalized = _normalize_url(value)
    parts = urlsplit(normalized)
    host = (parts.hostname or "").lower().rstrip(".")
    reasons: list[str] = []
    indicators: list[str] = []
    score = 0

    if not host:
        return 0, ["Could not identify a valid web address."], []
    if parts.username or parts.password:
        score += 35
        reasons.append("The address embeds user information before the hostname.")
        indicators.append("embedded_credentials")
    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("The address uses a numeric IP host instead of a domain name.")
        indicators.append("ip_host")
    except ValueError:
        pass
    if host in _SHORTENERS:
        score += 25
        reasons.append("The address uses a URL-shortening service that hides its destination.")
        indicators.append("shortened_url")
    if host.startswith("xn--") or ".xn--" in host:
        score += 25
        reasons.append("The domain uses internationalized/punycode labels.")
        indicators.append("punycode_domain")
    elif any(ord(character) > 127 for character in host):
        score += 20
        reasons.append("The hostname contains non-ASCII characters that may be visually confusable.")
        indicators.append("unicode_hostname")
    if host.count(".") >= 4:
        score += 15
        reasons.append("The hostname has an unusually large number of subdomain levels.")
        indicators.append("many_subdomains")
    if host.count("-") >= 3:
        score += 10
        reasons.append("The hostname contains several hyphens, which can be used to imitate familiar names.")
        indicators.append("unusual_hyphenation")
    if len(normalized) > 120:
        score += 10
        reasons.append("The address is unusually long.")
        indicators.append("long_url")
    if has_explicit_http_scheme and parts.scheme.lower() == "http":
        score += 8
        reasons.append("The address does not use HTTPS.")
        indicators.append("http_not_https")
    return score, reasons, indicators


def analyze_url(value: str) -> AnalysisResult:
    score, reasons, indicators = _url_signals(value)
    if not reasons:
        reasons.append("No configured URL risk indicators were detected.")
    return _result("url", score, reasons, indicators)


def analyze_message(value: str) -> AnalysisResult:
    text = value.strip()
    lowered = text.lower()
    score = 0
    reasons: list[str] = []
    indicators: list[str] = []
    urgent_hits = [term for term in _URGENT_TERMS if term in lowered]
    payment_hits = [term for term in _PAYMENT_TERMS if term in lowered]
    prize_hits = [term for term in _PRIZE_TERMS if term in lowered]
    impersonation_hits = [term for term in _IMPERSONATION_TERMS if term in lowered]
    if urgent_hits:
        score += min(20 + (len(urgent_hits) - 1) * 5, 30)
        reasons.append("The message uses urgency or account-pressure language.")
        indicators.append("urgency_language")
    if payment_hits:
        score += min(20 + (len(payment_hits) - 1) * 5, 30)
        reasons.append("The message requests sensitive information or unusual payment.")
        indicators.append("sensitive_request")
    if prize_hits:
        score += 25
        reasons.append("The message uses a prize, giveaway, or lottery claim.")
        indicators.append("prize_claim")
    if impersonation_hits:
        score += 15
        reasons.append("The message refers to an organization or support role that could be impersonated.")
        indicators.append("impersonation_language")
    urls = _URL_PATTERN.findall(text)
    for raw_url in urls[:5]:
        url_score, url_reasons, url_indicators = _url_signals(raw_url)
        if url_score:
            score += min(url_score, 30)
            reasons.append("A link in the message has potentially risky URL characteristics.")
            indicators.extend(f"linked_{item}" for item in url_indicators)
            break
    if re.search(r"\b(?:password|passcode|pin|otp)\b", lowered) and re.search(
        r"\b(?:send|share|reply|enter|provide)\b", lowered
    ):
        if "credential_request" not in indicators:
            score += 25
            reasons.append("The message asks the recipient to disclose an authentication secret.")
            indicators.append("credential_request")
    if not reasons:
        reasons.append("No configured message risk indicators were detected.")
    return _result("message", score, reasons, sorted(set(indicators)))


def analyze_email(value: str) -> AnalysisResult:
    text = value.strip()
    lowered = text.lower()
    score = 0
    reasons: list[str] = []
    indicators: list[str] = []
    sender_match = re.search(r"(?im)^from:\s*(.+)$", text)
    sender_raw = sender_match.group(1).strip() if sender_match else ""
    sender = (parseaddr(sender_raw)[1] or sender_raw) if sender_match else ""
    if not sender_match:
        score += 10
        reasons.append("No From header was found in the supplied email text.")
        indicators.append("missing_from_header")
    if re.search(r"(?im)^reply-to:\s*(.+)$", text):
        reply_to = re.search(r"(?im)^reply-to:\s*(.+)$", text).group(1).strip()
        reply_address = parseaddr(reply_to)[1] or reply_to
        sender_domain = re.search(r"@([^>\s]+)", sender)
        reply_domain = re.search(r"@([^>\s]+)", reply_address)
        if sender_domain and reply_domain and sender_domain.group(1).lower() != reply_domain.group(1).lower():
            score += 25
            reasons.append("Reply-To domain differs from the sender domain.")
            indicators.append("reply_to_mismatch")
    if re.search(r"(?im)^subject:.*(?:urgent|suspended|verify|action required)", text):
        score += 20
        reasons.append("The subject uses urgency or account-warning language.")
        indicators.append("urgent_subject")
    message_result = analyze_message(text)
    if "urgency_language" in message_result.indicators and "urgent_subject" not in indicators:
        score += 20
        reasons.append("The email body uses urgency or account-pressure language.")
        indicators.append("urgency_language")
    if "credential_request" in message_result.indicators:
        score += 25
        reasons.append("The email asks the recipient to disclose an authentication secret.")
        indicators.append("credential_request")
    if "prize_claim" in message_result.indicators:
        score += 25
        reasons.append("The email uses a prize, giveaway, or lottery claim.")
        indicators.append("prize_claim")
    if "impersonation_language" in message_result.indicators:
        score += 15
        reasons.append("The email refers to an organization or support role that could be impersonated.")
        indicators.append("impersonation_language")
    urls = _URL_PATTERN.findall(text)
    for raw_url in urls[:5]:
        url_score, _, url_indicators = _url_signals(raw_url)
        if url_score:
            score += min(url_score, 30)
            reasons.append("A link in the email has potentially risky URL characteristics.")
            indicators.extend(f"linked_{item}" for item in url_indicators)
            break
    for term in _PAYMENT_TERMS:
        if term in lowered:
            score += 20
            reasons.append("The email mentions a sensitive-information or unusual-payment request.")
            indicators.append("sensitive_request")
            break
    if sender and not re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", sender.strip("<> ")):
        score += 10
        reasons.append("The supplied sender address has an unusual or incomplete email format.")
        indicators.append("unusual_sender_format")
    sender_domain = re.search(r"@([^>\s]+)", sender)
    if sender_domain and urls and is_valid_url(urls[0]):
        sender_host = sender_domain.group(1).lower().rstrip(".")
        link_host = (urlsplit(_normalize_url(urls[0])).hostname or "").lower().rstrip(".")
        if link_host and sender_host != link_host:
            score += 10
            reasons.append(
                "The link hostname differs from the supplied sender domain; this mismatch can also occur in legitimate email."
            )
            indicators.append("sender_link_domain_difference")
    if not reasons:
        reasons.append("No configured email risk indicators were detected.")
    return _result("email", score, reasons, sorted(set(indicators)))


def extract_urls(value: str) -> list[str]:
    """Return candidate strings for analysis; this function never performs network I/O."""
    return [_normalize_url(url) for url in _URL_PATTERN.findall(value)]
