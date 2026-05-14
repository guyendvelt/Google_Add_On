"""Phishing heuristics: HTML sanitization, keyword regex, URL pattern checks.

Sanitization runs first so attackers can't smuggle indicators inside HTML
tags, attributes, or scripts (PLAN.MD §6). All regex patterns are bounded
(no unbounded `.*`) to avoid catastrophic backtracking on hostile input.
"""
from __future__ import annotations

import re
from email.utils import parseaddr
from urllib.parse import urlparse

import bleach

# Label -> compiled pattern. Labels are reused verbatim in the API reasoning,
# so they should read like things a human would say in a verdict.
PHISHING_PATTERNS: dict[str, re.Pattern[str]] = {
    "urgent": re.compile(r"\burgent(?:ly)?\b", re.IGNORECASE),
    "action required": re.compile(r"\baction\s+required\b", re.IGNORECASE),
    "verify account": re.compile(
        r"\bverify\s+(?:your\s+)?(?:account|identity|email|information)\b",
        re.IGNORECASE,
    ),
    "security alert": re.compile(
        r"\bsecurity\s+(?:alert|warning|notice|breach)\b", re.IGNORECASE
    ),
    "password reset": re.compile(
        r"\b(?:password\s+reset|reset\s+(?:your\s+)?password)\b", re.IGNORECASE
    ),
    "bank details": re.compile(
        r"\bbank(?:ing)?\s+(?:details|information|info|account)\b", re.IGNORECASE
    ),
    "account suspended": re.compile(
        r"\b(?:account|access)\s+(?:has\s+been\s+|is\s+)?suspended\b", re.IGNORECASE
    ),
    "click here": re.compile(r"\bclick\s+here\b", re.IGNORECASE),
    "confirm identity": re.compile(
        r"\bconfirm\s+(?:your\s+)?(?:identity|details|account)\b", re.IGNORECASE
    ),
    "prize/lottery": re.compile(
        r"\b(?:you(?:'ve|\s+have)?\s+won|congratulations)\b.{0,120}\b(?:prize|lottery|gift\s+card|reward)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    "wire transfer": re.compile(
        r"\b(?:wire\s+transfer|send\s+(?:money|funds|payment))\b", re.IGNORECASE
    ),
}

# TLDs frequently abused for phishing (free / low-cost / spoof-friendly).
SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
     "click", "loan", "work", "country", "review", "mov"}
)

_IP_URL_PATTERN = re.compile(
    r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:[/?#]|$)", re.IGNORECASE
)

# Brands commonly impersonated in display-name spoofing. We deliberately use
# short canonical tokens that we tokenize the display name against (word-level,
# not substring) so "Cleanups Inc" won't false-match "ups".
# Executable / scriptable file extensions commonly used in malware delivery.
# Flagged regardless of where they sit in the filename.
DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
    "exe", "scr", "bat", "cmd", "com", "pif",
    "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "jar", "msi", "lnk", "ps1", "reg",
    "iso", "img", "cab",
})

# Innocuous-looking primary extensions used as bait in double-extension
# spoofing — e.g. "invoice.pdf.exe", "photo.jpg.scr". The double-extension
# label fires only when followed by a DANGEROUS_EXTENSIONS suffix.
SPOOF_PRIMARY_EXTENSIONS: frozenset[str] = frozenset({
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "txt", "csv", "rtf",
    "jpg", "jpeg", "png", "gif",
})

PROTECTED_BRANDS: frozenset[str] = frozenset({
    "paypal", "amazon", "microsoft", "apple", "google", "netflix",
    "facebook", "instagram", "linkedin", "github", "dropbox",
    "ebay", "fedex", "ups", "dhl",
    "binance", "coinbase", "spotify", "twitter",
    "chase", "barclays", "hsbc", "santander",
})

_NAME_TOKEN_RE = re.compile(r"[a-z]+")


def sanitize_text(text: str) -> str:
    """Strip every HTML tag, attribute, and comment — leaves only text content."""
    return bleach.clean(text, tags=[], attributes={}, strip=True, strip_comments=True)


def scan_keywords(text: str) -> list[str]:
    """Return the labels of phishing patterns that matched the (sanitized) text."""
    return [label for label, pattern in PHISHING_PATTERNS.items() if pattern.search(text)]


def extract_sender_domain(sender_field: str) -> str:
    """Return the lowercase domain from an RFC-2822 From line, or '' if absent.

    Accepts both `"Display <user@host>"` and bare `"user@host"`. Used for
    PII-safe scan logging (we persist the domain, never the full address).
    """
    _, addr = parseaddr(sender_field or "")
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower()


def check_sender_mismatch(sender_field: str) -> list[str]:
    """Display-name brand-impersonation detector (PLAN.MD Rule 4).

    Returns a single `display-name-mismatch:<brand>` label when the display
    name on the From line names a protected brand (`PROTECTED_BRANDS`) but
    that brand keyword does not appear in the actual sender domain. Tokens
    are split on word boundaries so "Cleanups Inc" does not match `ups`.
    """
    name, addr = parseaddr(sender_field or "")
    if not name or "@" not in addr:
        return []
    domain = addr.rsplit("@", 1)[-1].lower()
    if not domain:
        return []
    name_tokens = set(_NAME_TOKEN_RE.findall(name.lower()))
    if not name_tokens:
        return []
    for brand in PROTECTED_BRANDS:
        if brand in name_tokens and brand not in domain:
            return [f"display-name-mismatch:{brand}"]
    return []


def check_attachment_filename(name: str) -> list[str]:
    """Filename-only heuristics for dangerous attachments.

    Returns a list of labels — empty if the filename looks safe. Two checks:

    * **Single dangerous extension** — `.exe`, `.scr`, `.vbs`, etc. Common
      malware delivery vectors that almost never belong in legitimate email.
    * **Double-extension spoofing** — a primary "decoy" extension followed by
      a dangerous one (`invoice.pdf.exe`, `photo.jpg.scr`). The decoy is what
      the user sees if their OS hides "known" extensions.

    Both labels can fire on the same filename; the caller is responsible for
    only counting the rule once toward the score.
    """
    if not name:
        return []
    lowered = name.lower().strip().rstrip(".")
    if "." not in lowered:
        return []
    parts = lowered.rsplit(".", 2)
    last_ext = parts[-1]

    triggered: list[str] = []
    if last_ext in DANGEROUS_EXTENSIONS:
        triggered.append(f"dangerous-extension:.{last_ext}")
    if len(parts) >= 3:
        primary = parts[-2]
        if primary in SPOOF_PRIMARY_EXTENSIONS and last_ext in DANGEROUS_EXTENSIONS:
            triggered.append(f"double-extension:.{primary}.{last_ext}")
    return triggered


def check_link_heuristics(url: str) -> list[str]:
    """Return heuristic labels triggered by this URL (empty if clean)."""
    triggered: list[str] = []

    if _IP_URL_PATTERN.match(url):
        triggered.append("ip-address-as-host")

    try:
        hostname = (urlparse(url).hostname or "").lower()
    except ValueError:
        return triggered

    if hostname:
        tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
        if tld in SUSPICIOUS_TLDS:
            triggered.append(f"suspicious-tld:.{tld}")

        # Deep subdomain spoofing, e.g. accounts.google.com.evil.tk
        if hostname.count(".") >= 4:
            triggered.append("deep-subdomain")

    return triggered
