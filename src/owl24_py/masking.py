"""masking.py

Task 8 (todolist.md), expanded 2026-08-23 from the original 4 bare regexes.
This is a faithful port of owl24-js's masking.js (the reference
implementation - see that file's own header for the full research/rationale
behind every category here) - same detection categories, same masking
formats, same tests translated to this language, so behavior is consistent
across every owl24 SDK a customer might mix within one organization.
"""
import re


# --- PCI-DSS payment cards ---------------------------------------------
CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
CARD_BRAND_RE = re.compile(
    r"^(4\d{12}(?:\d{3})?|5[1-5]\d{14}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011|5\d{2})\d{12})$"
)


def luhn_valid(digits: str) -> bool:
    total = 0
    alternate = False
    for ch in reversed(digits):
        n = ord(ch) - 48
        if alternate:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alternate = not alternate
    return total % 10 == 0


def _mask_card(match: "re.Match") -> str:
    digits = re.sub(r"[ -]", "", match.group(0))
    if not CARD_BRAND_RE.match(digits) or not luhn_valid(digits):
        return match.group(0)  # not a real card - leave untouched
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]


# --- Secrets & credentials ----------------------------------------------
# Vendor-prefixed formats ported from gitleaks' config/gitleaks.toml (MIT).
SECRET_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
    # Lookahead, not \b, at the end - the token body's character class
    # includes '-', a non-word char, so a token ending in '-' would fail a
    # trailing \b assertion (the same real bug found and fixed in the JS
    # reference implementation's Bearer/JWT regex below).
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}(?![A-Za-z0-9-])"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
]

# Tightened from "Bearer + anything JWT-shaped" to the real structure (eyJ
# prefix + 3 dot-separated base64url segments). Lookahead instead of a
# trailing \b for the same reason as the Slack pattern above.
BEARER_JWT_RE = re.compile(r"\bBearer\s+eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_-])")

# Catch-all for secret formats with no fixed vendor prefix - matched
# against attribute/field NAMES, not values.
SENSITIVE_KEY_NAME_RE = re.compile(r"password|secret|token|api[_-]?key|credential|authorization", re.IGNORECASE)

# --- Financial / banking -------------------------------------------------
IBAN_CANDIDATE_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")


def _mod97(numeric: str) -> int:
    remainder = 0
    for ch in numeric:
        remainder = (remainder * 10 + (ord(ch) - 48)) % 97
    return remainder


def _iban_numeric(iban: str) -> str:
    rearranged = iban[4:] + iban[:4]
    return "".join(str(ord(c) - 55) if "A" <= c <= "Z" else c for c in rearranged)


def iban_valid(iban: str) -> bool:
    return _mod97(_iban_numeric(iban)) == 1


def _mask_iban(match: "re.Match") -> str:
    iban = match.group(0).upper()
    if not iban_valid(iban):
        return match.group(0)  # not a real IBAN - leave untouched
    country = iban[:2]
    bban = "0" * len(iban[4:])  # masked body - all zeros as the placeholder
    remainder = _mod97(_iban_numeric(country + "00" + bban))
    check_digits = str(98 - remainder).zfill(2)
    return country + check_digits + bban


# US routing numbers: 9 digits, weighted (3,7,1 repeating) checksum - a
# bare 9-digit span is inherently ambiguous, the checksum only narrows it.
ROUTING_CANDIDATE_RE = re.compile(r"\b\d{9}\b")
_ROUTING_WEIGHTS = [3, 7, 1, 3, 7, 1, 3, 7, 1]


def routing_valid(digits: str) -> bool:
    return sum((ord(digits[i]) - 48) * _ROUTING_WEIGHTS[i] for i in range(9)) % 10 == 0


# --- Location / geolocation -----------------------------------------------
# IPv4: zero the last octet. IPv6: keep the first 48 bits, zero the rest -
# both match Google Analytics' old anonymizeIp (pseudonymization, not
# anonymization - still "personal data" under GDPR).
IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
IPV6_RE = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b")


def _truncate_ipv4(match: "re.Match") -> str:
    o1, o2, o3, o4 = match.groups()
    if any(int(o) > 255 for o in (o1, o2, o3, o4)):
        return match.group(0)
    return f"{o1}.{o2}.{o3}.0"


def _truncate_ipv6(match: "re.Match") -> str:
    groups = match.group(0).split(":")
    return ":".join(groups[:3] + ["0", "0", "0", "0", "0"])


# --- Internal network topology --------------------------------------------
# RFC1918 (+loopback/link-local) via real numeric subnet math, not regex.
_PRIVATE_IPV4_RANGES = [
    ("10.0.0.0", 8),
    ("172.16.0.0", 12),
    ("192.168.0.0", 16),
    ("127.0.0.0", 8),
    ("169.254.0.0", 16),
]


def _ipv4_to_int(ip: str) -> int:
    result = 0
    for octet in ip.split("."):
        result = (result << 8) + int(octet)
    return result


def is_private_ipv4(ip: str) -> bool:
    ip_int = _ipv4_to_int(ip)
    for base, bits in _PRIVATE_IPV4_RANGES:
        mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if (ip_int & mask) == (_ipv4_to_int(base) & mask):
            return True
    return False


# Hostnames/internal DNS/cluster names have no universal spec - a small
# default suffix denylist, extended via configure_masking().
_DEFAULT_INTERNAL_HOSTNAME_SUFFIXES = [".internal", ".svc.cluster.local", ".corp"]


def _escape_literal(s: str) -> str:
    return re.escape(s)


def _build_hostname_suffix_res(suffixes):
    return [re.compile(r"\b[\w-]+(?:\.[\w-]+)*" + _escape_literal(suffix) + r"\b", re.IGNORECASE) for suffix in suffixes]


# --- Customer-configurable field-name allow/deny list ---------------------
# Denylist-default (mask only what's configured, everything else passes
# through), not allowlist-default - matches owl24-js's decision (see that
# file's own comment): owl24's "one line of code, 5-minute setup" pitch
# doesn't work if a customer has to enumerate every safe field up front.
_DEFAULT_SENSITIVE_FIELD_NAME_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"password", r"secret", r"token", r"api[_-]?key", r"credential", r"authorization",
        r"\bssn\b", r"social[_-]?security", r"\bpin\b",
        r"\bbalance\b", r"account[_-]?number", r"routing[_-]?number", r"credit[_-]?score",
        r"\bdob\b", r"date[_-]?of[_-]?birth",
    ]
]

_custom_field_name_patterns = []
_internal_hostname_suffixes = list(_DEFAULT_INTERNAL_HOSTNAME_SUFFIXES)
_hostname_suffix_res = _build_hostname_suffix_res(_internal_hostname_suffixes)


def _compile_wildcard(pattern: str) -> "re.Pattern":
    escaped = ".*".join(_escape_literal(part) for part in pattern.split("*"))
    return re.compile(f"^{escaped}$", re.IGNORECASE)


def configure_masking(mask_fields=None, internal_hostname_suffixes=None):
    """Called once from Owl24.init() - lets a customer extend (not replace)
    the default sensitive-field-name list and the internal-hostname suffix
    list. mask_fields accepts exact names or '*'-wildcard patterns (e.g.
    '*api_key*', 'pricing.*', 'internal_customer_id')."""
    global _custom_field_name_patterns, _internal_hostname_suffixes, _hostname_suffix_res
    _custom_field_name_patterns = [_compile_wildcard(p) for p in (mask_fields or [])]
    _internal_hostname_suffixes = _DEFAULT_INTERNAL_HOSTNAME_SUFFIXES + list(internal_hostname_suffixes or [])
    _hostname_suffix_res = _build_hostname_suffix_res(_internal_hostname_suffixes)


def is_sensitive_field_name(name: str) -> bool:
    """True if `name` (an attribute or log-field name) should have its
    value masked wholesale, regardless of shape."""
    return any(p.search(name) for p in _DEFAULT_SENSITIVE_FIELD_NAME_PATTERNS) or \
        any(p.match(name) for p in _custom_field_name_patterns)


def mask_sensitive_data(text) -> str:
    """Value-based masking - runs regardless of field name, since these
    formats are identifiable from their own shape wherever they appear."""
    if not isinstance(text, str):
        return text

    masked = re.sub(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL_MASKED]", text)

    for pattern in SECRET_PATTERNS:
        masked = pattern.sub("[SECRET_MASKED]", masked)

    masked = BEARER_JWT_RE.sub("[TOKEN_MASKED]", masked)
    masked = CARD_CANDIDATE_RE.sub(_mask_card, masked)
    masked = IBAN_CANDIDATE_RE.sub(_mask_iban, masked)
    masked = ROUTING_CANDIDATE_RE.sub(lambda m: "[ROUTING_MASKED]" if routing_valid(m.group(0)) else m.group(0), masked)
    masked = IPV4_RE.sub(_truncate_ipv4, masked)
    masked = IPV6_RE.sub(_truncate_ipv6, masked)

    for pattern in _hostname_suffix_res:
        masked = pattern.sub("[HOSTNAME_MASKED]", masked)

    # Last: the most generic, most over-match-prone pattern (a bounded-length
    # \b...\b digit pattern can't match a mid-run substring of a longer
    # digit sequence, but running it last, after every more specific pattern
    # has already claimed what it recognizes, is the belt-and-suspenders
    # ordering the JS reference implementation settled on after a real test
    # caught it eating digits out of Slack tokens and IBANs).
    masked = re.sub(r"\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE_MASKED]", masked)

    return masked
