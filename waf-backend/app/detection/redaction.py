"""Remove passwords and tokens before anything is written to logs (data minimization)."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode

SENSITIVE = re.compile(
    r"pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|apikey|auth|session|sid|jwt|bearer|otp|pin|cvv|card|ssn",
    re.IGNORECASE,
)
_INLINE_SECRET = re.compile(
    r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[-_]?key|authorization|bearer|session(?:id)?|jwt)\b(\s*[=:]\s*|\s+)([^\s&;,'\"]+)"
)
_JWT = re.compile(r"\beyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}\b")
MASK = "[REDACTED]"
MAX_LOGGED_QUERY = 1024


def redact_query(query: str) -> str | None:
    if not query:
        return None
    pairs = parse_qsl(query, keep_blank_values=True)
    if not pairs:
        return redact_text(query)[:MAX_LOGGED_QUERY]
    cleaned = [(k, MASK if SENSITIVE.search(k) else redact_text(v)) for k, v in pairs]
    return urlencode(cleaned, safe="[]")[:MAX_LOGGED_QUERY]


def redact_text(text: str) -> str:
    masked = _INLINE_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    return _JWT.sub(MASK, masked)
