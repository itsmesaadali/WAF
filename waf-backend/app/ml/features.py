"""Turn a request into numbers the Isolation Forest can compare.

Features describe the shape of a request and the sender's behaviour. They deliberately
contain no attack keywords, so ML provides evidence independent of the signatures.
No raw values are kept: only these numbers are stored for later retraining.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qsl

FEATURE_NAMES: tuple[str, ...] = (
    "path_length",
    "path_depth",
    "query_length",
    "param_count",
    "max_param_length",
    "body_length",
    "special_char_ratio",
    "percent_encoded_ratio",
    "digit_ratio",
    "uppercase_ratio",
    "query_entropy",
    "path_entropy",
    "header_count",
    "user_agent_length",
    "missing_accept",
    "method_rarity",
    "requests_last_minute",
    "unique_paths_last_minute",
    "error_ratio_last_minute",
)

_SPECIAL = re.compile(r"[^A-Za-z0-9/_.\-=&?%+:,~ ]")
_PERCENT = re.compile(r"%[0-9a-fA-F]{2}")
_METHOD_RARITY = {"GET": 0.0, "HEAD": 0.2, "POST": 0.2, "OPTIONS": 0.4, "PUT": 0.5, "PATCH": 0.5, "DELETE": 0.6}
MAX_TEXT_FOR_FEATURES = 8192


@dataclass(frozen=True)
class RequestView:
    method: str
    path: str
    query: str
    header_count: int
    user_agent: str
    has_accept: bool
    body: bytes
    requests_last_minute: int = 1
    unique_paths_last_minute: int = 1
    error_ratio_last_minute: float = 0.0


def entropy(text: str) -> float:
    """Shannon entropy: random-looking text scores higher than ordinary words."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def extract(view: RequestView) -> list[float]:
    """Return values in FEATURE_NAMES order. Log scales stop huge values from dominating."""
    path = view.path[:MAX_TEXT_FOR_FEATURES]
    query = view.query[:MAX_TEXT_FOR_FEATURES]
    body = view.body[:MAX_TEXT_FOR_FEATURES].decode("utf-8", errors="replace")
    text = f"{path}?{query}{body}"
    length = max(1, len(text))
    params = parse_qsl(query, keep_blank_values=True)
    return [
        math.log1p(len(view.path)),
        float(path.count("/")),
        math.log1p(len(view.query)),
        float(len(params)),
        math.log1p(max((len(v) for _, v in params), default=0)),
        math.log1p(len(view.body)),
        len(_SPECIAL.findall(text)) / length,
        len(_PERCENT.findall(text)) * 3 / length,
        sum(c.isdigit() for c in text) / length,
        sum(c.isupper() for c in text) / length,
        entropy(query),
        entropy(path),
        float(view.header_count),
        math.log1p(len(view.user_agent)),
        0.0 if view.has_accept else 1.0,
        _METHOD_RARITY.get(view.method.upper(), 1.0),
        math.log1p(view.requests_last_minute),
        math.log1p(view.unique_paths_last_minute),
        view.error_ratio_last_minute,
    ]
