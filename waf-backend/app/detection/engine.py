"""Runs signatures over every attacker-controlled part of a request."""
from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import parse_qsl

from .normalizer import MAX_INSPECT_CHARS, compact, decode_rounds, deep_decode, normalize, try_base64
from .signatures import ALL_RULES, Rule

# Headers an attacker can set freely. Cookie is handled separately to avoid false positives.
INSPECTED_HEADERS = ("user-agent", "referer", "x-forwarded-host", "x-original-url", "x-rewrite-url", "origin")
SEVERITY_ORDER = {"medium": 1, "high": 2, "critical": 3}
EVIDENCE_LIMIT = 200
# Cookies often hold long tokens, so only the most reliable rules run on them.
COOKIE_RULE_SEVERITIES = {"critical"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    attack: str
    severity: str
    location: str
    evidence: str


def _evidence(text: str, start: int, end: int) -> str:
    return text[max(0, start - 30) : min(len(text), end + 30)][:EVIDENCE_LIMIT]


def _match(rule: Rule, normal: str, compacted: str) -> tuple[str, int, int] | None:
    text = compacted if rule.form == "compact" else normal
    found = rule.pattern.search(text)
    return (text, found.start(), found.end()) if found else None


def unwrap_base64(value: str) -> str | None:
    """Base64 text, even when it was URL-encoded or entity-encoded on top."""
    return try_base64(value) or try_base64(deep_decode(value))


def scan_value(value: str, location: str, severities: set[str] | None = None) -> list[Finding]:
    """Check one value in its normalized forms and return a finding per matching rule."""
    if not value:
        return []
    variants = [value]
    decoded = unwrap_base64(value)
    if decoded:
        variants.append(decoded)

    findings: list[Finding] = []
    seen: set[str] = set()
    for variant in variants:
        normal, compacted = normalize(variant), compact(variant)
        for rule in ALL_RULES:
            if rule.id in seen or (severities and rule.severity not in severities):
                continue
            hit = _match(rule, normal, compacted)
            if hit:
                seen.add(rule.id)
                findings.append(
                    Finding(rule.id, rule.name, rule.attack, rule.severity, location, _evidence(*hit))
                )
    return findings


def explain_value(value: str) -> dict:
    """Show the forms the signatures see for one value, and where each rule matched."""
    decoded = unwrap_base64(value)
    matches: list[dict] = []
    seen: set[str] = set()
    for variant_name, variant in (("text", value), ("base64", decoded)):
        if not variant:
            continue
        normal, compacted = normalize(variant), compact(variant)
        for rule in ALL_RULES:
            if rule.id in seen:
                continue
            text = compacted if rule.form == "compact" else normal
            found = rule.pattern.search(text)
            if found:
                seen.add(rule.id)
                matches.append({
                    "rule_id": rule.id, "variant": variant_name, "form": rule.form,
                    "start": found.start(), "end": found.end(),
                })
    return {
        "rounds": decode_rounds(value),
        "normalized": normalize(value),
        "compact": compact(value),
        "base64": decoded,
        "base64_normalized": normalize(decoded) if decoded else None,
        "base64_compact": compact(decoded) if decoded else None,
        "matches": matches,
    }


def _json_strings(node: object, depth: int = 0) -> list[str]:
    """Collect keys and string values from JSON, so nested payloads cannot hide."""
    if depth > 20:
        return []
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        out: list[str] = []
        for key, value in node.items():
            out.append(str(key))
            out.extend(_json_strings(value, depth + 1))
        return out
    if isinstance(node, list):
        out = []
        for item in node:
            out.extend(_json_strings(item, depth + 1))
        return out
    return []


def body_values(body: bytes, content_type: str) -> list[str]:
    """Split a body into individual values, always including the raw text as well."""
    text = body[:MAX_INSPECT_CHARS].decode("utf-8", errors="replace")
    values = [text]
    kind = content_type.split(";")[0].strip().lower()
    if kind == "application/x-www-form-urlencoded":
        for key, value in parse_qsl(text, keep_blank_values=True):
            values.extend((key, value))
    elif "json" in kind:
        try:
            values.extend(_json_strings(json.loads(text)))
        except (ValueError, RecursionError):
            pass
    return values


def inspect_request(
    path: str,
    query: str,
    headers: dict[str, str],
    body: bytes,
) -> list[Finding]:
    """Return all findings for a request, most severe first."""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add(items: list[Finding]) -> None:
        for item in items:
            key = (item.rule_id, item.location)
            if key not in seen:
                seen.add(key)
                findings.append(item)

    add(scan_value(path, "path"))
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        add(scan_value(query, "query"))
        for key, value in pairs:
            add(scan_value(key, "query"))
            add(scan_value(value, "query"))
        # Repeated parameters can be joined by the app, so check them joined as well.
        if len(pairs) > 1:
            add(scan_value(" ".join(value for _, value in pairs), "query"))

    for name in INSPECTED_HEADERS:
        value = headers.get(name)
        if value:
            add(scan_value(value, f"header:{name}"))

    cookie = headers.get("cookie")
    if cookie:
        add(scan_value(cookie, "header:cookie", COOKIE_RULE_SEVERITIES))

    if body:
        for value in body_values(body, headers.get("content-type", "")):
            add(scan_value(value, "body"))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
    return findings
