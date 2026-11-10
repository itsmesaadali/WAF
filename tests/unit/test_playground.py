"""Attack playground helpers: request building and the decoding explanation."""
from __future__ import annotations

import json
from urllib.parse import parse_qsl

from app.api.playground_routes import build_request
from app.detection.engine import explain_value, inspect_request
from app.detection.normalizer import decode_rounds, deep_decode


def test_each_location_puts_the_payload_where_the_waf_inspects_it() -> None:
    payload = "<script>alert(1)</script>"
    for where, location in [("query", "query"), ("path", "path"), ("form", "body"), ("json", "body"),
                            ("header", "header:user-agent"), ("cookie", "header:cookie")]:
        facts = build_request(payload, where)
        findings = inspect_request(facts.path, facts.query, facts.headers, facts.body)
        assert any(f.location == location for f in findings), where


def test_payload_survives_placement_intact() -> None:
    payload = "a&b=c d'\"<>"
    assert dict(parse_qsl(build_request(payload, "query").query))["q"] == payload
    assert json.loads(build_request(payload, "json").body)["note"] == payload
    assert dict(parse_qsl(build_request(payload, "form").body.decode()))["message"] == payload


def test_decode_rounds_match_deep_decode() -> None:
    value = "%25253Cscript%25253E"
    rounds = decode_rounds(value)
    assert rounds == ["%253Cscript%253E", "%3Cscript%3E", "<script>"]
    assert rounds[-1] == deep_decode(value)
    assert decode_rounds("plain text") == []


def test_explain_value_points_at_the_matched_text() -> None:
    explained = explain_value("1 UN/**/ION SEL/**/ECT 1,2")
    match = next(m for m in explained["matches"] if m["rule_id"] == "SQLI-002")
    assert match["form"] == "compact"
    assert explained["compact"][match["start"]:match["end"]].startswith("unionselect")


def test_explain_value_unwraps_base64() -> None:
    explained = explain_value("JyBPUiAnMSc9JzE=")
    assert explained["base64"] == "' OR '1'='1"
    assert any(m["variant"] == "base64" for m in explained["matches"])
