"""End-to-end checks of the proxy, detection, logging, bans and fail-safes."""
from __future__ import annotations

import base64
import gzip

import httpx
import psycopg

from .conftest import API, SHARED_SECRET, wait_for

FREE_PORT_FOR_DOWN_TEST = 8101
FREE_PORT_FOR_RESTART_TEST = 8102
UNUSED_UPSTREAM = "http://127.0.0.1:3999"


def incidents_for(client: httpx.Client, headers: dict, ip: str) -> list[dict]:
    return client.get(f"{API}/incidents", headers=headers, params={"ip": ip}).json()["items"]


def traffic_for(client: httpx.Client, headers: dict, ip: str) -> list[dict]:
    return client.get(f"{API}/traffic", headers=headers, params={"ip": ip}).json()["items"]


# --- Reverse proxy ---
def test_normal_request_reaches_the_website_through_the_waf(client, visitor) -> None:
    response = client.get("/products", params={"q": "book"}, headers=visitor)
    assert response.status_code == 200
    assert "Security Handbook" in response.text
    assert response.headers["x-waf"] == "hybrid"


def test_post_json_and_status_codes_pass_through(client, visitor) -> None:
    created = client.post("/api/orders", json={"productId": 1, "quantity": 2}, headers=visitor)
    assert created.status_code == 201 and created.json()["ok"] is True
    assert client.get("/no-such-page", headers=visitor).status_code == 404


def test_redirect_stays_on_the_waf(client, visitor) -> None:
    response = client.get("/redirect-home", headers=visitor, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/"


def test_website_refuses_direct_access(site) -> None:
    assert httpx.get(f"{site}/").status_code == 403
    assert httpx.get(f"{site}/", headers={"x-waf-secret": "guess"}).status_code == 403


def test_secret_is_never_exposed_to_visitors(client, visitor) -> None:
    response = client.get("/", headers=visitor)
    assert SHARED_SECRET not in response.text
    assert SHARED_SECRET not in str(response.headers)
    assert "x-waf-secret" not in response.headers


def test_visitor_supplied_secret_header_is_replaced(client, visitor) -> None:
    response = client.get("/", headers={**visitor, "x-waf-secret": "attacker"})
    assert response.status_code == 200


def test_waf_namespace_is_not_forwarded(client, visitor) -> None:
    assert client.get("/__waf/unknown", headers=visitor).status_code == 404


def test_public_ping_reveals_nothing(client) -> None:
    assert client.get("/__waf/ping").json() == {"status": "ok"}


# --- Detection and logging ---
def test_sqli_blocked_logged_and_never_forwarded(client, visitor, admin_headers) -> None:
    ip = visitor["x-forwarded-for"]
    response = client.get("/products", params={"q": "' OR '1'='1"}, headers=visitor)
    assert response.status_code == 403
    assert "SQLI" not in response.text, "the block page must not reveal rule details"

    found = wait_for(lambda: incidents_for(client, admin_headers, ip))
    assert found and found[0]["attack_type"] == "sqli" and found[0]["action_taken"] == "blocked"
    logs = wait_for(lambda: traffic_for(client, admin_headers, ip))
    assert logs[0]["action"] == "blocked"
    assert logs[0]["upstream_ms"] is None, "a blocked request must not reach the website"


def test_xss_in_form_body_blocked(client, visitor, admin_headers) -> None:
    response = client.post("/contact", data={"name": "<script>alert(1)</script>", "message": "x"}, headers=visitor)
    assert response.status_code == 403
    found = wait_for(lambda: incidents_for(client, admin_headers, visitor["x-forwarded-for"]))
    assert found[0]["attack_type"] == "xss" and found[0]["location"] == "body"


def test_double_encoded_attack_blocked(client, visitor) -> None:
    assert client.get("/products?q=%2527%2520OR%25201%253D1%2520--", headers=visitor).status_code == 403


def test_base64_hidden_attack_blocked(client, visitor) -> None:
    payload = base64.b64encode(b"' UNION SELECT 1,2 --").decode()
    assert client.get("/products", params={"q": payload}, headers=visitor).status_code == 403


def test_compressed_body_cannot_hide_a_payload(client, visitor, admin_headers) -> None:
    body = gzip.compress(b"name=<script>alert(1)</script>")
    response = client.post("/contact", content=body, headers={**visitor, "content-encoding": "gzip"})
    assert response.status_code == 403
    found = wait_for(lambda: incidents_for(client, admin_headers, visitor["x-forwarded-for"]))
    assert found[0]["attack_type"] == "evasion"


def test_oversized_body_refused(client, visitor) -> None:
    assert client.post("/contact", content=b"x" * 70000, headers=visitor).status_code == 413


def test_benign_text_with_sql_words_is_allowed(client, visitor) -> None:
    for q in ("please select a plan from the list", "O'Brien's guide", "drop me a line"):
        assert client.get("/products", params={"q": q}, headers=visitor).status_code == 200


def test_sensitive_values_are_not_stored(client, visitor, admin_headers, db: psycopg.Connection) -> None:
    ip = visitor["x-forwarded-for"]
    client.get("/products", params={"q": "book", "password": "hunter2-secret", "token": "tok-abc-secret"}, headers=visitor)
    logs = wait_for(lambda: traffic_for(client, admin_headers, ip))
    assert "hunter2-secret" not in logs[0]["query"] and "tok-abc-secret" not in logs[0]["query"]
    row = db.execute("SELECT count(*) FROM request_logs WHERE query LIKE '%hunter2%'").fetchone()
    assert row == (0,)


# --- Rate limiting and bans ---
def test_rate_limit_returns_429_then_recovers_for_others(client, visitor, admin_headers) -> None:
    client.patch(f"{API}/settings", headers=admin_headers, json={"rate_limit_per_minute": 10})
    try:
        statuses = [client.get("/", headers=visitor).status_code for _ in range(14)]
        assert 429 in statuses
        other = {**visitor, "x-forwarded-for": "198.51.100.200"}
        assert client.get("/", headers=other).status_code == 200
    finally:
        client.patch(f"{API}/settings", headers=admin_headers, json={"rate_limit_per_minute": 300})


def test_repeated_attacks_cause_a_temporary_ban_and_unban_works(client, visitor, admin_headers) -> None:
    ip = visitor["x-forwarded-for"]
    for _ in range(5):
        assert client.get("/products", params={"q": "<script>x</script>"}, headers=visitor).status_code == 403
    denied = client.get("/", headers=visitor)
    assert denied.status_code == 403 and "temporarily blocked" in denied.text

    bans = wait_for(lambda: [b for b in client.get(f"{API}/bans", headers=admin_headers).json()["items"] if b["ip"] == ip])
    assert bans and bans[0]["source"] == "auto" and bans[0]["expires_at"]

    assert client.delete(f"{API}/bans/{bans[0]['id']}", headers=admin_headers).status_code == 200
    assert client.get("/", headers=visitor).status_code == 200


def test_allowlisted_ip_is_still_inspected_but_never_banned(client, visitor, admin_headers) -> None:
    ip = visitor["x-forwarded-for"]
    client.patch(f"{API}/settings", headers=admin_headers, json={"ip_allowlist": [ip]})
    try:
        for _ in range(7):
            assert client.get("/products", params={"q": "<script>x</script>"}, headers=visitor).status_code == 403
    finally:
        client.patch(f"{API}/settings", headers=admin_headers, json={"ip_allowlist": []})
    assert client.get("/", headers=visitor).status_code == 200, "no ban should have been created while allowlisted"


def test_manual_ban_and_expiry_of_finished_bans(client, visitor, admin_headers, db: psycopg.Connection) -> None:
    ip = visitor["x-forwarded-for"]
    created = client.post(f"{API}/bans", headers=admin_headers, json={"ip": ip, "reason": "manual test", "minutes": 5})
    assert created.status_code == 201
    assert client.get("/", headers=visitor).status_code == 403
    client.delete(f"{API}/bans/{created.json()['id']}", headers=admin_headers)
    assert client.get("/", headers=visitor).status_code == 200


def test_invalid_ban_ip_is_rejected(client, admin_headers) -> None:
    response = client.post(f"{API}/bans", headers=admin_headers, json={"ip": "not-an-ip", "reason": "test reason"})
    assert response.status_code == 422


def test_visitor_cannot_fake_their_ip_to_escape_a_ban(client, visitor, admin_headers) -> None:
    ip = visitor["x-forwarded-for"]
    created = client.post(f"{API}/bans", headers=admin_headers, json={"ip": ip, "reason": "spoof test", "minutes": 5})
    # The left entry is attacker-supplied. The right entry is the one the trusted proxy added.
    spoofed = {**visitor, "x-forwarded-for": f"8.8.8.8, {ip}"}
    assert client.get("/", headers=spoofed).status_code == 403
    client.delete(f"{API}/bans/{created.json()['id']}", headers=admin_headers)


def test_ban_survives_a_waf_restart(waf_factory, client, visitor, admin_headers) -> None:
    ip = visitor["x-forwarded-for"]
    created = client.post(f"{API}/bans", headers=admin_headers, json={"ip": ip, "reason": "restart test", "minutes": 5})
    process = waf_factory(FREE_PORT_FOR_RESTART_TEST)
    try:
        fresh = httpx.get(f"http://127.0.0.1:{FREE_PORT_FOR_RESTART_TEST}/", headers=visitor, timeout=30)
        assert fresh.status_code == 403, "a new WAF process must load bans from the database"
    finally:
        process.terminate()
        process.wait(15)
        client.delete(f"{API}/bans/{created.json()['id']}", headers=admin_headers)


# --- Monitor mode ---
def test_monitor_mode_logs_but_forwards(client, visitor, admin_headers) -> None:
    ip = visitor["x-forwarded-for"]
    client.patch(f"{API}/settings", headers=admin_headers, json={"mode": "monitor"})
    try:
        response = client.get("/products", params={"q": "<script>x</script>"}, headers=visitor)
        assert response.status_code == 200
        assert "&lt;script&gt;" in response.text, "the website's own escaping is the next layer of defense"
        found = wait_for(lambda: incidents_for(client, admin_headers, ip))
        assert found[0]["action_taken"] == "logged"
        logs = wait_for(lambda: traffic_for(client, admin_headers, ip))
        assert logs[0]["action"] == "flagged"
    finally:
        client.patch(f"{API}/settings", headers=admin_headers, json={"mode": "block"})


# --- Machine learning ---
def test_every_forwarded_request_gets_an_anomaly_score(client, visitor, admin_headers) -> None:
    client.get("/products", headers=visitor)
    logs = wait_for(lambda: traffic_for(client, admin_headers, visitor["x-forwarded-for"]))
    assert logs[0]["anomaly_score"] is not None


def test_unusual_request_is_flagged_but_not_blocked_by_default(client, admin_headers, visitor) -> None:
    ip = visitor["x-forwarded-for"]
    noise = "aZ9xQ7" * 300
    odd = {"x-forwarded-for": ip, "user-agent": "x"}
    response = client.get("/api/products", params={"blob": noise}, headers=odd)
    assert response.status_code == 200, "ML alone must not block by default"
    logs = wait_for(lambda: traffic_for(client, admin_headers, ip))
    assert logs[0]["is_anomaly"] is True and logs[0]["action"] == "flagged"
    found = wait_for(lambda: incidents_for(client, admin_headers, ip))
    assert found[0]["attack_type"] == "anomaly" and found[0]["action_taken"] == "logged"


def test_ml_block_option_blocks_anomalies(client, admin_headers, visitor) -> None:
    client.patch(f"{API}/settings", headers=admin_headers, json={"ml_block": True})
    try:
        odd = {"x-forwarded-for": visitor["x-forwarded-for"], "user-agent": "x"}
        assert client.get("/api/products", params={"blob": "aZ9xQ7" * 300}, headers=odd).status_code == 403
    finally:
        client.patch(f"{API}/settings", headers=admin_headers, json={"ml_block": False})


# --- Fail-safes ---
def test_website_down_returns_502_and_is_logged(waf_factory, db: psycopg.Connection) -> None:
    process = waf_factory(FREE_PORT_FOR_DOWN_TEST, upstream=UNUSED_UPSTREAM)
    ip = "198.51.100.201"
    try:
        response = httpx.get(f"http://127.0.0.1:{FREE_PORT_FOR_DOWN_TEST}/x", headers={"x-forwarded-for": ip}, timeout=30)
        assert response.status_code == 502
        assert UNUSED_UPSTREAM not in response.text
        attack = httpx.get(f"http://127.0.0.1:{FREE_PORT_FOR_DOWN_TEST}/", params={"q": "<script>x</script>"}, headers={"x-forwarded-for": ip}, timeout=30)
        assert attack.status_code == 403, "attacks are still blocked while the website is down"
        rows = wait_for(lambda: db.execute("SELECT action FROM request_logs WHERE client_ip=%s AND status_code=502", (ip,)).fetchall())
        assert rows == [("error",)]
    finally:
        process.terminate()
        process.wait(15)


def test_settings_changes_persist_and_validate(client, admin_headers, db: psycopg.Connection) -> None:
    bad = client.patch(f"{API}/settings", headers=admin_headers, json={"mode": "off"})
    assert bad.status_code == 422
    bad_key = client.patch(f"{API}/settings", headers=admin_headers, json={"unknown_key": 1})
    assert bad_key.status_code == 422
    client.patch(f"{API}/settings", headers=admin_headers, json={"ban_minutes": 20})
    stored = db.execute("SELECT value FROM settings WHERE key='waf'").fetchone()
    assert stored[0]["ban_minutes"] == 20
    client.patch(f"{API}/settings", headers=admin_headers, json={"ban_minutes": 15})
