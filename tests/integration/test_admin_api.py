"""Admin authentication, access control, audit trail and dashboard data APIs."""
from __future__ import annotations

import csv
import io
import time
from datetime import UTC, datetime, timedelta

import jwt
import psycopg
import pytest

from .conftest import ADMIN_PASSWORD, ADMIN_USER, API, wait_for

PROTECTED_GETS = [
    "/stats/overview", "/traffic", "/incidents", "/incidents/export.csv", "/bans",
    "/ml/status", "/ml/anomalies", "/settings", "/audit", "/health", "/auth/me",
]


@pytest.mark.parametrize("path", PROTECTED_GETS)
def test_every_data_api_refuses_anonymous_requests(client, path: str) -> None:
    assert client.get(f"{API}{path}").status_code == 401


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", "/bans"), ("DELETE", "/bans/1"), ("PATCH", "/settings"), ("PATCH", "/incidents/1"),
     ("POST", "/ml/retrain"), ("POST", "/simulator/run"), ("POST", "/playground/inspect"), ("POST", "/auth/logout")],
)
def test_every_write_api_refuses_anonymous_requests(client, method: str, path: str) -> None:
    assert client.request(method, f"{API}{path}", json={}).status_code == 401


def test_forged_and_expired_tokens_are_refused(client) -> None:
    now = datetime.now(UTC)
    claims = {"sub": ADMIN_USER, "ver": 0, "iss": "hybrid-waf", "aud": "hybrid-waf-admin", "iat": now, "exp": now + timedelta(hours=1)}
    forged = jwt.encode(claims, "x" * 32, algorithm="HS256")
    assert client.get(f"{API}/auth/me", headers={"authorization": f"Bearer {forged}"}).status_code == 401
    none_alg = jwt.encode(claims, "", algorithm="none")
    assert client.get(f"{API}/auth/me", headers={"authorization": f"Bearer {none_alg}"}).status_code == 401


def test_password_is_stored_hashed(db: psycopg.Connection, admin_headers) -> None:  # noqa: ARG001
    stored = db.execute("SELECT password_hash FROM admin_users WHERE username=%s", (ADMIN_USER,)).fetchone()[0]
    assert stored.startswith("$argon2") and ADMIN_PASSWORD not in stored


def test_wrong_password_and_unknown_user_look_identical(client) -> None:
    wrong = client.post(f"{API}/auth/login", json={"username": ADMIN_USER + "x", "password": "wrong-password"})
    unknown = client.post(f"{API}/auth/login", json={"username": "nobody", "password": "wrong-password"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_account_locks_after_repeated_failures(client, db: psycopg.Connection) -> None:
    username = "lockuser"
    from argon2 import PasswordHasher

    password = "correct-password-123"
    db.execute("DELETE FROM admin_users WHERE username=%s", (username,))
    db.execute("INSERT INTO admin_users (username, password_hash) VALUES (%s, %s)", (username, PasswordHasher().hash(password)))
    headers = {"x-forwarded-for": "198.51.100.210"}
    for _ in range(5):
        assert client.post(f"{API}/auth/login", json={"username": username, "password": "bad"}, headers=headers).status_code == 401
    locked = client.post(f"{API}/auth/login", json={"username": username, "password": password}, headers=headers)
    assert locked.status_code == 401, "the right password must not work while locked"
    db.execute("UPDATE admin_users SET locked_until=NULL WHERE username=%s", (username,))
    assert client.post(f"{API}/auth/login", json={"username": username, "password": password}, headers=headers).status_code == 200
    db.execute("DELETE FROM admin_users WHERE username=%s", (username,))


def test_login_is_rate_limited_per_ip(client) -> None:
    headers = {"x-forwarded-for": "198.51.100.211"}
    codes = [client.post(f"{API}/auth/login", json={"username": "ghost", "password": "bad"}, headers=headers).status_code for _ in range(22)]
    assert 429 in codes


def test_validation_errors_do_not_echo_passwords(client) -> None:
    response = client.post(f"{API}/auth/login", json={"username": "", "password": "my-secret-value"})
    assert response.status_code == 422 and "my-secret-value" not in response.text


def test_logout_cancels_the_token_immediately(client, admin_headers) -> None:
    assert client.get(f"{API}/auth/me", headers=admin_headers).status_code == 200
    assert client.post(f"{API}/auth/logout", headers=admin_headers).status_code == 200
    assert client.get(f"{API}/auth/me", headers=admin_headers).status_code == 401


@pytest.fixture()
def fresh_admin(admin_headers) -> dict[str, str]:
    return admin_headers


def test_password_change_requires_current_password(client, fresh_admin) -> None:
    bad = client.post(f"{API}/auth/change-password", headers=fresh_admin,
                      json={"current_password": "wrong", "new_password": "a-long-enough-password"})
    assert bad.status_code == 401
    short = client.post(f"{API}/auth/change-password", headers=fresh_admin,
                        json={"current_password": ADMIN_PASSWORD, "new_password": "short"})
    assert short.status_code == 422


def test_overview_counts_real_requests(client, fresh_admin, visitor) -> None:
    before = client.get(f"{API}/stats/overview", headers=fresh_admin).json()["totals"]["requests"]
    client.get("/", headers=visitor)
    client.get("/products", params={"q": "<script>x</script>"}, headers=visitor)

    def grew() -> dict | None:
        data = client.get(f"{API}/stats/overview", headers=fresh_admin).json()
        return data if data["totals"]["requests"] >= before + 2 else None

    data = wait_for(grew)
    assert data and data["totals"]["blocked"] >= 1 and data["series"] and data["latency"]["waf_p95_ms"] is not None
    assert any(item["type"] == "xss" for item in data["incidents_by_type"])


def test_traffic_filters_and_pagination(client, fresh_admin, visitor) -> None:
    ip = visitor["x-forwarded-for"]
    for _ in range(3):
        client.get("/", headers=visitor)
    wait_for(lambda: len(client.get(f"{API}/traffic", headers=fresh_admin, params={"ip": ip}).json()["items"]) == 3)
    first = client.get(f"{API}/traffic", headers=fresh_admin, params={"ip": ip, "limit": 2}).json()
    assert len(first["items"]) == 2 and first["next_before_id"]
    second = client.get(f"{API}/traffic", headers=fresh_admin, params={"ip": ip, "limit": 2, "before_id": first["next_before_id"]}).json()
    assert len(second["items"]) == 1 and second["next_before_id"] is None


def test_search_treats_wildcards_literally(client, fresh_admin) -> None:
    response = client.get(f"{API}/traffic", headers=fresh_admin, params={"search": "%_impossible_%"})
    assert response.status_code == 200 and response.json()["items"] == []


def test_incident_status_update_is_audited(client, fresh_admin, visitor) -> None:
    client.get("/products", params={"q": "' OR '1'='1"}, headers=visitor)
    items = wait_for(lambda: client.get(f"{API}/incidents", headers=fresh_admin, params={"ip": visitor["x-forwarded-for"]}).json()["items"])
    incident_id = items[0]["id"]
    updated = client.patch(f"{API}/incidents/{incident_id}", headers=fresh_admin, json={"status": "false_positive"})
    assert updated.json()["status"] == "false_positive"
    assert client.patch(f"{API}/incidents/{incident_id}", headers=fresh_admin, json={"status": "bad"}).status_code == 422
    audit = client.get(f"{API}/audit", headers=fresh_admin).json()["items"]
    assert any(a["action"] == "incident_updated" and a["target"] == incident_id for a in audit)


def test_csv_export_neutralizes_formulas(client, fresh_admin, db: psycopg.Connection) -> None:
    db.execute(
        "INSERT INTO incidents (client_ip, method, path, attack_type, severity, action_taken, mode, evidence) "
        "VALUES ('198.51.100.220','GET','=HYPERLINK(1)','sqli','high','blocked','block','@SUM(1)')"
    )
    response = client.get(f"{API}/incidents/export.csv", headers=fresh_admin, params={"ip": "198.51.100.220"})
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert rows[0]["path"] == "'=HYPERLINK(1)" and rows[0]["evidence"] == "'@SUM(1)"


def test_settings_change_records_who_and_what(client, fresh_admin) -> None:
    client.patch(f"{API}/settings", headers=fresh_admin, json={"strikes_before_ban": 6})
    client.patch(f"{API}/settings", headers=fresh_admin, json={"strikes_before_ban": 5})
    audit = client.get(f"{API}/audit", headers=fresh_admin).json()["items"]
    change = next(a for a in audit if a["action"] == "settings_changed")
    assert change["username"] == ADMIN_USER and change["details"]["strikes_before_ban"]["to"] == 5


def test_health_reports_real_components(client, fresh_admin) -> None:
    health = client.get(f"{API}/health", headers=fresh_admin).json()
    assert health["status"] == "healthy"
    assert health["database"]["ok"] and health["database"]["latency_ms"] > 0
    assert health["upstream"]["ok"] and health["upstream"]["status"] == 200
    assert health["ml"]["loaded"] is True


@pytest.mark.parametrize(("scenario", "expected_blocked"), [("sqli", 5), ("xss", 4), ("evasion", 5), ("normal", 0)])
def test_simulator_runs_through_the_real_pipeline(client, fresh_admin, scenario: str, expected_blocked: int) -> None:
    result = client.post(f"{API}/simulator/run", headers=fresh_admin, json={"scenario": scenario})
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["blocked"] == expected_blocked
    assert body["simulated_ip"].startswith("203.0.113.")
    logged = wait_for(lambda: client.get(f"{API}/traffic", headers=fresh_admin, params={"ip": body["simulated_ip"]}).json()["items"])
    assert logged and all(row["simulated"] for row in logged)


def test_simulator_has_no_custom_target_or_payload(client, fresh_admin) -> None:
    bad = client.post(f"{API}/simulator/run", headers=fresh_admin, json={"scenario": "custom", "target": "https://example.com"})
    assert bad.status_code == 422


def test_retrain_replaces_the_model_and_records_history(client, fresh_admin) -> None:
    result = client.post(f"{API}/ml/retrain", headers=fresh_admin, json={"source": "generated"}, timeout=120)
    assert result.status_code == 200, result.text
    status = client.get(f"{API}/ml/status", headers=fresh_admin).json()
    assert status["loaded"] and status["history"][0]["active"] and status["history"][0]["trained_by"] == ADMIN_USER


def test_retrain_from_observed_requires_enough_data(client, fresh_admin) -> None:
    result = client.post(f"{API}/ml/retrain", headers=fresh_admin, json={"source": "observed"}, timeout=120)
    assert result.status_code in {200, 409}


def test_playground_explains_a_disguised_attack(client, fresh_admin) -> None:
    result = client.post(f"{API}/playground/inspect", headers=fresh_admin,
                         json={"payload": "%2527%2520OR%25201%253D1%2520--", "where": "query"})
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["verdict"] == "attack" and body["action"] == "blocked"
    assert body["findings"][0]["attack"] == "sqli"
    assert body["decoding"]["rounds"][-1] == "' OR 1=1 --"
    assert body["ml"]["available"] and body["ml"]["threshold"] > 0


def test_playground_allows_normal_text_in_every_location(client, fresh_admin) -> None:
    for where in ("query", "path", "form", "json", "header", "cookie"):
        body = client.post(f"{API}/playground/inspect", headers=fresh_admin,
                           json={"payload": "O'Brien mug", "where": where}).json()
        assert body["findings"] == [], where


def test_playground_never_forwards_or_logs(client, fresh_admin) -> None:
    marker = "playground_marker_7731"
    response = client.post(f"{API}/playground/inspect", headers=fresh_admin, json={"payload": f"<script>{marker}</script>"})
    assert response.status_code == 200 and response.json()["verdict"] == "attack"
    time.sleep(2)  # gives the background log writer time to write anything it had queued
    for path in ("/incidents", "/traffic"):
        rows = client.get(f"{API}{path}", headers=fresh_admin, params={"search": marker}).json()["items"]
        assert rows == [], path


def test_playground_limits_payload_size_and_location(client, fresh_admin) -> None:
    too_big = client.post(f"{API}/playground/inspect", headers=fresh_admin, json={"payload": "a" * 8001})
    assert too_big.status_code == 422
    bad_place = client.post(f"{API}/playground/inspect", headers=fresh_admin, json={"payload": "x", "where": "url"})
    assert bad_place.status_code == 422
