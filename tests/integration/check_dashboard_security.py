"""Check the running dashboard's security behaviour. Secrets are read from .env and never printed.

Usage (website, WAF and dashboard must be running):
  waf-backend\\.venv\\Scripts\\python.exe tests\\integration\\check_dashboard_security.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
BASE = "http://127.0.0.1:3001"
ORIGIN = {"origin": BASE}
EVIL = {"origin": "https://evil.example"}
failures = 0


def check(name: str, passed: bool, detail: object = "") -> None:
    global failures
    failures += not passed
    print(f"[{'PASS' if passed else 'FAIL'}] {name} {detail}")


def main() -> int:
    env = dotenv_values(ROOT / ".env")
    login_body = {"username": env.get("ADMIN_USERNAME", "admin"), "password": env["ADMIN_PASSWORD"]}

    with httpx.Client(base_url=BASE, timeout=90, follow_redirects=False) as anonymous:
        check("Anonymous API call is refused", anonymous.get("/api/waf/traffic").status_code == 401)
        page = anonymous.get("/dashboard")
        check("Anonymous page visit goes to login", page.status_code in {302, 307} and "/login" in page.headers["location"])
        check("Login without an Origin is refused", anonymous.post("/api/auth/login", json=login_body).status_code == 403)
        check("Login from another site is refused", anonymous.post("/api/auth/login", json=login_body, headers=EVIL).status_code == 403)
        wrong = anonymous.post("/api/auth/login", json={**login_body, "password": "wrong-password"}, headers=ORIGIN)
        check("Wrong password is refused", wrong.status_code == 401)
        check("Security headers are present", wrong.headers.get("x-frame-options") == "DENY" and "x-powered-by" not in wrong.headers)

    with httpx.Client(base_url=BASE, timeout=90, follow_redirects=False) as admin:
        login = admin.post("/api/auth/login", json=login_body, headers=ORIGIN)
        check("Correct login works", login.status_code == 200)
        cookie = login.headers.get("set-cookie", "").lower()
        check("Session cookie is httpOnly and SameSite", "httponly" in cookie and "samesite=lax" in cookie)
        check("Token isn't in the login response body", "access_token" not in login.text)
        check("Signed-in API call works", admin.get("/api/waf/traffic", params={"limit": 1}).status_code == 200)
        check("Cross-site change is refused", admin.patch("/api/waf/settings", json={}, headers=EVIL).status_code == 403)
        check("Bridge refuses its own login route", admin.post("/api/waf/auth/login", json=login_body, headers=ORIGIN).status_code == 404)
        overview = admin.get("/api/waf/stats/overview", params={"window": "1h"}).json()
        check("Overview returns real counts", overview["totals"]["requests"] > 0, overview["totals"])
        export = admin.get("/api/waf/incidents/export.csv")
        check("CSV export works", export.status_code == 200 and export.text.startswith("id,created_at"))

    # Browser files must never contain server secrets.
    secrets = [env[name] for name in ("WAF_SHARED_SECRET", "JWT_SECRET", "ADMIN_PASSWORD", "MODEL_SIGNING_KEY")]
    secrets.append(env["DATABASE_URL"].split("@")[0].split(":")[-1])
    leaked = 0
    for folder in (ROOT / "dashboard" / ".next" / "static", ROOT / "dashboard" / ".next" / "dev" / "static"):
        for file in folder.rglob("*") if folder.exists() else []:
            if file.is_file():
                content = file.read_text(encoding="utf-8", errors="ignore")
                leaked += any(secret in content for secret in secrets)
    check("No server secrets in browser files", leaked == 0)

    print("All checks passed" if not failures else f"{failures} checks failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
