"""Send real normal and attack requests through a running WAF, and report what happened.

The same script tests every setup, because only --base-url changes:

  local:   py tests/attacks/attack_suite.py --base-url http://127.0.0.1:8000
  live:    py tests/attacks/attack_suite.py --base-url https://your-waf.example --direct-url https://your-site.example

Only run this against systems you own or are authorized to test.
Attacks are refused at the WAF, so they don't reach the website.

The script signs in as admin to allowlist its own IP during the run (otherwise it would ban
itself after a few blocked requests), then puts the original settings back.
Admin details come from WAF_ADMIN_USER / WAF_ADMIN_PASSWORD, or from the project .env.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx
from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[2]
API = "/__waf/api"
BROWSER = {"user-agent": "Mozilla/5.0 (WAF attack suite; authorized testing)", "accept": "text/html,application/json"}

NORMAL = [
    ("Home page", "GET", "/", {}),
    ("Search", "GET", "/products", {"params": {"q": "book"}}),
    ("Search with an apostrophe", "GET", "/products", {"params": {"q": "O'Brien's guide"}}),
    ("Sentence with SQL words", "GET", "/products", {"params": {"q": "please select a plan from the list"}}),
    ("Form post", "POST", "/contact", {"data": {"name": "Sara", "message": "It's a nice shop, thanks!"}}),
    ("JSON API", "POST", "/api/orders", {"json": {"productId": 1, "quantity": 2}}),
    ("Static-style path", "GET", "/styles.css", {}),
]

ATTACKS = [
    ("SQLi tautology", "GET", "/products", {"params": {"q": "' OR '1'='1"}}),
    ("SQLi UNION", "GET", "/products", {"params": {"q": "1 UNION SELECT username, password FROM users --"}}),
    ("SQLi stacked DROP", "GET", "/products", {"params": {"q": "1; DROP TABLE users"}}),
    ("SQLi time-based", "GET", "/products", {"params": {"q": "1 AND SLEEP(5)"}}),
    ("SQLi in form body", "POST", "/contact", {"data": {"name": "admin'--", "message": "x"}}),
    ("SQLi in JSON", "POST", "/api/orders", {"json": {"productId": "1 UNION SELECT 1,2"}}),
    ("SQLi in User-Agent", "GET", "/", {"headers": {"user-agent": "' OR 1=1 --"}}),
    ("XSS script tag", "GET", "/products", {"params": {"q": "<script>alert(1)</script>"}}),
    ("XSS image event", "GET", "/products", {"params": {"q": "<img src=x onerror=alert(1)>"}}),
    ("XSS SVG", "POST", "/contact", {"data": {"name": "<svg onload=alert(1)>", "message": "x"}}),
    ("XSS script URL", "GET", "/products", {"params": {"q": "javascript:alert(document.cookie)"}}),
    ("Evasion double encoding", "GET", "/products?q=%2527%2520OR%25201%253D1%2520--", {}),
    ("Evasion comments", "GET", "/products", {"params": {"q": "1 UN/**/ION SEL/**/ECT 1,2"}}),
    ("Evasion mixed case", "GET", "/products", {"params": {"q": "<ScRiPt>alert(1)</sCrIpT>"}}),
    ("Evasion HTML entities", "GET", "/products", {"params": {"q": "&#60;img src=x onerror=alert(1)&#62;"}}),
    ("Evasion base64", "GET", "/products", {"params": {"q": "JyBPUiAnMSc9JzE="}}),
    ("Evasion compressed body", "POST", "/contact", {"content": b"\x1f\x8bhidden", "headers": {"content-encoding": "gzip"}}),
]


class Report:
    def __init__(self) -> None:
        self.rows: list[dict] = []

    def add(self, group: str, name: str, passed: bool, detail: str) -> None:
        self.rows.append({"group": group, "name": name, "passed": passed, "detail": detail})
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")

    @property
    def failed(self) -> int:
        return sum(not row["passed"] for row in self.rows)


def credentials() -> tuple[str, str]:
    env = dotenv_values(ROOT / ".env")
    username = os.environ.get("WAF_ADMIN_USER") or env.get("ADMIN_USERNAME") or "admin"
    password = os.environ.get("WAF_ADMIN_PASSWORD") or env.get("ADMIN_PASSWORD")
    return username, password or getpass.getpass(f"Admin password for {username}: ")


def send(client: httpx.Client, method: str, path: str, options: dict) -> httpx.Response:
    headers = {**BROWSER, **options.get("headers", {})}
    rest = {k: v for k, v in options.items() if k != "headers"}
    return client.request(method, path, headers=headers, **rest)


def run_rate_limit_test(client: httpx.Client, api: dict, report: Report, config: dict) -> None:
    """Drop the limit briefly, confirm it triggers, and put it back."""
    limit = 10
    client.patch(f"{API}/settings", headers=api, json={"rate_limit_per_minute": limit, "ip_allowlist": []}).raise_for_status()
    statuses = [client.get("/products", headers=BROWSER).status_code for _ in range(limit + 8)]
    limited = statuses.count(429)
    report.add("Rate limit", f"Requests over a temporary limit of {limit}/min", limited > 0, f"{limited} returned 429")


def verify_incident_saved(client: httpx.Client, api: dict, report: Report, since: str) -> None:
    for _ in range(10):
        items = client.get(f"{API}/incidents", headers=api, params={"limit": 50}).json()["items"]
        fresh = [i for i in items if i["created_at"] >= since and i["attack_type"] in {"sqli", "xss", "evasion"}]
        if fresh:
            report.add("Logging", "Blocked attacks saved as incidents", True, f"{len(fresh)} found in the database")
            return
        time.sleep(1)
    report.add("Logging", "Blocked attacks saved as incidents", False, "none found after 10 seconds")


def main() -> int:
    parser = argparse.ArgumentParser(description="Hybrid WAF attack suite")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="WAF address to send requests to")
    parser.add_argument("--direct-url", help="The website's own address, to confirm direct access is refused")
    parser.add_argument("--skip-rate-limit", action="store_true", help="Skip the burst test, for example on a slow host")
    parser.add_argument("--read-only", action="store_true", help="Forward only GET requests, for real websites")
    parser.add_argument("--output", type=Path, help="Save the results to a JSON file")
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    report = Report()

    print(f"Target WAF: {base}")
    client = httpx.Client(base_url=base, timeout=45, follow_redirects=False)

    username, password = credentials()
    login = client.post(f"{API}/auth/login", json={"username": username, "password": password})
    if login.status_code != 200:
        print(f"Admin login failed with status {login.status_code}. Check the admin details.")
        return 2
    api = {"authorization": f"Bearer {login.json()['access_token']}"}
    me = client.get(f"{API}/auth/me", headers=api).json()
    settings = client.get(f"{API}/settings", headers=api).json()
    original = settings["config"]
    env = settings["environment"]
    print(f"WAF environment: {env['waf_env']}")
    print(f"Website behind the WAF: {env['upstream_url']}")
    print(f"Your IP as seen by the WAF: {me['ip']}\n")
    if original["mode"] != "block":
        print("The WAF is in monitor mode, so attacks won't be blocked. Switch to block mode first.")
        return 2

    started = datetime.now(UTC).isoformat()
    client.patch(f"{API}/settings", headers=api, json={"ip_allowlist": [*original["ip_allowlist"], me["ip"]]}).raise_for_status()
    try:
        print("Normal requests (must reach the website):")
        for name, method, path, options in NORMAL:
            if args.read_only and method != "GET":
                print(f"  [SKIP] {name}: read-only mode sends only GET requests to the website")
                continue
            response = send(client, method, path, options)
            passed = response.status_code not in {403, 429, 502, 503} and response.headers.get("x-waf") == "hybrid"
            report.add("Normal", name, passed, f"status {response.status_code}")

        print("\nAttacks (must be blocked with 403):")
        for name, method, path, options in ATTACKS:
            response = send(client, method, path, options)
            report.add("Attack", name, response.status_code == 403, f"status {response.status_code}")

        print("\nBypass protection:")
        forged = client.get("/", headers={**BROWSER, "x-waf-secret": "guess"})
        report.add("Bypass", "A forged secret header doesn't break the site", forged.status_code < 500, f"status {forged.status_code}")
        if args.direct_url:
            direct = httpx.get(args.direct_url, timeout=30, follow_redirects=False)
            report.add("Bypass", "Direct access to the website is refused", direct.status_code == 403, f"status {direct.status_code}")
        else:
            print("  [SKIP] Direct access: pass --direct-url to test it")

        print("\nSecurity logging:")
        verify_incident_saved(client, api, report, started)

        if not args.skip_rate_limit:
            print("\nRate limiting:")
            run_rate_limit_test(client, api, report, original)
    finally:
        client.patch(f"{API}/settings", headers=api, json=original).raise_for_status()
        bans = client.get(f"{API}/bans", headers=api).json()["items"]
        for ban in (b for b in bans if b["ip"] == me["ip"]):
            client.delete(f"{API}/bans/{ban['id']}", headers=api)

    total = len(report.rows)
    print(f"\nResult: {total - report.failed}/{total} checks passed. Your original settings were restored.")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(
                {"ran_at": started, "waf": base, "upstream": env["upstream_url"], "environment": env["waf_env"], "results": report.rows},
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Saved to {args.output}")
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
