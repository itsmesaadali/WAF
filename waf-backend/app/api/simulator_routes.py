"""Admin-only attack simulator.

Requests run through the real WAF pipeline inside this process, so they can only reach
the configured UPSTREAM_URL. The admin can't supply a target URL or custom payload.
They come from the reserved 203.0.113.0/24 range, which can't be spoofed from outside
because the address comes from the in-process connection, and all records are marked simulated.
"""
from __future__ import annotations

import asyncio
import random
from typing import Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from ..runtime import get_runtime
from .deps import Admin, audit, current_admin, request_ip

router = APIRouter(prefix="/simulator", dependencies=[Depends(current_admin)])

Scenario = Literal["sqli", "xss", "evasion", "anomaly", "normal", "rate_limit"]

BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"

_ATTACKS: dict[str, list[dict]] = {
    "sqli": [
        {"path": "/products", "params": {"q": "' OR '1'='1"}},
        {"path": "/products", "params": {"q": "1 UNION SELECT username, password FROM users --"}},
        {"path": "/api/products", "params": {"category": "books'; DROP TABLE users; --"}},
        {"path": "/contact", "method": "POST", "data": {"name": "admin'--", "message": "x"}},
        {"path": "/products", "params": {"q": "1 AND SLEEP(5)"}},
    ],
    "xss": [
        {"path": "/products", "params": {"q": "<script>alert(1)</script>"}},
        {"path": "/products", "params": {"q": "<img src=x onerror=alert(1)>"}},
        {"path": "/contact", "method": "POST", "data": {"name": "<svg onload=alert(1)>", "message": "x"}},
        {"path": "/products", "params": {"q": "javascript:alert(document.cookie)"}},
    ],
    "evasion": [
        {"path": "/products", "raw_query": "q=%2527%2520OR%25201%253D1%2520--"},
        {"path": "/products", "params": {"q": "1 UN/**/ION SEL/**/ECT 1,2"}},
        {"path": "/products", "raw_query": "q=%253Cscript%253Ealert(1)%253C%252Fscript%253E"},
        {"path": "/products", "params": {"q": "&#60;img src=x onerror=alert(1)&#62;"}},
        {"path": "/products", "params": {"q": "JyBPUiAnMSc9JzE="}},
    ],
}
_MAX_RATE_LIMIT_REQUESTS = 2000


def _anomaly_requests() -> list[dict]:
    """Odd requests with no attack keywords: only the ML layer should notice them."""
    rng = random.Random()
    noise = "".join(rng.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=900))
    many_params = {f"p{i}": str(rng.randint(0, 99999)) for i in range(45)}
    return [
        {"path": "/api/products", "params": {"token_blob": noise}, "headers": {"user-agent": "x", "accept": ""}},
        {"path": "/api/products", "params": many_params, "headers": {"user-agent": ""}},
        {"path": "/" + "/".join(f"s{rng.randint(1000, 9999)}" for _ in range(30)), "headers": {"user-agent": "x"}},
        {"path": "/api/orders", "method": "POST", "content": noise.encode() * 20, "headers": {"user-agent": "x"}},
    ]


def _normal_requests() -> list[dict]:
    return [
        {"path": "/"},
        {"path": "/products", "params": {"q": "book"}},
        {"path": "/products/2"},
        {"path": "/contact", "method": "POST", "data": {"name": "O'Brien", "message": "It's a nice shop"}},
        {"path": "/api/products", "params": {"category": "books"}},
        {"path": "/styles.css"},
    ]


class RunBody(BaseModel):
    scenario: Scenario


def _next_ip() -> str:
    # Each run uses its own address, so bans from one run don't affect the next.
    return f"203.0.113.{random.randint(1, 254)}"


async def _send_all(ip: str, requests: list[dict], request: Request) -> list[dict]:
    transport = httpx.ASGITransport(app=request.app, client=(ip, 40000))
    results: list[dict] = []
    async with httpx.AsyncClient(transport=transport, base_url="http://simulator.internal", timeout=30) as client:
        for spec in requests:
            headers = {"user-agent": BROWSER, "accept": "text/html,application/json", **spec.get("headers", {})}
            url = spec["path"]
            if spec.get("raw_query"):
                url = f"{url}?{spec['raw_query']}"
            response = await client.request(
                spec.get("method", "GET"),
                url,
                params=spec.get("params"),
                data=spec.get("data"),
                content=spec.get("content"),
                headers=headers,
            )
            results.append({"method": spec.get("method", "GET"), "path": spec["path"][:80], "status": response.status_code})
    return results


@router.post("/run")
async def run(body: RunBody, request: Request, admin: Admin = Depends(current_admin)) -> dict:
    runtime = get_runtime()
    if not runtime.settings.simulator_enabled:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "The simulator is switched off (SIMULATOR_ENABLED=false)")
    ip = _next_ip()

    if body.scenario == "normal":
        specs = _normal_requests()
    elif body.scenario == "anomaly":
        specs = _anomaly_requests()
    elif body.scenario == "rate_limit":
        count = min(runtime.config.rate_limit_per_minute + 10, _MAX_RATE_LIMIT_REQUESTS)
        specs = [{"path": "/healthz"} for _ in range(count)]
    else:
        specs = _ATTACKS[body.scenario]

    results = await _send_all(ip, specs, request)
    await asyncio.to_thread(runtime.writer.flush, 10.0)

    blocked = sum(r["status"] in {403, 429} for r in results)
    await asyncio.to_thread(
        audit, admin.username, "simulator_run", body.scenario,
        {"simulated_ip": ip, "requests": len(results), "blocked": blocked}, request_ip(request),
    )
    # A rate-limit run has too many rows to be useful, so it's summarized.
    visible = results if body.scenario != "rate_limit" else results[-5:]
    return {
        "scenario": body.scenario,
        "simulated_ip": ip,
        "target": runtime.settings.upstream_url,
        "requests": len(results),
        "blocked": blocked,
        "forwarded": len(results) - blocked,
        "results": visible,
    }
