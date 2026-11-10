"""Reverse proxy: every request that isn't a WAF admin route is inspected here first."""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime, timedelta
from html import escape
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request, Response
from starlette.background import BackgroundTask
from starlette.responses import StreamingResponse

from ..detection.redaction import redact_query, redact_text
from ..runtime import Runtime, get_runtime
from ..security.client_ip import resolve_client_ip
from .pipeline import Decision, RequestFacts, check_signatures, score_with_ml

router = APIRouter()

SIMULATOR_NETWORK = ip_network("203.0.113.0/24")  # Reserved range: can't come from the internet.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
}
# Never forwarded from visitors: the secret proves a request came through the WAF.
STRIPPED_REQUEST_HEADERS = HOP_BY_HOP | {
    "host", "content-length", "x-waf-secret", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-real-ip", "forwarded",
}
METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
MAX_LOGGED_PATH = 1024
MAX_LOGGED_AGENT = 512


class BodyTooLarge(Exception):
    pass


async def _read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise BodyTooLarge
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            raise BodyTooLarge
        chunks.append(chunk)
    return b"".join(chunks)


def _is_simulated(ip: str) -> bool:
    try:
        return ip_address(ip) in SIMULATOR_NETWORK
    except ValueError:
        return False


def _block_page(status: int, title: str, message: str, headers: dict[str, str] | None = None) -> Response:
    # Deliberately vague: attackers learn nothing about which rule matched.
    body = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>"
        f"{escape(title)}</title><style>body{{font-family:system-ui,sans-serif;display:grid;place-items:center;"
        "min-height:100vh;margin:0}main{max-width:32rem;padding:2rem;text-align:center}</style></head>"
        f"<body><main><h1>{escape(title)}</h1><p>{escape(message)}</p></main></body></html>"
    )
    return Response(body, status, {"content-type": "text/html; charset=utf-8", "x-waf": "hybrid", **(headers or {})})


def _log_request(
    rt: Runtime,
    facts: RequestFacts,
    status: int,
    action: str,
    reason: str | None,
    decision: Decision | None,
    waf_ms: float,
    upstream_ms: float | None = None,
) -> None:
    rt.writer.enqueue(
        "request",
        {
            "created_at": datetime.now(UTC),
            "client_ip": facts.ip,
            "method": facts.method[:16],
            "path": redact_text(facts.path)[:MAX_LOGGED_PATH],
            "query": redact_query(facts.query),
            "user_agent": (facts.headers.get("user-agent") or "")[:MAX_LOGGED_AGENT] or None,
            "status_code": status,
            "action": action,
            "reason": reason,
            "waf_ms": round(waf_ms, 3),
            "upstream_ms": round(upstream_ms, 3) if upstream_ms is not None else None,
            "anomaly_score": decision.anomaly_score if decision else None,
            "is_anomaly": decision.is_anomaly if decision else False,
            "features": decision.features if decision else None,
            "mode": rt.config.mode,
            "simulated": _is_simulated(facts.ip),
            "upstream": rt.settings.upstream_url,
        },
    )


def _log_incident(
    rt: Runtime,
    facts: RequestFacts,
    attack_type: str,
    severity: str,
    action_taken: str,
    rule_id: str | None = None,
    rule_name: str | None = None,
    location: str | None = None,
    evidence: str | None = None,
    anomaly_score: float | None = None,
) -> None:
    rt.writer.enqueue(
        "incident",
        {
            "created_at": datetime.now(UTC),
            "client_ip": facts.ip,
            "method": facts.method[:16],
            "path": redact_text(facts.path)[:MAX_LOGGED_PATH],
            "attack_type": attack_type,
            "severity": severity,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "location": location,
            "evidence": redact_text(evidence)[:200] if evidence else None,
            "action_taken": action_taken,
            "anomaly_score": anomaly_score,
            "mode": rt.config.mode,
            "status": "open",
            "simulated": _is_simulated(facts.ip),
        },
    )


def _ban(rt: Runtime, ip: str, reason: str) -> None:
    expires = datetime.now(UTC) + timedelta(minutes=rt.config.ban_minutes)
    rt.bans.add(ip, expires)
    rt.writer.enqueue(
        "ban",
        {
            "ip": ip,
            "reason": reason[:500],
            "source": "auto",
            "created_by": "waf",
            "created_at": datetime.now(UTC),
            "expires_at": expires,
            "simulated": _is_simulated(ip),
        },
    )


def _add_strike(rt: Runtime, ip: str, reason: str) -> None:
    """Too many blocked requests earn a temporary ban. Monitor mode and allowlisted IPs never get banned."""
    if rt.config.mode != "block" or rt.config.is_allowlisted(ip):
        return
    if rt.activity.add_strike(ip) >= rt.config.strikes_before_ban:
        rt.activity.clear_strikes(ip)
        _ban(rt, ip, reason)


def _rewrite_location(value: str, upstream: str) -> str:
    """Keep redirects on the WAF, so visitors don't get sent directly to the website."""
    if value.startswith(upstream):
        return value[len(upstream):] or "/"
    target = urlsplit(value)
    if target.scheme and target.netloc == urlsplit(upstream).netloc:
        rest = target.path or "/"
        return f"{rest}?{target.query}" if target.query else rest
    return value


async def _forward(
    rt: Runtime, request: Request, facts: RequestFacts, decision: Decision, started: float, reason: str | None, action: str
) -> Response:
    assert rt.client is not None
    settings = rt.settings
    upstream = settings.upstream_url

    outgoing = [
        (name, value)
        for name, value in request.headers.items()
        if name.lower() not in STRIPPED_REQUEST_HEADERS
    ]
    outgoing.extend(
        [
            ("x-waf-secret", settings.waf_shared_secret),
            ("x-forwarded-for", facts.ip),
            ("x-forwarded-proto", request.headers.get("x-forwarded-proto", request.url.scheme) if settings.trust_proxy_hops else request.url.scheme),
            ("x-forwarded-host", request.headers.get("host", "")),
        ]
    )
    # The raw path is sent exactly as inspected. The destination host is fixed by configuration.
    raw_path = request.scope.get("raw_path", b"").decode("latin-1") or request.url.path
    query = request.scope.get("query_string", b"").decode("latin-1")
    url = f"{upstream}{raw_path}" + (f"?{query}" if query else "")

    waf_ms = (time.perf_counter() - started) * 1000
    upstream_started = time.perf_counter()
    try:
        outgoing_request = rt.client.build_request(facts.method, url, headers=outgoing, content=facts.body)
        response = await rt.client.send(outgoing_request, stream=True)
    except httpx.HTTPError as exc:
        rt.upstream_errors += 1
        rt.activity.record_error(facts.ip)
        _log_request(rt, facts, 502, "error", f"upstream:{exc.__class__.__name__}", decision, waf_ms)
        return _block_page(502, "Website unavailable", "The protected website could not be reached.")

    upstream_ms = (time.perf_counter() - upstream_started) * 1000
    if response.status_code >= 400:
        rt.activity.record_error(facts.ip)
    _log_request(rt, facts, response.status_code, action, reason, decision, waf_ms, upstream_ms)

    streaming = StreamingResponse(
        response.aiter_raw(), status_code=response.status_code, background=BackgroundTask(response.aclose)
    )
    raw_headers: list[tuple[bytes, bytes]] = []
    for name, value in response.headers.multi_items():
        lowered = name.lower()
        if lowered in HOP_BY_HOP or lowered == "x-waf-secret":
            continue
        if lowered == "location":
            value = _rewrite_location(value, upstream)
        raw_headers.append((lowered.encode("latin-1"), value.encode("latin-1", "replace")))
    raw_headers.append((b"x-waf", b"hybrid"))
    streaming.raw_headers = raw_headers
    return streaming


@router.api_route("/{full_path:path}", methods=METHODS, include_in_schema=False)
async def proxy(request: Request, full_path: str) -> Response:  # noqa: ARG001
    started = time.perf_counter()
    rt = get_runtime()
    rt.requests_total += 1
    config = rt.config

    peer = request.client.host if request.client else None
    ip = resolve_client_ip(peer, request.headers.get("x-forwarded-for"), rt.settings.trust_proxy_hops)
    headers = {name.lower(): value for name, value in request.headers.items()}
    query = request.url.query
    facts = RequestFacts(ip, request.method, request.url.path, query, headers, b"")
    block_mode = config.mode == "block"

    def elapsed() -> float:
        return (time.perf_counter() - started) * 1000

    allowlisted = config.is_allowlisted(ip)

    # 1. Banned IPs stop here, before any further work is spent on them.
    if not allowlisted and rt.bans.is_banned(ip):
        if rt.activity.should_report(ip, "banned_ip"):
            _log_incident(rt, facts, "banned_ip", "low", "blocked" if block_mode else "logged",
                          rule_id="BAN-001", rule_name="Request from a banned IP")
        if block_mode:
            _log_request(rt, facts, 403, "banned", "ip_banned", None, elapsed())
            return _block_page(403, "Access denied", "Your address is temporarily blocked.")

    # 2. Rate limit before reading the body, so floods are cheap to refuse.
    snapshot = rt.activity.record(ip, facts.path)
    if not allowlisted and snapshot.requests_last_minute > config.rate_limit_per_minute:
        if rt.activity.should_report(ip, "rate_limit"):
            _log_incident(
                rt, facts, "rate_limit", "medium", "blocked" if block_mode else "logged",
                rule_id="RATE-001", rule_name="Too many requests",
                evidence=f"{snapshot.requests_last_minute} requests in the last minute (limit {config.rate_limit_per_minute})",
            )
            _add_strike(rt, ip, "Repeatedly exceeded the rate limit")
        if block_mode:
            _log_request(rt, facts, 429, "rate_limited", "rate_limit", None, elapsed())
            return _block_page(429, "Too many requests", "Please slow down and try again shortly.", {"retry-after": "60"})

    # 3. Oversized bodies can't be fully inspected, so they aren't accepted (fail-safe default).
    try:
        facts.body = await _read_body(request, rt.settings.max_body_bytes)
    except BodyTooLarge:
        _log_request(rt, facts, 413, "blocked", "body_too_large", None, elapsed())
        return _block_page(413, "Request too large", "The request is larger than this site allows.")

    decision = Decision()

    # 4. Signatures. If the inspection itself crashes, FAIL_MODE decides what happens.
    try:
        # Runs on a worker thread, so a large request can't stall other visitors.
        await asyncio.to_thread(check_signatures, decision, facts)
    except Exception as exc:  # noqa: BLE001 - a bug here must not become a silent bypass
        rt.inspection_errors += 1
        closed = rt.settings.fail_mode == "closed"
        _log_incident(rt, facts, "inspection_error", "high", "blocked" if closed else "logged",
                      rule_id="FAIL-001", rule_name=f"Inspection failed ({exc.__class__.__name__})")
        if closed:
            _log_request(rt, facts, 503, "error", "inspection_error", None, elapsed())
            return _block_page(503, "Temporarily unavailable", "The request could not be checked safely.")

    # 5. ML adds evidence. If it fails, signatures still protect the site.
    if config.ml_enabled and rt.model is not None:
        try:
            await asyncio.to_thread(score_with_ml, decision, facts, snapshot, rt.model, config)
        except Exception:  # noqa: BLE001
            rt.ml_errors += 1

    # 6. Act on the result.
    signature_hit = decision.verdict == "block"
    if signature_hit:
        assert decision.attack_type and decision.severity
        action_taken = "blocked" if block_mode else "logged"
        _log_incident(
            rt, facts, decision.attack_type, decision.severity, action_taken,
            decision.rule_id, decision.rule_name, decision.location, decision.evidence, decision.anomaly_score,
        )
        if block_mode:
            _add_strike(rt, ip, f"Repeated attacks detected ({decision.attack_type})")
            _log_request(rt, facts, 403, "blocked", decision.rule_id, decision, elapsed())
            return _block_page(403, "Request blocked", "This request was blocked by the website's security system.")
        return await _forward(rt, request, facts, decision, started, decision.rule_id, "flagged")

    if decision.is_anomaly:
        ml_blocks = config.ml_block and block_mode
        if rt.activity.should_report(ip, f"anomaly:{facts.path[:64]}"):
            _log_incident(
                rt, facts, "anomaly", "medium", "blocked" if ml_blocks else "logged",
                rule_id="ML-001", rule_name="Isolation Forest anomaly", anomaly_score=decision.anomaly_score,
            )
        if ml_blocks:
            _log_request(rt, facts, 403, "blocked", "ML-001", decision, elapsed())
            return _block_page(403, "Request blocked", "This request was blocked by the website's security system.")
        return await _forward(rt, request, facts, decision, started, "ML-001", "flagged")

    return await _forward(rt, request, facts, decision, started, None, "allowed")
