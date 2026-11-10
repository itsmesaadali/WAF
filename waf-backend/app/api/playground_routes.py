"""Attack playground: check a payload against the WAF without sending it anywhere.

The payload is wrapped in a pretend request and run through the same signature and ML code
the proxy uses. Nothing is forwarded, logged as traffic or stored, so admins can explore
freely without creating incidents or reaching any website.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Literal
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from ..detection.engine import explain_value
from ..ml.features import FEATURE_NAMES
from ..proxy.pipeline import Decision, RequestFacts, check_signatures, score_with_ml
from ..runtime import get_runtime
from ..security.activity import IpSnapshot
from .deps import current_admin

router = APIRouter(prefix="/playground", dependencies=[Depends(current_admin)])

Where = Literal["query", "path", "form", "json", "header", "cookie"]
MAX_PAYLOAD = 8000
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
# An ordinary visitor's recent behaviour, so ML judges the request itself, not a burst.
TYPICAL_VISITOR = IpSnapshot(requests_last_minute=4, unique_paths_last_minute=3, error_ratio_last_minute=0.0)
BASELINE_TEXT = "blue cotton shirt"


class InspectBody(BaseModel):
    payload: str = Field(max_length=MAX_PAYLOAD)
    where: Where = "query"


def build_request(payload: str, where: Where) -> RequestFacts:
    """Place the payload where a real visitor could put it."""
    headers = {"user-agent": BROWSER, "accept": "text/html,application/json", "accept-language": "en"}
    method, path, query, body = "GET", "/products", "", b""
    if where == "query":
        query = "q=" + quote(payload, safe="")
    elif where == "path":
        path = "/products/" + quote(payload, safe="/")
    elif where == "form":
        method, path = "POST", "/contact"
        headers["content-type"] = "application/x-www-form-urlencoded"
        body = urlencode({"name": "Visitor", "message": payload}).encode()
    elif where == "json":
        method, path = "POST", "/api/orders"
        headers["content-type"] = "application/json"
        body = json.dumps({"product_id": 1, "note": payload}).encode()
    elif where == "header":
        headers["user-agent"] = payload
    else:
        headers["cookie"] = "session=" + payload
    return RequestFacts(ip="playground", method=method, path=path, query=query, headers=headers, body=body)


def _describe(facts: RequestFacts) -> dict:
    shown = {k: v[:300] for k, v in facts.headers.items() if k in {"user-agent", "cookie", "content-type"}}
    return {
        "method": facts.method,
        "url": facts.path + (f"?{facts.query}" if facts.query else ""),
        "headers": shown,
        "body": facts.body[:600].decode("utf-8", errors="replace"),
    }


def _inspect(payload: str, where: Where) -> dict:
    rt = get_runtime()
    facts = build_request(payload, where)

    started = time.perf_counter()
    decision = Decision()
    check_signatures(decision, facts)
    signature_ms = (time.perf_counter() - started) * 1000

    ml: dict = {"available": rt.model is not None and rt.config.ml_enabled}
    if ml["available"]:
        started = time.perf_counter()
        score_with_ml(decision, facts, TYPICAL_VISITOR, rt.model, rt.config)
        ml_ms = (time.perf_counter() - started) * 1000
        baseline = Decision()
        score_with_ml(baseline, build_request(BASELINE_TEXT, where), TYPICAL_VISITOR, rt.model, rt.config)
        threshold = rt.config.ml_threshold_override or rt.model.threshold
        changes = [
            {"name": name, "value": round(value, 4), "normal": round(normal, 4)}
            for name, value, normal in zip(FEATURE_NAMES, decision.features or [], baseline.features or [])
            if abs(value - normal) > 1e-6
        ]
        changes.sort(key=lambda c: abs(c["value"] - c["normal"]) / (abs(c["normal"]) + 1), reverse=True)
        ml.update(
            score=round(decision.anomaly_score or 0.0, 4),
            normal_score=round(baseline.anomaly_score or 0.0, 4),
            threshold=round(threshold, 4),
            is_anomaly=decision.is_anomaly,
            changed_features=changes[:6],
            ms=round(ml_ms, 2),
        )

    attack = bool(decision.findings) or decision.rule_id == "EVASION-001"
    if attack:
        verdict = "attack"
    elif decision.is_anomaly:
        verdict = "suspicious"
    else:
        verdict = "clean"

    blocking = rt.config.mode == "block"
    if verdict == "attack":
        action = "blocked" if blocking else "logged only (Monitor mode)"
    elif verdict == "suspicious":
        action = "blocked" if blocking and rt.config.ml_block else "allowed and flagged for review"
    else:
        action = "allowed"

    return {
        "verdict": verdict,
        "action": action,
        "mode": rt.config.mode,
        "request": _describe(facts),
        "findings": [
            {"rule_id": f.rule_id, "rule_name": f.rule_name, "attack": f.attack, "severity": f.severity,
             "location": f.location, "evidence": f.evidence}
            for f in decision.findings
        ],
        "decoding": explain_value(payload),
        "ml": ml,
        "signature_ms": round(signature_ms, 2),
    }


@router.post("/inspect")
async def inspect(body: InspectBody) -> dict:
    # Regex and ML work run off the event loop, like they do for proxied requests.
    return await asyncio.to_thread(_inspect, body.payload, body.where)
