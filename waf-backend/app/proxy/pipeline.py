"""The inspection decision for one request. Forwarding and logging happen in the router."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ..detection.engine import Finding, inspect_request
from ..ml.features import FEATURE_NAMES, RequestView, extract
from ..ml.model import TrainedModel
from ..security.activity import IpSnapshot
from ..services.runtime_settings import RuntimeSettings

Verdict = Literal["allow", "block", "rate_limit", "banned", "error"]


@dataclass
class RequestFacts:
    ip: str
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes


@dataclass
class Decision:
    verdict: Verdict = "allow"
    attack_type: str | None = None
    severity: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    location: str | None = None
    evidence: str | None = None
    findings: list[Finding] = field(default_factory=list)
    anomaly_score: float | None = None
    is_anomaly: bool = False
    features: list[float] | None = None


def to_view(facts: RequestFacts, snapshot: IpSnapshot) -> RequestView:
    return RequestView(
        method=facts.method,
        path=facts.path,
        query=facts.query,
        header_count=len(facts.headers),
        user_agent=facts.headers.get("user-agent", ""),
        has_accept="accept" in facts.headers,
        body=facts.body,
        requests_last_minute=snapshot.requests_last_minute,
        unique_paths_last_minute=snapshot.unique_paths_last_minute,
        error_ratio_last_minute=snapshot.error_ratio_last_minute,
    )


def score_with_ml(
    decision: Decision,
    facts: RequestFacts,
    snapshot: IpSnapshot,
    model: TrainedModel,
    config: RuntimeSettings,
) -> None:
    features = extract(to_view(facts, snapshot))
    decision.features = features
    assert len(features) == len(FEATURE_NAMES)
    decision.anomaly_score = model.score(features)
    decision.is_anomaly = model.is_anomaly(decision.anomaly_score, config.ml_threshold_override)


def check_signatures(decision: Decision, facts: RequestFacts) -> None:
    encoding = facts.headers.get("content-encoding", "identity").strip().lower()
    if facts.body and encoding not in {"", "identity"}:
        # A compressed body can't be inspected, so it can't be allowed through unseen.
        decision.verdict = "block"
        decision.attack_type = "evasion"
        decision.severity = "medium"
        decision.rule_id = "EVASION-001"
        decision.rule_name = "Request body hidden by compression"
        decision.location = "header:content-encoding"
        decision.evidence = encoding[:64]
        return

    findings = inspect_request(facts.path, facts.query, facts.headers, facts.body)
    if not findings:
        return
    top = findings[0]
    decision.verdict = "block"
    decision.findings = findings
    decision.attack_type = top.attack
    decision.severity = top.severity
    decision.rule_id = top.rule_id
    decision.rule_name = top.rule_name
    decision.location = top.location
    decision.evidence = top.evidence
