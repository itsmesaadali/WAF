"""Compare signatures alone against signatures plus ML, on the same labelled traffic.

Detection uses the WAF's real inspection code with no network. Latency is measured over
real HTTP against a running website and WAF, when both are available.

  py tests/evaluation/run_evaluation.py
  py tests/evaluation/run_evaluation.py --waf-url http://127.0.0.1:8000 --site-url http://127.0.0.1:3000

"Detected" for ML means flagged. By default the WAF logs ML flags and doesn't block on them.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "waf-backend"))
sys.path.insert(0, str(ROOT))

import httpx  # noqa: E402
from dotenv import dotenv_values, load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

from app.detection.engine import inspect_request  # noqa: E402
from app.ml.features import RequestView, extract  # noqa: E402
from app.ml.train import train  # noqa: E402
from tests.evaluation.dataset import Sample, build_dataset  # noqa: E402

API = "/__waf/api"
LATENCY_REQUESTS = 200
OUTPUT_DIR = ROOT / "docs" / "evidence"


def view_of(sample: Sample) -> RequestView:
    headers = {k.lower(): v for k, v in sample.headers.items()}
    return RequestView(
        method=sample.method,
        path=sample.path,
        query=sample.query,
        header_count=len(headers),
        user_agent=headers.get("user-agent", ""),
        has_accept="accept" in headers,
        body=sample.body,
        requests_last_minute=sample.requests_last_minute,
        unique_paths_last_minute=sample.unique_paths_last_minute,
        error_ratio_last_minute=sample.error_ratio_last_minute,
    )


def percent(part: int, whole: int) -> float:
    return round(100 * part / whole, 2) if whole else 0.0


def evaluate_detection() -> dict:
    result = train()
    model = result.model
    samples = build_dataset()
    categories = sorted({s.category for s in samples})
    counts = {c: {"total": 0, "signature": 0, "hybrid": 0, "ml_only": 0} for c in categories}
    missed: list[str] = []
    signature_times: list[float] = []
    ml_times: list[float] = []

    for sample in samples:
        started = time.perf_counter()
        hit = bool(inspect_request(sample.path, sample.query, {k.lower(): v for k, v in sample.headers.items()}, sample.body))
        signature_times.append((time.perf_counter() - started) * 1000)

        started = time.perf_counter()
        flagged = model.is_anomaly(model.score(extract(view_of(sample))))
        ml_times.append((time.perf_counter() - started) * 1000)

        row = counts[sample.category]
        row["total"] += 1
        row["signature"] += hit
        row["hybrid"] += hit or flagged
        row["ml_only"] += flagged and not hit
        if sample.is_attack and not (hit or flagged):
            missed.append(f"{sample.category}: {sample.method} {sample.path[:50]} {(sample.query or sample.body.decode('utf-8', 'replace'))[:70]}")

    attacks = [c for c in categories if c != "normal"]
    attack_total = sum(counts[c]["total"] for c in attacks)
    normal = counts["normal"]
    return {
        "dataset": {"normal": normal["total"], "attacks": attack_total, "categories": {c: counts[c]["total"] for c in categories}},
        "model": {"threshold": model.threshold, "training_samples": result.samples, "holdout_flag_rate_percent": round(result.holdout_flag_rate * 100, 2)},
        "signature_only": {
            "detection_rate_percent": percent(sum(counts[c]["signature"] for c in attacks), attack_total),
            "false_positive_rate_percent": percent(normal["signature"], normal["total"]),
            "by_category_percent": {c: percent(counts[c]["signature"], counts[c]["total"]) for c in attacks},
        },
        "hybrid": {
            "detection_rate_percent": percent(sum(counts[c]["hybrid"] for c in attacks), attack_total),
            "false_positive_rate_percent": percent(normal["hybrid"], normal["total"]),
            "by_category_percent": {c: percent(counts[c]["hybrid"], counts[c]["total"]) for c in attacks},
            "caught_only_by_ml": sum(counts[c]["ml_only"] for c in attacks),
        },
        "inspection_time_ms": {
            "signatures_median": round(statistics.median(signature_times), 3),
            "signatures_p95": round(statistics.quantiles(signature_times, n=20)[18], 3),
            "ml_median": round(statistics.median(ml_times), 3),
            "ml_p95": round(statistics.quantiles(ml_times, n=20)[18], 3),
        },
        "missed_attacks": missed,
    }


def _timed(client: httpx.Client, url: str, headers: dict) -> list[float]:
    times = []
    for _ in range(LATENCY_REQUESTS):
        started = time.perf_counter()
        response = client.get(url, headers=headers)
        times.append((time.perf_counter() - started) * 1000)
        if response.status_code >= 400:
            raise RuntimeError(f"latency test got status {response.status_code} from {url}")
    return times


def _summary(times: list[float]) -> dict:
    # The first requests warm up connections and are excluded.
    steady = times[10:]
    return {"median_ms": round(statistics.median(steady), 2), "p95_ms": round(statistics.quantiles(steady, n=20)[18], 2), "requests": len(steady)}


def evaluate_latency(waf_url: str, site_url: str) -> dict:
    env = dotenv_values(ROOT / ".env")
    secret = env["WAF_SHARED_SECRET"]
    login = httpx.post(f"{waf_url}{API}/auth/login", json={"username": env.get("ADMIN_USERNAME", "admin"), "password": env["ADMIN_PASSWORD"]}, timeout=45)
    login.raise_for_status()
    api = {"authorization": f"Bearer {login.json()['access_token']}"}
    original = httpx.get(f"{waf_url}{API}/settings", headers=api, timeout=45).json()["config"]
    ip = httpx.get(f"{waf_url}{API}/auth/me", headers=api, timeout=45).json()["ip"]
    page = "/products?q=book"
    visitor = {"user-agent": "evaluation", "accept": "text/html"}

    def set_ml(enabled: bool) -> None:
        httpx.patch(f"{waf_url}{API}/settings", headers=api, json={"ml_enabled": enabled, "ip_allowlist": [ip]}, timeout=45).raise_for_status()

    try:
        with httpx.Client(timeout=30) as client:
            direct = _timed(client, f"{site_url}{page}", {**visitor, "x-waf-secret": secret})
            set_ml(False)
            signature = _timed(client, f"{waf_url}{page}", visitor)
            set_ml(True)
            hybrid = _timed(client, f"{waf_url}{page}", visitor)
    finally:
        httpx.patch(f"{waf_url}{API}/settings", headers=api, json=original, timeout=45).raise_for_status()

    return {
        "direct": _summary(direct),
        "through_waf_signatures_only": _summary(signature),
        "through_waf_hybrid": _summary(hybrid),
        "background_logging": True,
    }


def to_markdown(results: dict) -> str:
    sig, hyb = results["signature_only"], results["hybrid"]
    data = results["dataset"]
    lines = [
        "# Evaluation Results",
        "",
        f"Generated by `tests/evaluation/run_evaluation.py` on {results['generated_at']}.",
        "",
        f"Test traffic: {data['normal']} normal requests and {data['attacks']} attack or abnormal requests. All of it is simulated.",
        "",
        "## Detection",
        "",
        "| Measure | Signatures only | Signatures + ML |",
        "|---|---:|---:|",
        f"| Detection rate | {sig['detection_rate_percent']}% | {hyb['detection_rate_percent']}% |",
        f"| False-positive rate | {sig['false_positive_rate_percent']}% | {hyb['false_positive_rate_percent']}% |",
    ]
    for category in sig["by_category_percent"]:
        lines.append(f"| {category} detected | {sig['by_category_percent'][category]}% | {hyb['by_category_percent'][category]}% |")
    lines += [
        "",
        f"ML caught {hyb['caught_only_by_ml']} requests that signatures missed. ML results count as flagged, not blocked, under the default settings.",
        "",
        "## Inspection time per request",
        "",
        "| Step | Median | 95th percentile |",
        "|---|---:|---:|",
        f"| Signatures | {results['inspection_time_ms']['signatures_median']} ms | {results['inspection_time_ms']['signatures_p95']} ms |",
        f"| ML scoring | {results['inspection_time_ms']['ml_median']} ms | {results['inspection_time_ms']['ml_p95']} ms |",
    ]
    if results.get("latency"):
        latency = results["latency"]
        lines += [
            "",
            "## End-to-end latency over HTTP",
            "",
            "| Path | Median | 95th percentile |",
            "|---|---:|---:|",
            f"| Direct to the website | {latency['direct']['median_ms']} ms | {latency['direct']['p95_ms']} ms |",
            f"| Through WAF, signatures only | {latency['through_waf_signatures_only']['median_ms']} ms | {latency['through_waf_signatures_only']['p95_ms']} ms |",
            f"| Through WAF, signatures + ML | {latency['through_waf_hybrid']['median_ms']} ms | {latency['through_waf_hybrid']['p95_ms']} ms |",
            "",
            "Logs were written in the background during these runs, so the database doesn't add to these times.",
        ]
    lines += ["", f"## Attacks missed by both layers ({len(results['missed_attacks'])})", ""]
    lines += [f"- `{m}`".replace("|", "\\|") for m in results["missed_attacks"]] or ["None in this dataset."]
    lines += [
        "",
        "## How to read these results",
        "",
        "- The traffic is simulated, so results describe this dataset and may differ on real traffic.",
        "- The attacks were written by the project authors, so this isn't an independent benchmark.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--waf-url", help="Running WAF, to measure latency")
    parser.add_argument("--site-url", help="The website's own address, to measure direct latency")
    args = parser.parse_args()

    results = {"generated_at": datetime.now(UTC).isoformat(timespec="seconds"), **evaluate_detection()}
    if args.waf_url and args.site_url:
        results["latency"] = evaluate_latency(args.waf_url.rstrip("/"), args.site_url.rstrip("/"))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "evaluation.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    markdown = to_markdown(results)
    (OUTPUT_DIR / "evaluation.md").write_text(markdown, encoding="utf-8")
    print(markdown)
    return 0


if __name__ == "__main__":
    sys.exit(main())
