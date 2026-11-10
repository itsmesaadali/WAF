"""Train the anomaly model.

Usage:
  py -m app.ml.train                       simulated normal traffic
  py -m app.ml.train --source observed     simulated plus real traffic the WAF allowed
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass

import numpy as np
from sqlalchemy import select

from ..config import get_settings
from ..db import session_scope
from ..models import MlModelRun, RequestLog
from . import model as model_lib
from .features import FEATURE_NAMES, extract
from .model import TrainedModel
from .traffic import generate_normal

DEFAULT_SAMPLES = 6000
HOLDOUT_SAMPLES = 2000
TRAIN_SEED = 20261
HOLDOUT_SEED = 20262
MIN_OBSERVED = 200
MAX_OBSERVED = 20000


@dataclass(frozen=True)
class TrainResult:
    model: TrainedModel
    source: str
    samples: int
    observed_samples: int
    holdout_flag_rate: float


def observed_rows() -> list[list[float]]:
    """Real requests that passed every check. Flagged traffic is excluded to resist poisoning."""
    with session_scope() as session:
        stored = session.scalars(
            select(RequestLog.features)
            .where(
                RequestLog.action == "allowed",
                RequestLog.is_anomaly.is_(False),
                RequestLog.simulated.is_(False),
                RequestLog.features.is_not(None),
            )
            .order_by(RequestLog.created_at.desc())
            .limit(MAX_OBSERVED)
        ).all()
    return [row for row in stored if isinstance(row, list) and len(row) == len(FEATURE_NAMES)]


def train(source: str = "generated", samples: int = DEFAULT_SAMPLES) -> TrainResult:
    rows = [extract(view) for view in generate_normal(samples, TRAIN_SEED)]
    observed: list[list[float]] = []
    if source == "observed":
        observed = observed_rows()
        if len(observed) < MIN_OBSERVED:
            raise ValueError(f"need at least {MIN_OBSERVED} allowed requests, only {len(observed)} recorded")
        rows += observed
    model = model_lib.fit(rows)
    # Held-out traffic was never seen in training, giving a fair false-alarm estimate.
    holdout = [extract(view) for view in generate_normal(HOLDOUT_SAMPLES, HOLDOUT_SEED)]
    flag_rate = float(np.mean(model.score_many(holdout) >= model.threshold))
    return TrainResult(model, source, len(rows), len(observed), flag_rate)


def record_run(result: TrainResult, trained_by: str | None) -> int:
    with session_scope() as session:
        session.query(MlModelRun).filter(MlModelRun.active.is_(True)).update({"active": False})
        run = MlModelRun(
            source=result.source,
            samples=result.samples,
            contamination=result.model.contamination,
            threshold=result.model.threshold,
            holdout_flag_rate=result.holdout_flag_rate,
            feature_names=list(FEATURE_NAMES),
            trained_by=trained_by,
            active=True,
        )
        session.add(run)
        session.flush()
        return run.id


def train_and_save(source: str = "generated", samples: int = DEFAULT_SAMPLES, trained_by: str | None = None) -> TrainResult:
    settings = get_settings()
    result = train(source, samples)
    model_lib.save(result.model, settings.model_path, settings.model_signing_key)
    try:
        record_run(result, trained_by)
    except Exception as exc:  # noqa: BLE001 - the model is usable without this history row
        print(f"Warning: model saved, but its history row was not written: {exc.__class__.__name__}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Isolation Forest anomaly model")
    parser.add_argument("--source", choices=("generated", "observed"), default="generated")
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    args = parser.parse_args()
    result = train_and_save(args.source, args.samples, trained_by="cli")
    print(f"Trained on {result.samples} requests ({result.source}, {result.observed_samples} observed)")
    print(f"Alert threshold: {result.model.threshold:.4f}")
    print(f"Held-out normal traffic flagged: {result.holdout_flag_rate:.2%}")


if __name__ == "__main__":
    main()
