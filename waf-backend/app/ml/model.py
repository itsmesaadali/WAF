"""Train, save, load and score the Isolation Forest."""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from .features import FEATURE_NAMES

# Share of normal traffic allowed above the alert line while training.
DEFAULT_CONTAMINATION = 0.01
N_ESTIMATORS = 100


class ModelIntegrityError(RuntimeError):
    """The model file is missing its signature or its signature does not match."""


@dataclass
class TrainedModel:
    forest: IsolationForest
    threshold: float
    feature_names: tuple[str, ...]
    contamination: float

    def score(self, features: list[float]) -> float:
        """Anomaly score from roughly 0.3 to 0.8. Higher means more unusual."""
        row = np.asarray([features], dtype=np.float64)
        return float(-self.forest.score_samples(row)[0])

    def score_many(self, rows: list[list[float]]) -> np.ndarray:
        return -self.forest.score_samples(np.asarray(rows, dtype=np.float64))

    def is_anomaly(self, score: float, threshold_override: float | None = None) -> bool:
        return score >= (self.threshold if threshold_override is None else threshold_override)


def fit(rows: list[list[float]], contamination: float = DEFAULT_CONTAMINATION, seed: int = 42) -> TrainedModel:
    data = np.asarray(rows, dtype=np.float64)
    forest = IsolationForest(
        n_estimators=N_ESTIMATORS, contamination="auto", random_state=seed, n_jobs=1
    ).fit(data)
    scores = -forest.score_samples(data)
    # The alert line is set from normal traffic only, so no attack data is needed.
    threshold = float(np.quantile(scores, 1.0 - contamination))
    return TrainedModel(forest, threshold, FEATURE_NAMES, contamination)


def _signature_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".sig")


def _sign(data: bytes, key: str) -> str:
    return hmac.new(key.encode(), data, hashlib.sha256).hexdigest()


def save(model: TrainedModel, path: Path, signing_key: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "forest": model.forest,
            "threshold": model.threshold,
            "feature_names": model.feature_names,
            "contamination": model.contamination,
        },
        path,
    )
    _signature_path(path).write_text(_sign(path.read_bytes(), signing_key), encoding="ascii")


def load(path: Path, signing_key: str) -> TrainedModel:
    """joblib files can run code when loaded, so the signature is checked first."""
    signature_file = _signature_path(path)
    if not signature_file.exists():
        raise ModelIntegrityError("model signature is missing")
    expected = signature_file.read_text(encoding="ascii").strip()
    if not hmac.compare_digest(_sign(path.read_bytes(), signing_key), expected):
        raise ModelIntegrityError("model signature does not match")
    saved = joblib.load(path)
    if tuple(saved["feature_names"]) != FEATURE_NAMES:
        raise ModelIntegrityError("model was trained with different features; retrain it")
    return TrainedModel(saved["forest"], saved["threshold"], tuple(saved["feature_names"]), saved["contamination"])
