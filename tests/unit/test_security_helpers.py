"""Client IP, rate limiting, redirects, settings, ML and login token behaviour."""
from __future__ import annotations

from pathlib import Path

import jwt
import numpy as np
import pytest
from pydantic import ValidationError

from app.config import to_sqlalchemy_url
from app.ml import model as model_lib
from app.ml.features import FEATURE_NAMES, RequestView, entropy, extract
from app.ml.traffic import generate_normal
from app.proxy.router import _rewrite_location
from app.security.activity import IpActivity
from app.security.auth import create_token, decode_token, hash_password, verify_password
from app.security.client_ip import canonical_ip, resolve_client_ip
from app.services.runtime_settings import RuntimeSettings


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# --- Client IP ---
def test_forwarded_header_ignored_without_trusted_proxy() -> None:
    assert resolve_client_ip("10.0.0.5", "1.2.3.4", 0) == "10.0.0.5"


def test_attacker_cannot_fake_ip_behind_one_proxy() -> None:
    # The attacker sent "9.9.9.9"; the trusted proxy appended the real address.
    assert resolve_client_ip("10.0.0.1", "9.9.9.9, 5.6.7.8", 1) == "5.6.7.8"


def test_missing_or_invalid_forwarded_header_falls_back_to_peer() -> None:
    assert resolve_client_ip("10.0.0.1", None, 1) == "10.0.0.1"
    assert resolve_client_ip("10.0.0.1", "not-an-ip", 1) == "10.0.0.1"
    assert resolve_client_ip("10.0.0.1", "1.1.1.1", 2) == "10.0.0.1"


def test_canonical_ip_handles_ipv4_mapped_and_garbage() -> None:
    assert canonical_ip("::ffff:1.2.3.4") == "1.2.3.4"
    assert canonical_ip("nope") is None


# --- Activity tracking ---
def test_sliding_window_expires_old_requests() -> None:
    clock = FakeClock()
    activity = IpActivity(clock)
    for _ in range(5):
        activity.record("1.1.1.1", "/")
    assert activity.record("1.1.1.1", "/").requests_last_minute == 6
    clock.now += 61
    assert activity.record("1.1.1.1", "/").requests_last_minute == 1


def test_ips_are_counted_separately_and_unique_paths_tracked() -> None:
    activity = IpActivity(FakeClock())
    activity.record("1.1.1.1", "/a")
    snapshot = activity.record("1.1.1.1", "/b")
    assert snapshot.unique_paths_last_minute == 2
    assert activity.record("2.2.2.2", "/a").requests_last_minute == 1


def test_strikes_expire_after_ten_minutes() -> None:
    clock = FakeClock()
    activity = IpActivity(clock)
    assert activity.add_strike("1.1.1.1") == 1
    assert activity.add_strike("1.1.1.1") == 2
    clock.now += 601
    assert activity.add_strike("1.1.1.1") == 1


def test_repeated_incidents_are_deduplicated() -> None:
    clock = FakeClock()
    activity = IpActivity(clock)
    assert activity.should_report("1.1.1.1", "rate_limit") is True
    assert activity.should_report("1.1.1.1", "rate_limit") is False
    clock.now += 61
    assert activity.should_report("1.1.1.1", "rate_limit") is True


# --- Redirects ---
def test_upstream_redirect_stays_on_the_waf() -> None:
    assert _rewrite_location("https://site.example/a?b=1", "https://site.example") == "/a?b=1"
    assert _rewrite_location("http://site.example/a", "https://site.example") == "/a"
    assert _rewrite_location("/local", "https://site.example") == "/local"
    assert _rewrite_location("https://other.example/x", "https://site.example") == "https://other.example/x"


# --- Settings ---
def test_settings_reject_invalid_values() -> None:
    with pytest.raises(ValidationError):
        RuntimeSettings(mode="off")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        RuntimeSettings(rate_limit_per_minute=1)
    with pytest.raises(ValidationError):
        RuntimeSettings(ip_allowlist=["not-a-network"])


def test_allowlist_matches_networks() -> None:
    settings = RuntimeSettings(ip_allowlist=["10.0.0.0/8", "1.2.3.4"])
    assert settings.is_allowlisted("10.5.5.5") and settings.is_allowlisted("1.2.3.4")
    assert not settings.is_allowlisted("8.8.8.8")


def test_database_url_is_converted_with_options_kept() -> None:
    url = to_sqlalchemy_url("postgresql://u:p@h/db?sslmode=require&channel_binding=require&schema=x")
    assert url.startswith("postgresql+psycopg://u:p@h/db?")
    assert "channel_binding=require" in url and "schema" not in url


# --- Machine learning ---
def _view(**overrides: object) -> RequestView:
    base = dict(
        method="GET", path="/products", query="q=book", header_count=12,
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
        has_accept=True, body=b"", requests_last_minute=5, unique_paths_last_minute=3, error_ratio_last_minute=0.0,
    )
    return RequestView(**{**base, **overrides})  # type: ignore[arg-type]


@pytest.fixture(scope="module")
def trained() -> model_lib.TrainedModel:
    return model_lib.fit([extract(v) for v in generate_normal(3000, 1)])


def test_feature_vector_matches_declared_names() -> None:
    assert len(extract(_view())) == len(FEATURE_NAMES)


def test_entropy_is_higher_for_random_text() -> None:
    assert entropy("aaaaaaaa") == 0
    assert entropy("x8Kq2Zp9") > entropy("aaaabbbb")


def test_generated_traffic_is_reproducible() -> None:
    assert generate_normal(50, 7) == generate_normal(50, 7)


def test_ordinary_request_is_not_anomalous(trained: model_lib.TrainedModel) -> None:
    assert not trained.is_anomaly(trained.score(extract(_view())))


def test_unusual_request_is_anomalous(trained: model_lib.TrainedModel) -> None:
    odd = _view(
        query="blob=" + "aZ9x" * 400, user_agent="x", has_accept=False, header_count=2,
        requests_last_minute=500, unique_paths_last_minute=480, error_ratio_last_minute=0.9,
    )
    assert trained.is_anomaly(trained.score(extract(odd)))


def test_held_out_normal_traffic_flag_rate_is_low(trained: model_lib.TrainedModel) -> None:
    rows = [extract(v) for v in generate_normal(1000, 99)]
    assert float(np.mean(trained.score_many(rows) >= trained.threshold)) < 0.05


def test_threshold_override_is_used(trained: model_lib.TrainedModel) -> None:
    assert trained.is_anomaly(0.1, threshold_override=0.05)
    assert not trained.is_anomaly(0.99, threshold_override=1.0)


def test_signed_model_round_trip(trained: model_lib.TrainedModel, tmp_path: Path) -> None:
    path = tmp_path / "m.joblib"
    model_lib.save(trained, path, "key")
    assert model_lib.load(path, "key").threshold == trained.threshold


def test_tampered_model_is_refused(trained: model_lib.TrainedModel, tmp_path: Path) -> None:
    path = tmp_path / "m.joblib"
    model_lib.save(trained, path, "key")
    path.write_bytes(path.read_bytes() + b"tampered")
    with pytest.raises(model_lib.ModelIntegrityError):
        model_lib.load(path, "key")


def test_wrong_key_and_missing_signature_are_refused(trained: model_lib.TrainedModel, tmp_path: Path) -> None:
    path = tmp_path / "m.joblib"
    model_lib.save(trained, path, "key")
    with pytest.raises(model_lib.ModelIntegrityError):
        model_lib.load(path, "other")
    path.with_suffix(".joblib.sig").unlink()
    with pytest.raises(model_lib.ModelIntegrityError):
        model_lib.load(path, "key")


# --- Login ---
def test_password_hash_verifies_and_rejects() -> None:
    stored = hash_password("correct horse battery")
    assert "correct" not in stored
    assert verify_password(stored, "correct horse battery")
    assert not verify_password(stored, "wrong")
    assert not verify_password(None, "anything")


def test_token_round_trip_and_tampering() -> None:
    token, _ = create_token("admin", 3)
    payload = decode_token(token)
    assert payload["sub"] == "admin" and payload["ver"] == 3
    with pytest.raises(jwt.PyJWTError):
        decode_token(token[:-2] + "xx")


def test_unsigned_token_is_refused() -> None:
    forged = jwt.encode({"sub": "admin", "ver": 0}, "", algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        decode_token(forged)
