"""Make the WAF package importable and load safe values for tests that need no database."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "waf-backend"))

# Unit tests never connect, so these only satisfy the settings validation.
os.environ.setdefault("WAF_SHARED_SECRET", "unit-test-shared-secret-000000000000")
os.environ.setdefault("JWT_SECRET", "unit-test-jwt-secret-000000000000000")
os.environ.setdefault("MODEL_SIGNING_KEY", "unit-test-signing-key-00000000000000")
os.environ.setdefault("DATABASE_URL", "postgresql://unused:unused@localhost/unused")
