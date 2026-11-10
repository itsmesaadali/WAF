"""Create .env from .env.example and fill any empty secret with a random value.

Existing values are never overwritten, and secret values are never printed.
Usage: py scripts/setup-env.py
"""
from __future__ import annotations

import pathlib
import re
import secrets

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENV = ROOT / ".env"
EXAMPLE = ROOT / ".env.example"
GENERATED = ("WAF_SHARED_SECRET", "JWT_SECRET", "MODEL_SIGNING_KEY", "ADMIN_PASSWORD")


def main() -> None:
    created = not ENV.exists()
    text = ENV.read_text(encoding="utf-8") if ENV.exists() else EXAMPLE.read_text(encoding="utf-8")
    filled = []
    for name in GENERATED:
        pattern = re.compile(rf"^{name}=\s*$", re.MULTILINE)
        if pattern.search(text):
            text = pattern.sub(f"{name}={secrets.token_urlsafe(32)}", text)
            filled.append(name)
    ENV.write_text(text, encoding="utf-8")
    print(".env created" if created else ".env already existed")
    print("Generated:", ", ".join(filled) if filled else "nothing (all secrets already set)")
    if "USER:PASSWORD" in text:
        print("Next: open .env and set DATABASE_URL and DATABASE_URL_UNPOOLED.")


if __name__ == "__main__":
    main()
