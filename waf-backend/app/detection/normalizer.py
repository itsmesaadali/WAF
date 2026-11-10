"""Undo the encoding tricks attackers use to hide payloads from signatures.

Each function is pure and bounded: decoding depth and input size are both limited,
so a crafted request cannot make normalization run for a long time.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from urllib.parse import unquote_plus

MAX_DECODE_ROUNDS = 4
MAX_INSPECT_CHARS = 64 * 1024

_UNICODE_ESCAPE = re.compile(r"(?:\\u|%u)([0-9a-fA-F]{4})")
_HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_WHITESPACE = re.compile(r"\s+")
_BASE64_TOKEN = re.compile(r"^[A-Za-z0-9+/_-]{12,}={0,2}$")
_ZERO_WIDTH = re.compile("[​‌‍⁠﻿­]")
# Remove control characters that browsers ignore inside words such as java\tscript.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _decode_once(value: str) -> str:
    decoded = unquote_plus(value, errors="replace")
    decoded = html.unescape(decoded)
    decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), decoded)
    decoded = _HEX_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), decoded)
    return decoded


def deep_decode(value: str) -> str:
    """Decode repeatedly until stable, which defeats double and triple encoding."""
    current = value[:MAX_INSPECT_CHARS]
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = _decode_once(current)
        if decoded == current:
            break
        current = decoded[:MAX_INSPECT_CHARS]
    return current


def decode_rounds(value: str) -> list[str]:
    """Each decoding round's output, for showing how a hidden payload was revealed."""
    rounds: list[str] = []
    current = value[:MAX_INSPECT_CHARS]
    for _ in range(MAX_DECODE_ROUNDS):
        decoded = _decode_once(current)[:MAX_INSPECT_CHARS]
        if decoded == current:
            break
        rounds.append(decoded)
        current = decoded
    return rounds


def normalize(value: str) -> str:
    """Canonical form for most signatures: decoded, lower-case, single-spaced."""
    decoded = deep_decode(value)
    decoded = unicodedata.normalize("NFKC", decoded)
    decoded = _ZERO_WIDTH.sub("", decoded)
    decoded = _CONTROL.sub("", decoded)
    # uni/**/on becomes "uni on", and un/**/ion is covered by compact() below.
    decoded = _SQL_BLOCK_COMMENT.sub(" ", decoded)
    return _WHITESPACE.sub(" ", decoded).strip().lower()


def compact(value: str) -> str:
    """Remove comments and all spaces to catch keywords split up to avoid matching."""
    decoded = deep_decode(value)
    decoded = unicodedata.normalize("NFKC", decoded)
    decoded = _ZERO_WIDTH.sub("", decoded)
    decoded = _CONTROL.sub("", decoded)
    decoded = _SQL_BLOCK_COMMENT.sub("", decoded)
    return _WHITESPACE.sub("", decoded).lower()


def try_base64(value: str) -> str | None:
    """Return decoded text when a value looks like base64 of readable text."""
    stripped = value.strip()
    if len(stripped) > 8192 or not _BASE64_TOKEN.match(stripped):
        return None
    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.replace("+", "-").replace("/", "_"))
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    return text if text and printable / len(text) > 0.95 else None
