# SPDX-License-Identifier: Apache-2.0
"""Structured logging with redaction for SecuGent.

The logger MUST redact API keys, bearer tokens,
emails, KR resident numbers, large file bodies and large base64 blobs before
they reach the JSONL log file or the durable SQLite event store.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

__all__ = ["redact", "JsonlLogger", "redact_string"]


# ---------------------------------------------------------------------------
# Patterns (compiled once)
# ---------------------------------------------------------------------------

_API_KEY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{20,}"),
    re.compile(r"xox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgho_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),  # long hex (md5/sha1/sha256-like)
)

_BEARER_PATTERN = re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-_\.=]+")
_EMAIL_PATTERN = re.compile(r"\b([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*(@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_KR_RRN_PATTERN = re.compile(r"\b\d{6}-\d{7}\b")
#: Payment-card PANs (credit/debit): 13–19 digits, contiguous or hyphen/space
#: grouped. Mirrors :data:`secugent.audit.export._CARD_PAN` so write-time redaction
#: and disclosure scrubbing stay symmetric — a card number must never reach the
#: durable store unmasked (adversarial-review finding-1). A Luhn check
#: (:func:`_luhn_valid`) gates masking to avoid over-masking order/serial numbers.
_CARD_PAN_PATTERN = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")
_BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/=]{2048,}")

# Body / blob size limits (bytes when encoded as UTF-8)
_MAX_STRING_BYTES = 8 * 1024
_BLOB_TRUNCATE_HEAD = 256
_LARGE_BLOB_THRESHOLD = 4 * 1024

# Fields whose names imply secret material — replaced wholesale.
_SECRET_KEY_NAMES = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "private_key",
    "client_secret",
}


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------


def _mask_email(match: re.Match[str]) -> str:
    first, domain = match.group(1), match.group(2)
    return f"{first}***{domain}"


def _luhn_valid(digits: str) -> bool:
    """Return ``True`` iff ``digits`` (digit-only) satisfies the Luhn checksum.

    Distinguishes real payment-card PANs from incidental long digit runs so the
    card masker does not over-mask order/serial numbers.
    """
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48  # '0' == 48; caller guarantees digits-only
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_card_pan(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    return "[REDACTED:CARD]" if 13 <= len(digits) <= 19 and _luhn_valid(digits) else match.group(0)


def redact_string(value: str) -> str:
    """Apply textual redaction patterns to a single string value."""
    out = value
    for pat in _API_KEY_PATTERNS:
        out = pat.sub("[REDACTED:KEY]", out)
    out = _BEARER_PATTERN.sub("Bearer [REDACTED]", out)
    out = _EMAIL_PATTERN.sub(_mask_email, out)
    out = _KR_RRN_PATTERN.sub("[REDACTED:RRN]", out)
    # Card PANs after RRN (RRN is exactly 13 digits with a fixed hyphen position;
    # masking it first keeps the card rule from over-claiming an RRN-shaped token).
    out = _CARD_PAN_PATTERN.sub(_mask_card_pan, out)

    # Large base64-ish blobs
    def _blob_repl(m: re.Match[str]) -> str:
        blob = m.group(0)
        digest = hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()
        return f"[REDACTED:BLOB sha256={digest[:16]} len={len(blob)}]"

    out = _BASE64_BLOB_PATTERN.sub(_blob_repl, out)

    # Overall string-length cap
    encoded = out.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_STRING_BYTES:
        digest = hashlib.sha256(encoded).hexdigest()
        head = encoded[:_BLOB_TRUNCATE_HEAD].decode("utf-8", errors="replace")
        out = f"{head}…[TRUNCATED sha256={digest[:16]} bytes={len(encoded)}]"
    return out


def redact(payload: Any) -> Any:
    """Recursively redact a JSON-like payload.

    - dict keys matching secret name list → replaced with ``[REDACTED]``
    - all string leaves run through :func:`redact_string`
    - other scalars (int/float/bool/None) pass through unchanged
    """
    if isinstance(payload, dict):
        cleaned: dict[str, Any] = {}
        for k, v in payload.items():
            if isinstance(k, str) and k.lower() in _SECRET_KEY_NAMES:
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact(v)
        return cleaned
    if isinstance(payload, list):
        return [redact(item) for item in payload]
    if isinstance(payload, tuple):
        return tuple(redact(item) for item in payload)
    if isinstance(payload, str):
        return redact_string(payload)
    return payload


# ---------------------------------------------------------------------------
# JSONL logger
# ---------------------------------------------------------------------------


class JsonlLogger:
    """Append-only JSONL log file with automatic redaction.

    The JSONL log is the **auxiliary** output. The durable source of truth is
    :class:`secugent.core.event_store.EventStore`. Both writers MUST apply
    redaction before persisting.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def emit(
        self,
        *,
        actor: str,
        event_type: str,
        severity: str = "info",
        payload: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "ts": datetime.now(tz=UTC).isoformat(),
            "actor": actor,
            "event_type": event_type,
            "severity": severity,
            "payload": redact(payload or {}),
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
