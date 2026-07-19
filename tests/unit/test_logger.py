# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secugent.core.logger — DA-M14 coverage gate (90%).

Covers previously-uncovered branches:
- L91: _luhn_valid double-digit reduction (value -= 9)
- L124-126: redact_string string-length truncation
- L148: redact() tuple branch
- L173: JsonlLogger.path property
"""

from __future__ import annotations

from pathlib import Path

from secugent.core.logger import JsonlLogger, redact, redact_string


def test_luhn_valid_triggers_double_digit_reduction() -> None:
    """L91: Luhn algorithm must subtract 9 when doubled digit exceeds 9.

    4111111111111111 (Visa) has all 1s — doubling gives 2, which never exceeds 9
    and doesn't trigger the L91 path.  We need a card where doubling ≥ 5 yields > 9.

    5500005555555559 (Mastercard test PAN): the reversed digits include '5's at
    even positions → 5*2=10 > 9 → value -= 9 fires (L91).  This PAN is Luhn-valid
    so redact_string must output [REDACTED:CARD].
    """
    # Mastercard test number: 5500 0055 5555 5559 (Luhn-valid)
    mastercard_pan = "5500 0055 5555 5559"
    result = redact_string(mastercard_pan)
    assert "[REDACTED:CARD]" in result, f"Expected card redaction, got: {result}"


def test_redact_string_truncates_long_string() -> None:
    """L124-126: strings exceeding _MAX_STRING_BYTES are truncated with a hash digest.

    Use Korean characters (not base64) to avoid the BLOB pattern firing first.
    _MAX_STRING_BYTES is 8 192 bytes; each Korean char is 3 UTF-8 bytes, so
    2 800 chars = 8 400 bytes, which exceeds the cap without triggering the blob regex.
    """
    # 한국어 문자는 base64 알파벳 밖이므로 blob 패턴을 촉발하지 않음 (§C-3)
    long_str = "가" * 2_800  # 2800 * 3 bytes = 8400 bytes > _MAX_STRING_BYTES (8192)
    result = redact_string(long_str)
    assert "[TRUNCATED" in result, f"Expected truncation marker, got: {result[:80]}"
    assert "sha256=" in result


def test_redact_tuple_branch() -> None:
    """L148: redact() must recurse into tuples."""
    payload = ({"api_key": "secret-value"}, "plain")
    result = redact(payload)
    assert isinstance(result, tuple)
    assert result[0]["api_key"] == "[REDACTED]"
    assert result[1] == "plain"


def test_jsonl_logger_path_property(tmp_path: Path) -> None:
    """L173: JsonlLogger.path property returns the configured Path."""
    log_file = tmp_path / "test.jsonl"
    logger = JsonlLogger(log_file)
    assert logger.path == log_file
    assert isinstance(logger.path, Path)


def test_jsonl_logger_emit_redacts_korean_actor(tmp_path: Path) -> None:
    """JsonlLogger.emit() redacts payload and writes a JSONL line.

    Korean actor fixture (§C-3): 금융감독원-시스템
    """
    log_file = tmp_path / "audit.jsonl"
    logger = JsonlLogger(log_file)
    logger.emit(
        actor="금융감독원-시스템",
        event_type="test.redact",
        severity="info",
        payload={"api_key": "should-be-redacted", "safe": "visible"},
    )
    content = log_file.read_text(encoding="utf-8")
    assert "[REDACTED]" in content
    assert "should-be-redacted" not in content
    assert "visible" in content
    assert "금융감독원-시스템" in content
