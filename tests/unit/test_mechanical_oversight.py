# SPDX-License-Identifier: Apache-2.0
"""Unit tests for secugent.core.mechanical_oversight.

Covers fail-closed normalisation, bypass defenses (.. traversal, UNC, 8.3
short paths, env-var expansion, case variants, punycode, subdomains, IP
literals) and the four rule categories.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from secugent.core.contracts import (
    HardBlockException,
    SessionRegulationPatch,
    Step,
)
from secugent.core.mechanical_oversight import (
    NormalizationError,
    OversightEngine,
    normalize_command,
    normalize_domain,
    normalize_path,
)
from secugent.core.regulations import (
    BannedCommand,
    BannedPath,
    DataLabel,
    DomainPolicy,
    Regulations,
    load_regulations,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


_REGULATIONS_EXAMPLES_DIR = Path(__file__).resolve().parents[2] / "regulations_examples"
_requires_examples = pytest.mark.skipif(
    not _REGULATIONS_EXAMPLES_DIR.is_dir(),
    reason="regulations_examples fixtures not shipped in public core",
)


def _engine_from_default() -> OversightEngine:
    path = Path(__file__).resolve().parents[2] / "regulations_examples" / "default.json"
    return OversightEngine(load_regulations(path))


def _make_engine(**kwargs: object) -> OversightEngine:
    regs = Regulations(
        version="t",
        banned_paths=list(kwargs.get("banned_paths", [])),  # type: ignore[arg-type]
        domain_policy=kwargs.get("domain_policy"),  # type: ignore[arg-type]
        banned_commands=list(kwargs.get("banned_commands", [])),  # type: ignore[arg-type]
        data_labels=list(kwargs.get("data_labels", [])),  # type: ignore[arg-type]
    )
    return OversightEngine(regs)


def _step(*, action_type: str = "file_read", target: str | None = None, command: str | None = None) -> Step:
    return Step(
        tenant_id="legacy-default",
        run_id="r",
        actor="sub:1",
        action_type=action_type,  # type: ignore[arg-type]
        target=target,
        command=command,
    )


# ---------------------------------------------------------------------------
# normalize_path
# ---------------------------------------------------------------------------


def test_normalize_path_basic_windows() -> None:
    assert normalize_path("C:\\Users\\Foo\\bar.txt") == "c:/users/foo/bar.txt"


def test_normalize_path_dotdot_resolved() -> None:
    assert normalize_path("C:/a/b/../c") == "c:/a/c"


def test_normalize_path_repeated_slashes() -> None:
    assert normalize_path("C:////a///b") == "c:/a/b"


def test_normalize_path_unc_preserved() -> None:
    assert normalize_path("\\\\server\\share\\foo") == "//server/share/foo"


def test_normalize_path_rejects_short_name() -> None:
    with pytest.raises(NormalizationError):
        normalize_path("C:/PROGRA~1/x")


def test_normalize_path_rejects_env_var() -> None:
    with pytest.raises(NormalizationError):
        normalize_path("%USERPROFILE%/secret.txt")
    with pytest.raises(NormalizationError):
        normalize_path("$HOME/x")


def test_normalize_path_rejects_nul() -> None:
    with pytest.raises(NormalizationError):
        normalize_path("C:/a\x00b")


def test_normalize_path_dotdot_escape_anchored() -> None:
    # Excess `..` segments cannot escape the root.
    assert normalize_path("C:/../../../etc/passwd") == "c:/etc/passwd"


# ---------------------------------------------------------------------------
# normalize_domain
# ---------------------------------------------------------------------------


def test_normalize_domain_strip_userinfo_and_port() -> None:
    host, is_ip = normalize_domain("https://user:pw@Sub.Example.Com:8443/path")
    assert host == "sub.example.com"
    assert is_ip is False


def test_normalize_domain_idn_to_punycode() -> None:
    host, is_ip = normalize_domain("http://한국.kr")
    assert host.startswith("xn--")
    assert is_ip is False


def test_normalize_domain_ip_literal() -> None:
    host, is_ip = normalize_domain("http://192.168.1.10:80/")
    assert is_ip is True
    assert host == "192.168.1.10"


def test_normalize_domain_strip_trailing_dot() -> None:
    host, _ = normalize_domain("Example.com.")
    assert host == "example.com"


def test_normalize_domain_rejects_empty() -> None:
    with pytest.raises(NormalizationError):
        normalize_domain("")


# ---------------------------------------------------------------------------
# normalize_command
# ---------------------------------------------------------------------------


def test_normalize_command_collapses_whitespace() -> None:
    assert normalize_command("rm   -rf   /") == "rm -rf /"


def test_normalize_command_rejects_empty() -> None:
    with pytest.raises(NormalizationError):
        normalize_command("   ")


# ---------------------------------------------------------------------------
# Banned path matching
# ---------------------------------------------------------------------------


def test_d_confidential_hard_block() -> None:
    engine = _make_engine(
        banned_paths=[
            BannedPath(
                rule_id="r1",
                pattern="d:/confidential/*",
                actions=["file_read", "file_write"],
            )
        ]
    )
    step = _step(action_type="file_read", target="D:\\confidential\\secret.docx")
    result = engine.evaluate(step)
    assert result.allowed is False
    assert result.hard_block is True
    assert result.violation is not None
    assert result.violation.category == "banned_path"
    with pytest.raises(HardBlockException):
        result.raise_if_blocked()


def test_dotdot_cannot_bypass_banned_path() -> None:
    engine = _make_engine(
        banned_paths=[BannedPath(rule_id="r1", pattern="d:/confidential/*", actions=["file_read"])]
    )
    sneaky = _step(action_type="file_read", target="D:\\public\\..\\confidential\\plan.txt")
    result = engine.evaluate(sneaky)
    assert result.hard_block is True


def test_case_variation_cannot_bypass_banned_path() -> None:
    engine = _make_engine(
        banned_paths=[BannedPath(rule_id="r1", pattern="d:/confidential/*", actions=["file_read"])]
    )
    res = engine.evaluate(_step(target="d:\\CONFIDENTIAL\\plan.txt"))
    assert res.hard_block is True


def test_short_name_rejected_as_normalisation_fail() -> None:
    engine = _make_engine(banned_paths=[BannedPath(rule_id="r1", pattern="*", actions=["file_read"])])
    res = engine.evaluate(_step(target="C:/PROGRA~1/secret"))
    assert res.allowed is False
    assert res.violation is not None
    assert res.violation.category == "normalization"


def test_env_var_path_rejected_as_normalisation_fail() -> None:
    engine = _make_engine(banned_paths=[])
    res = engine.evaluate(_step(target="%USERPROFILE%\\Documents\\x.txt"))
    assert res.allowed is False
    assert res.violation is not None
    assert res.violation.category == "normalization"


def test_unc_path_matched() -> None:
    engine = _make_engine(
        banned_paths=[
            BannedPath(rule_id="r1", pattern="//server/share/*", actions=["file_read", "file_write"])
        ]
    )
    res = engine.evaluate(_step(target="\\\\Server\\Share\\file.txt"))
    assert res.hard_block is True


def test_action_filter_skips_irrelevant_rules() -> None:
    engine = _make_engine(
        banned_paths=[BannedPath(rule_id="r1", pattern="d:/confidential/*", actions=["file_write"])]
    )
    # file_read should pass since the rule scope is file_write only.
    res = engine.evaluate(_step(action_type="file_read", target="d:/confidential/x"))
    assert res.allowed is True


# ---------------------------------------------------------------------------
# Domain policy (allow_list / deny_list / subdomain / ip / punycode)
# ---------------------------------------------------------------------------


def test_domain_allow_list_pass() -> None:
    engine = _make_engine(
        domain_policy=DomainPolicy(mode="allow_list", domains=["example.com"], allow_subdomains=True)
    )
    res = engine.evaluate(_step(action_type="http_get", target="https://docs.example.com/x"))
    assert res.allowed is True


def test_domain_allow_list_subdomain_disabled() -> None:
    engine = _make_engine(
        domain_policy=DomainPolicy(mode="allow_list", domains=["example.com"], allow_subdomains=False)
    )
    res = engine.evaluate(_step(action_type="http_get", target="https://docs.example.com/x"))
    assert res.allowed is False
    assert res.hard_block is True


def test_domain_allow_list_other_domain_blocked() -> None:
    engine = _make_engine(domain_policy=DomainPolicy(mode="allow_list", domains=["example.com"]))
    res = engine.evaluate(_step(action_type="http_get", target="https://evil.com/"))
    assert res.hard_block is True


def test_domain_ip_literal_blocked() -> None:
    engine = _make_engine(
        domain_policy=DomainPolicy(mode="allow_list", domains=["example.com"], block_ip_literal=True)
    )
    res = engine.evaluate(_step(action_type="http_get", target="https://10.0.0.1/admin"))
    assert res.hard_block is True


def test_domain_punycode_blocked() -> None:
    engine = _make_engine(
        domain_policy=DomainPolicy(
            mode="allow_list",
            domains=["example.com"],
            block_punycode=True,
        )
    )
    # IDN gets encoded to punycode by normalize_domain; should be blocked.
    res = engine.evaluate(_step(action_type="http_get", target="http://한국.kr/"))
    assert res.hard_block is True


def test_domain_deny_list() -> None:
    engine = _make_engine(
        domain_policy=DomainPolicy(mode="deny_list", domains=["evil.com"], allow_subdomains=True)
    )
    res = engine.evaluate(_step(action_type="http_get", target="https://api.evil.com/"))
    assert res.hard_block is True


def test_domain_wildcard_pattern() -> None:
    engine = _make_engine(
        domain_policy=DomainPolicy(mode="allow_list", domains=["*.example.com"], allow_subdomains=False)
    )
    ok = engine.evaluate(_step(action_type="http_get", target="https://api.example.com/"))
    assert ok.allowed is True
    bad = engine.evaluate(_step(action_type="http_get", target="https://other.org/"))
    assert bad.allowed is False


def test_domain_normalisation_failure_blocks() -> None:
    engine = _make_engine(domain_policy=DomainPolicy(mode="allow_list", domains=["example.com"]))
    res = engine.evaluate(_step(action_type="http_get", target=""))
    assert res.allowed is False
    assert res.violation is not None
    assert res.violation.category == "normalization"


# ---------------------------------------------------------------------------
# Banned commands
# ---------------------------------------------------------------------------


def test_banned_command_matches() -> None:
    engine = _make_engine(banned_commands=[BannedCommand(rule_id="r1", pattern="\\brm\\s+-rf\\b")])
    res = engine.evaluate(_step(action_type="compute", command="rm -rf /tmp/x"))
    assert res.hard_block is True
    assert res.violation is not None
    assert res.violation.category == "banned_command"


def test_banned_command_case_insensitive() -> None:
    engine = _make_engine(banned_commands=[BannedCommand(rule_id="r1", pattern="format\\s+[a-z]:")])
    res = engine.evaluate(_step(action_type="compute", command="FORMAT C:"))
    assert res.hard_block is True


def test_invalid_command_regex_fails_closed() -> None:
    # Construct via dict bypassing pydantic-side validation (which doesn't
    # currently validate regex compileability).
    bad = BannedCommand(rule_id="bad", pattern="(unclosed")
    engine = _make_engine(banned_commands=[bad])
    res = engine.evaluate(_step(action_type="compute", command="anything"))
    assert res.allowed is False
    assert res.violation is not None
    assert res.violation.category == "schema"


# ---------------------------------------------------------------------------
# Data labels
# ---------------------------------------------------------------------------


def test_data_label_blocks_disallowed_action() -> None:
    engine = _make_engine(
        data_labels=[
            DataLabel(
                rule_id="lab-1",
                label="confidential",
                path_patterns=["*/대외비/*"],
                allowed_actions=["file_read"],
                hard_block=True,
            )
        ]
    )
    res = engine.evaluate(_step(action_type="file_write", target="D:/원본/대외비/plan.docx"))
    assert res.hard_block is True
    assert res.violation is not None
    assert res.violation.category == "data_label"


def test_data_label_allows_listed_action() -> None:
    engine = _make_engine(
        data_labels=[
            DataLabel(
                rule_id="lab-1",
                label="confidential",
                path_patterns=["*/대외비/*"],
                allowed_actions=["file_read"],
            )
        ]
    )
    res = engine.evaluate(_step(action_type="file_read", target="D:/원본/대외비/plan.docx"))
    assert res.allowed is True


# ---------------------------------------------------------------------------
# Unknown action_type and missing target
# ---------------------------------------------------------------------------


def test_unknown_action_blocked() -> None:
    engine = _make_engine()
    res = engine.evaluate(_step(action_type="unknown", target="anything"))
    assert res.allowed is False
    assert res.violation is not None
    assert res.violation.category == "unknown_action"


@_requires_examples
def test_no_target_no_match() -> None:
    engine = _engine_from_default()
    res = engine.evaluate(_step(action_type="compute", target=None, command="echo hi"))
    assert res.allowed is True


# ---------------------------------------------------------------------------
# Session patches (PHASE 6 preview — patch interface stable here)
# ---------------------------------------------------------------------------


def test_session_patch_adds_banned_path() -> None:
    engine = _make_engine()
    patch = SessionRegulationPatch(
        tenant_id="legacy-default",
        run_id="r",
        rules=[
            {
                "category": "banned_path",
                "rule_id": "session-attach",
                "pattern": "*/attachments/*",
                "actions": ["file_read", "file_write"],
                "hard_block": True,
            }
        ],
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        reason="STEER: do not touch attachments",
    )
    engine.add_session_patch(patch)
    res = engine.evaluate(_step(target="D:/case/attachments/secret.pdf"))
    assert res.hard_block is True


def test_session_patch_adds_banned_command() -> None:
    engine = _make_engine()
    patch = SessionRegulationPatch(
        tenant_id="legacy-default",
        run_id="r",
        rules=[
            {
                "category": "banned_command",
                "rule_id": "session-mail",
                "pattern": "\\bmail\\s+",
                "hard_block": True,
            }
        ],
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        reason="STEER: no outbound mail",
    )
    engine.add_session_patch(patch)
    res = engine.evaluate(_step(action_type="compute", command="mail boss@x.com < report"))
    assert res.hard_block is True


# ---------------------------------------------------------------------------
# Default sample integration
# ---------------------------------------------------------------------------


@_requires_examples
def test_default_blocks_confidential_dir() -> None:
    engine = _engine_from_default()
    res = engine.evaluate(_step(target="D:/team/confidential/plan.docx"))
    assert res.hard_block is True


@_requires_examples
def test_default_blocks_rm_rf() -> None:
    engine = _engine_from_default()
    res = engine.evaluate(_step(action_type="compute", command="rm -rf /"))
    assert res.hard_block is True
