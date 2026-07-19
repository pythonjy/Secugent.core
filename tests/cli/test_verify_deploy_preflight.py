# SPDX-License-Identifier: Apache-2.0
"""Tests for the ``secugent verify --deploy`` preflight doctor (W8 B1).

Triple test strategy for a deterministic CLI module (§B-4a):

* **Unit** — every check's fire boundary AND pass boundary (severities + report.ok).
* **Property (hypothesis)** — arbitrary env dicts never raise and yield only
  findings (invariant P1); same env → identical report (determinism).
* **Scenario regression** — 6 fixtures reproducing the W6 blocker configs map to
  the expected firing-severity set. At least one Korean-message assertion (§C-3).
* **Determinism 100x** — one env snapshot → byte-identical ``PreflightReport``.

The preflight is a **pure** function (env dict in, report out) and never performs
I/O — this preserves ``verify``'s read-only Invariant I1.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from secugent.cli.verify import (
    CheckResult,
    PreflightReport,
    _parse_env_file,
    main,
    verify_deploy_preflight,
)

FIXTURES = Path(__file__).parent / "fixtures"


# --------------------------------------------------------------------------- #
# Baselines
# --------------------------------------------------------------------------- #

#: A fully-configured production env that passes every critical/high check.
GOOD_PROD: dict[str, str] = {
    "SECUGENT_ENV": "production",
    "SECUGENT_KMS_PROVIDER": "vault_transit",
    "VAULT_ADDR": "https://vault.internal:8200",
    "VAULT_TOKEN": "s.example",
    "DATABASE_URL": "postgresql+asyncpg://u:p@pg:5432/secugent",
    "SECUGENT_DB_PATH": "/data/secugent.db",
    "ANTHROPIC_API_KEY": "sk-ant-example",
    "SECUGENT_POLICY_BUNDLE_PATH": "/etc/secugent/policy.bundle.json",
    "SECUGENT_POLICY_ALLOWED_KEY_IDS": "merkle-2026",
    "SECUGENT_SANDBOX_ROOTS": "/srv/work",
    "SECUGENT_ALLOWED_DOMAINS": "api.internal",
}


def _with(**overrides: str | None) -> dict[str, str]:
    """Copy GOOD_PROD, applying overrides. A ``None`` value deletes the key."""
    env = dict(GOOD_PROD)
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return env


def _check(report: PreflightReport, name: str) -> CheckResult:
    for c in report.checks:
        if c.name == name:
            return c
    raise AssertionError(f"no check named {name!r} in {[c.name for c in report.checks]}")


# --------------------------------------------------------------------------- #
# Baseline / shape
# --------------------------------------------------------------------------- #


def test_good_prod_passes_all_critical_and_high() -> None:
    report = verify_deploy_preflight(GOOD_PROD)
    assert report.ok is True
    assert all(c.ok for c in report.checks if c.severity in ("critical", "high"))


def test_report_check_order_is_stable() -> None:
    names = [c.name for c in verify_deploy_preflight({}).checks]
    assert names == [
        "kms-signer",
        "audit-persistence",
        "ha-audit-fork",
        "tool-surface",
        "domestic-model",
        "ldap-tls",
        "egress-bundle",
    ]


def test_empty_env_never_raises_and_returns_report() -> None:
    report = verify_deploy_preflight({})
    assert isinstance(report, PreflightReport)
    assert len(report.checks) == 7


# --------------------------------------------------------------------------- #
# 1. kms-signer (A1, critical)
# --------------------------------------------------------------------------- #


def test_kms_signer_fires_critical_on_prod_local_provider() -> None:
    report = verify_deploy_preflight(_with(SECUGENT_KMS_PROVIDER="local"))
    c = _check(report, "kms-signer")
    assert c.severity == "critical"
    assert c.ok is False
    assert report.ok is False


def test_kms_signer_fires_when_provider_unset_in_prod() -> None:
    # provider unset ⇒ local ⇒ prod auto require_external ⇒ crash.
    report = verify_deploy_preflight(_with(SECUGENT_KMS_PROVIDER=None))
    assert _check(report, "kms-signer").ok is False


def test_kms_signer_passes_with_external_provider() -> None:
    assert _check(verify_deploy_preflight(GOOD_PROD), "kms-signer").ok is True


def test_kms_signer_passes_with_dev_hmac_escape_hatch() -> None:
    env = _with(SECUGENT_KMS_PROVIDER="local", SECUGENT_KMS_ALLOW_DEV_HMAC="1")
    assert _check(verify_deploy_preflight(env), "kms-signer").ok is True


def test_kms_signer_passes_local_outside_production() -> None:
    env = _with(SECUGENT_KMS_PROVIDER="local", SECUGENT_ENV="dev")
    assert _check(verify_deploy_preflight(env), "kms-signer").ok is True


def test_kms_signer_degrades_to_info_when_settings_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # If KmsSettings cannot be loaded/parsed, the check must NOT raise (P1): it
    # degrades to a non-blocking info finding instead.
    import secugent.audit.merkle as merkle

    def _boom(environ: object = None) -> object:
        raise RuntimeError("kms module unavailable")

    monkeypatch.setattr(merkle.KmsSettings, "from_env", _boom)
    report = verify_deploy_preflight(_with(SECUGENT_KMS_PROVIDER="local"))
    c = _check(report, "kms-signer")
    assert c.severity == "info"
    assert c.ok is True
    assert report.ok is True


# --------------------------------------------------------------------------- #
# 2. audit-persistence (W6-B, high)
# --------------------------------------------------------------------------- #


def test_audit_persistence_fires_when_singlenode_without_db_path() -> None:
    report = verify_deploy_preflight(_with(DATABASE_URL=None, SECUGENT_DB_PATH=None))
    c = _check(report, "audit-persistence")
    assert c.severity == "high"
    assert c.ok is False
    assert report.ok is False


def test_audit_persistence_passes_with_db_path() -> None:
    env = _with(DATABASE_URL=None, SECUGENT_DB_PATH="/data/secugent.db")
    assert _check(verify_deploy_preflight(env), "audit-persistence").ok is True


def test_audit_persistence_passes_with_database_url() -> None:
    env = _with(SECUGENT_DB_PATH=None)  # DATABASE_URL still set from GOOD_PROD
    assert _check(verify_deploy_preflight(env), "audit-persistence").ok is True


# --------------------------------------------------------------------------- #
# 3. ha-audit-fork (W6-A, high)
# --------------------------------------------------------------------------- #


def test_ha_fork_fires_when_ha_on_without_shared_pg() -> None:
    env = _with(SECUGENT_HA_ENABLED="1", DATABASE_URL=None)
    report = verify_deploy_preflight(env)
    c = _check(report, "ha-audit-fork")
    assert c.severity == "high"
    assert c.ok is False


def test_ha_fork_fires_on_replica_count_hint() -> None:
    env = _with(SECUGENT_REPLICA_COUNT="3", DATABASE_URL=None)
    assert _check(verify_deploy_preflight(env), "ha-audit-fork").ok is False


def test_ha_fork_passes_with_shared_pg() -> None:
    env = _with(SECUGENT_HA_ENABLED="1")  # DATABASE_URL set
    assert _check(verify_deploy_preflight(env), "ha-audit-fork").ok is True


def test_ha_fork_passes_when_ha_off() -> None:
    env = _with(SECUGENT_HA_ENABLED="0", DATABASE_URL=None)
    assert _check(verify_deploy_preflight(env), "ha-audit-fork").ok is True


# --------------------------------------------------------------------------- #
# 4. tool-surface (W6-H, info)
# --------------------------------------------------------------------------- #


def test_tool_surface_info_does_not_fail_report() -> None:
    env = _with(SECUGENT_SANDBOX_ROOTS=None, SECUGENT_ALLOWED_DOMAINS=None)
    report = verify_deploy_preflight(env)
    c = _check(report, "tool-surface")
    assert c.severity == "info"
    assert c.ok is False
    # info never sinks report.ok.
    assert report.ok is True


def test_tool_surface_passes_with_one_surface_set() -> None:
    env = _with(SECUGENT_ALLOWED_DOMAINS=None)  # roots still set
    assert _check(verify_deploy_preflight(env), "tool-surface").ok is True


# --------------------------------------------------------------------------- #
# 5. domestic-model (W6-LLM, high)
# --------------------------------------------------------------------------- #


def test_domestic_model_fires_endpoint_without_id() -> None:
    env = _with(
        ANTHROPIC_API_KEY=None,
        SECUGENT_DOMESTIC_MODEL_ENDPOINT="https://sovereign:8080",
    )
    report = verify_deploy_preflight(env)
    c = _check(report, "domestic-model")
    assert c.severity == "high"
    assert c.ok is False


def test_domestic_model_passes_with_model_id() -> None:
    env = _with(
        ANTHROPIC_API_KEY=None,
        SECUGENT_DOMESTIC_MODEL_ENDPOINT="https://sovereign:8080",
        SECUGENT_DOMESTIC_MODEL_ID="exaone-3.5",
    )
    assert _check(verify_deploy_preflight(env), "domestic-model").ok is True


def test_domestic_model_passes_with_anthropic_key() -> None:
    env = _with(SECUGENT_DOMESTIC_MODEL_ENDPOINT="https://sovereign:8080")
    assert _check(verify_deploy_preflight(env), "domestic-model").ok is True


def test_domestic_model_passes_without_endpoint() -> None:
    env = _with(ANTHROPIC_API_KEY=None)
    assert _check(verify_deploy_preflight(env), "domestic-model").ok is True


# --------------------------------------------------------------------------- #
# 6. ldap-tls (W6-F, high)
# --------------------------------------------------------------------------- #


def test_ldap_tls_fires_on_plaintext_ldap() -> None:
    env = _with(SECUGENT_AUTH_MODE="ldap", SECUGENT_LDAP_URI="ldap://ad.internal:389")
    report = verify_deploy_preflight(env)
    c = _check(report, "ldap-tls")
    assert c.severity == "high"
    assert c.ok is False


def test_ldap_tls_passes_on_ldaps() -> None:
    env = _with(SECUGENT_AUTH_MODE="ldap", SECUGENT_LDAP_URI="ldaps://ad.internal:636")
    assert _check(verify_deploy_preflight(env), "ldap-tls").ok is True


def test_ldap_tls_passes_with_explicit_insecure_optin() -> None:
    env = _with(
        SECUGENT_AUTH_MODE="ldap",
        SECUGENT_LDAP_URI="ldap://ad.internal:389",
        SECUGENT_LDAP_ALLOW_INSECURE_TRANSPORT="1",
    )
    assert _check(verify_deploy_preflight(env), "ldap-tls").ok is True


def test_ldap_tls_passes_when_auth_mode_not_ldap() -> None:
    env = _with(SECUGENT_AUTH_MODE="oidc", SECUGENT_LDAP_URI="ldap://ad.internal:389")
    assert _check(verify_deploy_preflight(env), "ldap-tls").ok is True


# --------------------------------------------------------------------------- #
# 7. egress-bundle (B6, high)
# --------------------------------------------------------------------------- #


def test_egress_bundle_fires_when_bundle_missing_in_prod() -> None:
    env = _with(SECUGENT_POLICY_BUNDLE_PATH=None)
    report = verify_deploy_preflight(env)
    c = _check(report, "egress-bundle")
    assert c.severity == "high"
    assert c.ok is False


def test_egress_bundle_fires_when_key_ids_missing_in_prod() -> None:
    env = _with(SECUGENT_POLICY_ALLOWED_KEY_IDS=None)
    assert _check(verify_deploy_preflight(env), "egress-bundle").ok is False


def test_egress_bundle_passes_when_fully_configured() -> None:
    assert _check(verify_deploy_preflight(GOOD_PROD), "egress-bundle").ok is True


def test_egress_bundle_passes_when_broker_disabled() -> None:
    env = _with(SECUGENT_POLICY_BUNDLE_PATH=None, SECUGENT_EGRESS_BROKER="0")
    assert _check(verify_deploy_preflight(env), "egress-bundle").ok is True


def test_egress_bundle_passes_in_dev() -> None:
    env = _with(SECUGENT_POLICY_BUNDLE_PATH=None, SECUGENT_ENV="dev")
    assert _check(verify_deploy_preflight(env), "egress-bundle").ok is True


# --------------------------------------------------------------------------- #
# Korean-message assertion (§C-3)
# --------------------------------------------------------------------------- #


def test_findings_carry_korean_guidance() -> None:
    kms = _check(verify_deploy_preflight(_with(SECUGENT_KMS_PROVIDER="local")), "kms-signer")
    # message explains what/why/how-to-fix in Korean (KST allowed).
    assert "프로덕션" in kms.message
    assert "SECUGENT_KMS_PROVIDER" in kms.message
    dom = _check(
        verify_deploy_preflight(
            _with(ANTHROPIC_API_KEY=None, SECUGENT_DOMESTIC_MODEL_ENDPOINT="https://s:8080")
        ),
        "domestic-model",
    )
    assert "SECUGENT_DOMESTIC_MODEL_ID" in dom.message


# --------------------------------------------------------------------------- #
# Scenario regression — 6 W6 blocker fixtures → expected firing severities
# --------------------------------------------------------------------------- #

_SCENARIOS: dict[str, tuple[dict[str, str], str, str]] = {
    # name: (env, offending_check, expected_severity)
    "kms": (_with(SECUGENT_KMS_PROVIDER="local"), "kms-signer", "critical"),
    "audit-persistence": (
        _with(DATABASE_URL=None, SECUGENT_DB_PATH=None),
        "audit-persistence",
        "high",
    ),
    "ha-fork": (_with(SECUGENT_HA_ENABLED="1", DATABASE_URL=None), "ha-audit-fork", "high"),
    "domestic": (
        _with(ANTHROPIC_API_KEY=None, SECUGENT_DOMESTIC_MODEL_ENDPOINT="https://s:8080"),
        "domestic-model",
        "high",
    ),
    "ldap": (
        _with(SECUGENT_AUTH_MODE="ldap", SECUGENT_LDAP_URI="ldap://ad:389"),
        "ldap-tls",
        "high",
    ),
    "egress": (_with(SECUGENT_POLICY_BUNDLE_PATH=None), "egress-bundle", "high"),
}


@pytest.mark.parametrize("scenario", sorted(_SCENARIOS))
def test_scenario_regression(scenario: str) -> None:
    env, offender, severity = _SCENARIOS[scenario]
    report = verify_deploy_preflight(env)
    c = _check(report, offender)
    assert c.ok is False
    assert c.severity == severity
    # critical/high scenarios must sink report.ok.
    assert report.ok is False


# --------------------------------------------------------------------------- #
# Property-based (hypothesis) — invariant P1 + determinism
# --------------------------------------------------------------------------- #

_KNOWN_KEYS = [
    "SECUGENT_ENV",
    "SECUGENT_KMS_PROVIDER",
    "SECUGENT_KMS_ALLOW_DEV_HMAC",
    "SECUGENT_KMS_REQUIRE_EXTERNAL",
    "DATABASE_URL",
    "SECUGENT_DB_PATH",
    "SECUGENT_HA_ENABLED",
    "SECUGENT_REPLICA_COUNT",
    "SECUGENT_SANDBOX_ROOTS",
    "SECUGENT_ALLOWED_DOMAINS",
    "ANTHROPIC_API_KEY",
    "SECUGENT_DOMESTIC_MODEL_ENDPOINT",
    "SECUGENT_DOMESTIC_MODEL_ID",
    "SECUGENT_AUTH_MODE",
    "SECUGENT_LDAP_URI",
    "SECUGENT_LDAP_ALLOW_INSECURE_TRANSPORT",
    "SECUGENT_POLICY_BUNDLE_PATH",
    "SECUGENT_POLICY_ALLOWED_KEY_IDS",
    "SECUGENT_EGRESS_BROKER",
]

_env_strategy = st.dictionaries(
    keys=st.one_of(st.sampled_from(_KNOWN_KEYS), st.text(max_size=40)),
    values=st.text(max_size=200),
    max_size=25,
)


@given(env=_env_strategy)
@settings(max_examples=250, suppress_health_check=[HealthCheck.too_slow])
def test_never_raises_returns_only_findings(env: dict[str, str]) -> None:
    report = verify_deploy_preflight(env)
    assert isinstance(report, PreflightReport)
    assert len(report.checks) == 7
    for c in report.checks:
        assert isinstance(c, CheckResult)
        assert c.severity in ("critical", "high", "medium", "info")
        assert isinstance(c.ok, bool)
        assert isinstance(c.message, str) and c.message
    expected_ok = all(c.ok for c in report.checks if c.severity in ("critical", "high"))
    assert report.ok is expected_ok


@given(env=_env_strategy)
@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
def test_same_env_identical_report(env: dict[str, str]) -> None:
    assert verify_deploy_preflight(env) == verify_deploy_preflight(dict(env))


# --------------------------------------------------------------------------- #
# Determinism 100x
# --------------------------------------------------------------------------- #


def test_determinism_100_runs() -> None:
    env = _with(SECUGENT_KMS_PROVIDER="local", DATABASE_URL=None, SECUGENT_DB_PATH=None)
    expected = verify_deploy_preflight(env)
    for _ in range(100):
        assert verify_deploy_preflight(env) == expected


# --------------------------------------------------------------------------- #
# CLI wiring
# --------------------------------------------------------------------------- #


def test_cli_deploy_bad_env_file_returns_nonzero(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["--deploy", "--env-file", str(FIXTURES / "bad_deploy.env")])
    assert rc == 1
    err = capsys.readouterr().err
    assert "kms-signer" in err  # critical routed to stderr


def test_cli_deploy_good_env_file_returns_zero() -> None:
    rc = main(["--deploy", "--env-file", str(FIXTURES / "good_deploy.env")])
    assert rc == 0


def test_cli_deploy_missing_env_file_is_operator_error() -> None:
    rc = main(["--deploy", "--env-file", str(FIXTURES / "does_not_exist.env")])
    assert rc == 1


def test_cli_deploy_unparseable_env_file(tmp_path: Path) -> None:
    bad = tmp_path / "broken.env"
    bad.write_text("this line has no equals sign\n", encoding="utf-8")
    rc = main(["--deploy", "--env-file", str(bad)])
    assert rc == 1


def test_cli_deploy_env_file_with_comments_and_blanks(tmp_path: Path) -> None:
    envf = tmp_path / "ok.env"
    envf.write_text(
        "\n# a comment\n\nSECUGENT_ENV=production\nSECUGENT_KMS_PROVIDER=vault_transit\n"
        "DATABASE_URL=postgres://x\nSECUGENT_DB_PATH=/d\nANTHROPIC_API_KEY=k\n"
        "SECUGENT_POLICY_BUNDLE_PATH=/b\nSECUGENT_POLICY_ALLOWED_KEY_IDS=k1\n"
        "SECUGENT_SANDBOX_ROOTS=/r\n",
        encoding="utf-8",
    )
    assert main(["--deploy", "--env-file", str(envf)]) == 0


def test_cli_deploy_alone_uses_process_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "environ", dict(GOOD_PROD))
    assert main(["--deploy"]) == 0


def test_cli_deploy_alone_fails_on_bad_process_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "environ", {"SECUGENT_ENV": "production"})
    assert main(["--deploy"]) == 1


def test_parse_env_file_supports_export_and_comments(tmp_path: Path) -> None:
    envf = tmp_path / "e.env"
    envf.write_text(
        "# a comment\n\nexport SECUGENT_ENV=dev\nSECUGENT_DB_PATH=/data/x\n",
        encoding="utf-8",
    )
    assert _parse_env_file(envf) == {"SECUGENT_ENV": "dev", "SECUGENT_DB_PATH": "/data/x"}


def test_cli_deploy_composes_with_determinism() -> None:
    rc = main(
        [
            "--deploy",
            "--env-file",
            str(FIXTURES / "good_deploy.env"),
            "--determinism",
            "--fixture",
            str(FIXTURES / "determinism_seed.json"),
        ]
    )
    assert rc == 0


def test_cli_deploy_absent_preserves_determinism_only() -> None:
    # Existing --determinism behavior is byte-unchanged when --deploy is absent.
    rc = main(["--determinism", "--fixture", str(FIXTURES / "determinism_seed.json")])
    assert rc == 0
