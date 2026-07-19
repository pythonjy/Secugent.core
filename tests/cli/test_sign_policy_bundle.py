# SPDX-License-Identifier: Apache-2.0
"""Blocker E — ``secugent sign-policy-bundle`` (§B-4a deterministic module).

The prod ``docker-compose.yml`` HARD-requires a signed egress policy bundle
(``SECUGENT_POLICY_BUNDLE_FILE=${VAR:?}``) but no CLI could produce one. These
tests pin the new signing subcommand across the mandated triple test layers:

  * UNIT           — schema/shape, admin+MFA gate, empty-fixtures reject,
                     missing-key reject, happy path verifies.
  * PROPERTY       — round-trip sign→verify ALWAYS holds; any tamper → verify FAILS.
  * SCENARIO REG.  — the produced bundle is accepted by the *production* boot
                     loader (``load_active_policy``) exactly as compose expects.
  * DETERMINISM    — 100× fixed-provider sign yields byte-identical payload +
                     signature and always verifies.

Prod-mode coverage: the defect only bites under ``SECUGENT_ENV=production``
container boot, so the scenario tests drive the real env → ``build_kms_provider``
path (B5 prod guard) rather than dev fixtures alone.

§C-3 fixtures are Korean financial closed-net (KB국민은행 ``*.kr-bank.internal``).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from secugent.audit.merkle import (
    KmsSettings,
    LocalHmacKmsProvider,
    build_kms_provider,
)
from secugent.cli.sign_policy_bundle import main, run_sign_policy_bundle
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import PolicyLoadError, load_active_policy
from secugent.core.tenancy import Principal, TenantId

# --------------------------------------------------------------------------- #
# shared fixtures / helpers
# --------------------------------------------------------------------------- #

_KEY_ID = "policy-prod-krbank"
_KEY_BYTES = b"secugent-closed-net-krbank-signing-key-0001"

_TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "secugent"
    / "core"
    / "sec"
    / "policy"
    / "bundles"
    / "closed_net.json"
)

# §C-3 Korean financial closed-net behaviour the operator signs off on.
_INTERNAL_EFFECT = {
    "kind": "net_send",
    "target": "https://core.kr-bank.internal/v1/accounts",
    "sink_class": "internal",
}
_EXTERNAL_EFFECT = {
    "kind": "net_send",
    "target": "https://api.vendor.example/v1/x",
    "sink_class": "external",
}
_GOOD_FIXTURES: dict[str, object] = {
    "fixtures": [
        {"effect": _INTERNAL_EFFECT, "label": "CONFIDENTIAL", "expected": "allow"},
        {"effect": _EXTERNAL_EFFECT, "label": "PUBLIC", "expected": "hard_block"},
    ]
}


def _dev_kms(key_id: str = _KEY_ID, *, register: bool = True) -> LocalHmacKmsProvider:
    kms = LocalHmacKmsProvider()
    if register:
        kms.register_key(key_id, _KEY_BYTES)
    return kms


def _admin(*, mfa: bool = True) -> Principal:
    return Principal(
        user_id="보안담당관",
        tenant_id=TenantId("financial-kr"),
        role="admin",
        mfa_satisfied=mfa,
    )


def _operator() -> Principal:
    return Principal(user_id="bob", tenant_id=TenantId("financial-kr"), role="operator", mfa_satisfied=True)


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _draft_file(tmp_path: Path) -> Path:
    dst = tmp_path / "draft.json"
    dst.write_text(_TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8")
    return dst


def _fixtures_file(tmp_path: Path, payload: object = _GOOD_FIXTURES) -> Path:
    return _write(tmp_path / "fixtures.json", payload)


def _internal() -> Effect:
    return Effect(
        kind=EffectKind.NET_SEND,
        target="https://core.kr-bank.internal/v1/accounts",
        sink_class=SinkClass.INTERNAL,
    )


def _external() -> Effect:
    return Effect(
        kind=EffectKind.NET_SEND, target="https://api.vendor.example/v1/x", sink_class=SinkClass.EXTERNAL
    )


def _assert_closed_net(out: Path, kms: LocalHmacKmsProvider) -> None:
    """Load the produced bundle exactly like prod boot and pin the behaviour."""
    compiled = load_active_policy(out, kms=kms, allowed_key_ids={_KEY_ID})
    assert compiled.evaluate(_internal(), DataLabel.CONFIDENTIAL).outcome == "allow"
    assert compiled.evaluate(_external(), DataLabel.PUBLIC).outcome == "hard_block"


# --------------------------------------------------------------------------- #
# UNIT
# --------------------------------------------------------------------------- #


def test_happy_path_writes_verifiable_bundle(tmp_path: Path) -> None:
    out = tmp_path / "active.bundle.json"
    kms = _dev_kms()
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=kms,
    )
    assert rc == 0
    assert out.exists()
    _assert_closed_net(out, kms)


def test_empty_fixtures_rejected(tmp_path: Path) -> None:
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path, {"fixtures": []}),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()  # INV-5: no partial artifact


def test_non_admin_rejected(tmp_path: Path) -> None:
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        approver=_operator(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_non_mfa_rejected(tmp_path: Path) -> None:
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(mfa=False),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_fixture_mismatch_rejected(tmp_path: Path) -> None:
    # External sink is hard_block by the template, but declare "allow" → mismatch.
    bad = {"fixtures": [{"effect": _EXTERNAL_EFFECT, "label": "PUBLIC", "expected": "allow"}]}
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path, bad),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_missing_key_in_kms_rejected(tmp_path: Path) -> None:
    # Provider without the signing key registered → KeyError → fail-closed.
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(register=False),
    )
    assert rc == 1
    assert not out.exists()


def test_missing_draft_file(tmp_path: Path) -> None:
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=tmp_path / "nope.json",
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_bad_draft_json_rejected(tmp_path: Path) -> None:
    draft = _write(tmp_path / "draft.json", {"version": "1"})  # missing tenant_id etc.
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=draft,
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_missing_fixtures_file(tmp_path: Path) -> None:
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=tmp_path / "nope.json",
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_bad_fixtures_schema_rejected(tmp_path: Path) -> None:
    bad = {"fixtures": [{"effect": _INTERNAL_EFFECT, "label": "CONFIDENTIAL"}]}  # no expected
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path, bad),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_non_canonical_effect_target_rejected(tmp_path: Path) -> None:
    bad = {
        "fixtures": [
            {
                "effect": {"kind": "file_read", "target": "c:\\secret\\a.txt", "sink_class": "local_sandbox"},
                "label": "SECRET",
                "expected": "deny",
            }
        ]
    }
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path, bad),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


@pytest.mark.parametrize("label", ["CONFIDENTIAL", "confidential", "2", 2])
def test_label_accepts_name_and_int(tmp_path: Path, label: object) -> None:
    payload = {
        "fixtures": [
            {"effect": _INTERNAL_EFFECT, "label": label, "expected": "allow"},
            {"effect": _EXTERNAL_EFFECT, "label": "PUBLIC", "expected": "hard_block"},
        ]
    }
    out = tmp_path / "active.bundle.json"
    kms = _dev_kms()
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path, payload),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=kms,
    )
    assert rc == 0
    _assert_closed_net(out, kms)


def test_unknown_label_name_rejected(tmp_path: Path) -> None:
    payload = {"fixtures": [{"effect": _INTERNAL_EFFECT, "label": "TOPSECRET", "expected": "allow"}]}
    out = tmp_path / "active.bundle.json"
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path, payload),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_write_failure_rejected(tmp_path: Path) -> None:
    out = tmp_path / "missing_dir" / "active.bundle.json"  # parent does not exist
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=_dev_kms(),
    )
    assert rc == 1
    assert not out.exists()


def test_default_approver_is_admin_happy(tmp_path: Path) -> None:
    # approver omitted → default CLI admin principal is used.
    out = tmp_path / "active.bundle.json"
    kms = _dev_kms()
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        kms=kms,
    )
    assert rc == 0
    _assert_closed_net(out, kms)


# --------------------------------------------------------------------------- #
# main() / argparse / dispatch
# --------------------------------------------------------------------------- #


def _local_env() -> dict[str, str]:
    return {"SECUGENT_KMS_PROVIDER": "local"}


def _main_args(tmp_path: Path, out: Path, extra: list[str] | None = None) -> list[str]:
    args = [
        "--draft",
        str(_draft_file(tmp_path)),
        "--fixtures",
        str(_fixtures_file(tmp_path)),
        "--key-id",
        _KEY_ID,
        "--out",
        str(out),
    ]
    return args + (extra or [])


def _loader_kms_from_env(env: Mapping[str, str]) -> LocalHmacKmsProvider:
    settings = KmsSettings.from_env(env).model_copy(update={"key_id": _KEY_ID})
    provider = build_kms_provider(settings)
    assert isinstance(provider, LocalHmacKmsProvider)
    return provider


def test_main_happy_builds_kms_from_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUGENT_KMS_PROVIDER", "local")
    out = tmp_path / "active.bundle.json"
    rc = main(_main_args(tmp_path, out))
    assert rc == 0
    _assert_closed_net(out, _loader_kms_from_env(_local_env()))


def test_main_operator_role_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUGENT_KMS_PROVIDER", "local")
    out = tmp_path / "active.bundle.json"
    rc = main(_main_args(tmp_path, out, ["--approver-role", "operator"]))
    assert rc == 1
    assert not out.exists()


def test_main_viewer_role_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUGENT_KMS_PROVIDER", "local")
    out = tmp_path / "active.bundle.json"
    rc = main(_main_args(tmp_path, out, ["--approver-role", "viewer"]))
    assert rc == 1
    assert not out.exists()


def test_main_no_mfa_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUGENT_KMS_PROVIDER", "local")
    out = tmp_path / "active.bundle.json"
    rc = main(_main_args(tmp_path, out, ["--no-approver-mfa"]))
    assert rc == 1
    assert not out.exists()


def test_main_bad_approver_tenant_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECUGENT_KMS_PROVIDER", "local")
    out = tmp_path / "active.bundle.json"
    rc = main(_main_args(tmp_path, out, ["--approver-tenant", "_Invalid_"]))
    assert rc == 1
    assert not out.exists()


def test_main_missing_required_arg_exits_2(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--draft", str(_draft_file(tmp_path))])  # missing --fixtures/--key-id/--out
    assert exc.value.code == 2


def test_dispatch_via_cli_entrypoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from secugent.cli.__main__ import main as cli_main

    monkeypatch.setenv("SECUGENT_KMS_PROVIDER", "local")
    out = tmp_path / "active.bundle.json"
    rc = cli_main(["sign-policy-bundle", *_main_args(tmp_path, out)])
    assert rc == 0
    _assert_closed_net(out, _loader_kms_from_env(_local_env()))


# --------------------------------------------------------------------------- #
# PROPERTY (hypothesis)
# --------------------------------------------------------------------------- #


@settings(
    max_examples=40,
    deadline=None,  # per-example file I/O + sign + load is not latency-bounded
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(host=st.from_regex(r"[a-z][a-z0-9-]{0,20}", fullmatch=True))
def test_property_roundtrip_sign_verify_always_holds(tmp_path: Path, host: str) -> None:
    """INV-3: any valid internal host → sign→load_active_policy always verifies."""
    target = f"https://{host}.kr-bank.internal/v1/x"
    payload = {
        "fixtures": [
            {
                "effect": {"kind": "net_send", "target": target, "sink_class": "internal"},
                "label": "CONFIDENTIAL",
                "expected": "allow",
            },
            {"effect": _EXTERNAL_EFFECT, "label": "PUBLIC", "expected": "hard_block"},
        ]
    }
    out = tmp_path / "prop.bundle.json"
    kms = _dev_kms()
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path, payload),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=kms,
    )
    assert rc == 0
    # Verifies (does not raise) under the same key material.
    load_active_policy(out, kms=kms, allowed_key_ids={_KEY_ID})


@settings(
    max_examples=40,
    deadline=None,  # per-example file I/O + sign + load is not latency-bounded
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(field=st.sampled_from(["doc_json", "doc_hash", "signature_hex", "key_id"]))
def test_property_any_tamper_fails_verify(tmp_path: Path, field: str) -> None:
    """INV-4: flipping any signed field → load_active_policy fails closed."""
    out = tmp_path / "tamper.bundle.json"
    kms = _dev_kms()
    rc = run_sign_policy_bundle(
        draft_path=_draft_file(tmp_path),
        fixtures_path=_fixtures_file(tmp_path),
        key_id=_KEY_ID,
        out_path=out,
        approver=_admin(),
        kms=kms,
    )
    assert rc == 0

    data = json.loads(out.read_text(encoding="utf-8"))
    original = data[field]
    if field == "signature_hex":
        # Flip the first hex nibble to a definitely-different one.
        data[field] = ("f" if original[0] != "f" else "0") + original[1:]
    else:
        data[field] = original + "X"
    out.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(PolicyLoadError):
        load_active_policy(out, kms=kms, allowed_key_ids={_KEY_ID})


# --------------------------------------------------------------------------- #
# SCENARIO REGRESSION — production boot path (SECUGENT_ENV=production)
# --------------------------------------------------------------------------- #


def test_prod_mirror_bundle_accepted_by_prod_loader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The signed bundle a prod-mirror operator produces is accepted by the exact
    fail-closed loader ``_resolve_broker_policy`` runs at production boot."""
    monkeypatch.setenv("SECUGENT_ENV", "production")
    monkeypatch.setenv("SECUGENT_KMS_PROVIDER", "local")
    monkeypatch.setenv("SECUGENT_KMS_ALLOW_DEV_HMAC", "1")  # documented prod-mirror escape hatch
    out = tmp_path / "active.bundle.json"
    rc = main(_main_args(tmp_path, out))
    assert rc == 0
    # Rebuild the loader KMS the way prod boot would (same env) and enforce.
    env = {
        "SECUGENT_ENV": "production",
        "SECUGENT_KMS_PROVIDER": "local",
        "SECUGENT_KMS_ALLOW_DEV_HMAC": "1",
    }
    _assert_closed_net(out, _loader_kms_from_env(env))


def test_prod_without_escape_hatch_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """B5 prod guard: SECUGENT_ENV=production + provider=local (no escape hatch) →
    refuse to sign with the dev HMAC key (fail-closed, no artifact)."""
    monkeypatch.setenv("SECUGENT_ENV", "production")
    monkeypatch.setenv("SECUGENT_KMS_PROVIDER", "local")
    monkeypatch.delenv("SECUGENT_KMS_ALLOW_DEV_HMAC", raising=False)
    out = tmp_path / "active.bundle.json"
    rc = main(_main_args(tmp_path, out))
    assert rc == 1
    assert not out.exists()


# --------------------------------------------------------------------------- #
# DETERMINISM — 100× (§B-4a)
# --------------------------------------------------------------------------- #


def test_determinism_100x(tmp_path: Path) -> None:
    """INV-2: same (draft, fixtures, key) → byte-identical payload + signature,
    100× under the fixed dev HMAC provider, always verifying."""
    draft = _draft_file(tmp_path)
    fixtures = _fixtures_file(tmp_path)
    kms = _dev_kms()

    canonical: tuple[str, str] | None = None
    for i in range(100):
        out = tmp_path / f"det_{i}.bundle.json"
        rc = run_sign_policy_bundle(
            draft_path=draft,
            fixtures_path=fixtures,
            key_id=_KEY_ID,
            out_path=out,
            approver=_admin(),
            kms=kms,
        )
        assert rc == 0
        data = json.loads(out.read_text(encoding="utf-8"))
        pair = (data["doc_json"], data["signature_hex"])
        if canonical is None:
            canonical = pair
        else:
            assert pair == canonical, f"non-deterministic signed payload at iteration {i}"
        # Always verifies.
        load_active_policy(out, kms=kms, allowed_key_ids={_KEY_ID})
