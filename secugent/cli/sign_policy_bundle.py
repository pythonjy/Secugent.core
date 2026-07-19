# SPDX-License-Identifier: Apache-2.0
"""``secugent sign-policy-bundle`` — offline signer for the egress policy bundle (blocker E).

The production ``deploy/docker-compose.yml`` HARD-requires a signed egress policy
bundle (``SECUGENT_POLICY_BUNDLE_FILE=${VAR:?}`` → compose aborts if unset), but
no subcommand could *produce* one from the shipped ``closed_net.json`` template.
Operators were stuck: prod compose could not boot. This subcommand closes that
gap by driving the exact 4-eyes/MFA sign-off gate the HTTP ``/policy/sign`` route
uses, but offline (air-gap-first) — no running server, no audit store.

Trust model (deterministic module):

* The signing gate is :func:`secugent.core.sec.policy.authoring.sign_off` — NEVER
  ``sign_bundle`` directly. ``sign_off`` refuses unless the approver is an
  admin with MFA satisfied AND every fixture matches the compiled draft's
  behaviour (the operator approves *behaviour*, not JSON).
* Signing material comes from :func:`secugent.audit.merkle.build_kms_provider`
  (HMAC in dev / prod-mirror, external KMS in prod) — no hand-rolled crypto. The
  The prod guard makes ``SECUGENT_ENV=production`` refuse the dev HMAC key
  (fail-closed) unless ``SECUGENT_KMS_ALLOW_DEV_HMAC=1`` (prod-mirror smoke tests).
* This CLI is an OFFLINE admin tool: ``role=admin`` is asserted by tool
  invocation, MFA/4-eyes is affirmed via ``--approver-mfa`` (default on), and the
  real cryptographic control is KMS signing-key possession.

The produced bundle is the file an operator points ``SECUGENT_POLICY_BUNDLE_FILE``
at; production boot loads it fail-closed via ``load_active_policy`` with the
``SECUGENT_POLICY_ALLOWED_KEY_IDS`` pin.

Import closure is PUBLIC_CORE only (policy authoring/signer/loader + audit KMS +
tenancy + ``secugent.cli.verify``); it never imports the FastAPI app.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from secugent.audit.merkle import KmsProvider, KmsSettings, build_kms_provider
from secugent.cli.verify import _emit
from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy.authoring import AuthoringError, sign_off
from secugent.core.sec.policy.fixtures import Fixture
from secugent.core.sec.policy.loader import write_signed_bundle
from secugent.core.sec.policy.schema import PolicyDoc
from secugent.core.tenancy import Principal, Role, TenantId

__all__ = ["run_sign_policy_bundle", "main"]

_PROG = "secugent sign-policy-bundle"


# --------------------------------------------------------------------------- #
# Boundary input models (mirror the /policy/sign route's EffectIn/FixtureIn) —
# validated with extra="forbid" so a typo'd key fails closed.
# --------------------------------------------------------------------------- #


class _EffectIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: EffectKind
    target: str
    sink_class: SinkClass
    byte_estimate: int = 0
    action: str | None = None

    def to_effect(self) -> Effect:
        # Effect.__post_init__ rejects non-canonical targets (ValueError), which
        # the loader surfaces as a fail-closed exit.
        return Effect(
            kind=self.kind,
            target=self.target,
            sink_class=self.sink_class,
            byte_estimate=self.byte_estimate,
            action=self.action,
        )


class _FixtureIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    effect: _EffectIn
    label: DataLabel
    expected: Literal["allow", "deny", "hard_block"]

    @field_validator("label", mode="before")
    @classmethod
    def _coerce_label(cls, value: object) -> object:
        """Accept a ``DataLabel`` member NAME ("CONFIDENTIAL", case-insensitive) as
        well as its integer value — operators hand-author fixtures, and a
        readable name is far less error-prone than a bare ``2``."""
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.lstrip("-").isdigit():
                return int(stripped)
            try:
                return DataLabel[stripped.upper()]
            except KeyError as exc:
                valid = ", ".join(member.name for member in DataLabel)
                raise ValueError(f"unknown DataLabel {value!r}; use one of: {valid}") from exc
        return value

    def to_fixture(self) -> Fixture:
        return Fixture(effect=self.effect.to_effect(), label=self.label, expected=self.expected)


class _FixturesFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixtures: list[_FixtureIn]


# --------------------------------------------------------------------------- #
# Loaders / KMS
# --------------------------------------------------------------------------- #


def _load_draft(path: str | Path) -> PolicyDoc:
    raw = Path(path).read_text(encoding="utf-8")
    return PolicyDoc.model_validate_json(raw)


def _load_fixtures(path: str | Path) -> list[Fixture]:
    raw = Path(path).read_text(encoding="utf-8")
    parsed = _FixturesFile.model_validate_json(raw)
    # to_fixture() constructs Effect, which may raise ValueError on a
    # non-canonical target — surfaced fail-closed by the caller.
    return [fx.to_fixture() for fx in parsed.fixtures]


def _build_signing_kms(key_id: str, environ: Mapping[str, str] | None) -> KmsProvider:
    """Build the signing provider from the KMS env, pinning ``key_id``.

    Reuses :func:`build_kms_provider` (the Merkle signer factory) so the policy
    signer never hand-rolls crypto. Overriding ``key_id`` makes the local
    (dev / prod-mirror) provider register the policy signing key; external
    providers pass it at sign time. The prod guard raises ``ValueError`` when
    ``SECUGENT_ENV=production`` selects ``provider=local`` without the documented
    ``SECUGENT_KMS_ALLOW_DEV_HMAC`` escape hatch (fail-closed).
    """
    settings = KmsSettings.from_env(environ).model_copy(update={"key_id": key_id})
    return build_kms_provider(settings)


def _default_admin() -> Principal:
    """Default offline signing principal (admin + MFA affirmed by tool use)."""
    return Principal(user_id="cli-admin", tenant_id=TenantId("cli-signer"), role="admin", mfa_satisfied=True)


# --------------------------------------------------------------------------- #
# Core
# --------------------------------------------------------------------------- #


def run_sign_policy_bundle(
    *,
    draft_path: str | Path,
    fixtures_path: str | Path,
    key_id: str,
    out_path: str | Path,
    approver: Principal | None = None,
    kms: KmsProvider | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Sign ``draft_path`` into a signed bundle at ``out_path`` through the 4-eyes gate.

    Returns a process exit code: ``0`` on a written, verifiable bundle; ``1`` on
    any gate/input/KMS failure (fail-closed — no partial artifact is written).
    ``approver`` / ``kms`` may be injected (tests); otherwise a default offline
    admin principal is used and the provider is built from the KMS env.
    """
    resolved_approver = approver if approver is not None else _default_admin()

    try:
        draft = _load_draft(draft_path)
    except OSError as exc:
        _emit(f"{_PROG}: cannot read policy draft '{draft_path}' — {exc}", stderr=True)
        return 1
    except (ValidationError, ValueError) as exc:
        _emit(f"{_PROG}: invalid policy draft — {exc}", stderr=True)
        return 1

    try:
        fixtures = _load_fixtures(fixtures_path)
    except OSError as exc:
        _emit(f"{_PROG}: cannot read fixtures '{fixtures_path}' — {exc}", stderr=True)
        return 1
    except (ValidationError, ValueError) as exc:
        _emit(f"{_PROG}: invalid fixtures — {exc}", stderr=True)
        return 1

    # Mirror the route's 422: at least one fixture must pin the signed behaviour.
    if not fixtures:
        _emit(
            f"{_PROG}: at least one fixture is required to sign behavior (empty fixture set rejected).",
            stderr=True,
        )
        return 1

    resolved_kms = kms
    if resolved_kms is None:
        try:
            resolved_kms = _build_signing_kms(key_id, environ)
        except ValueError as exc:
            _emit(f"{_PROG}: KMS/signing provider unavailable — {exc}", stderr=True)
            return 1

    try:
        bundle = sign_off(draft, fixtures, approver=resolved_approver, kms=resolved_kms, key_id=key_id)
    except AuthoringError as exc:
        # Non-admin / non-MFA approver, or a fixture that does not match the draft.
        _emit(f"{_PROG}: sign-off refused — {exc}", stderr=True)
        return 1
    except KeyError as exc:
        # The provider does not hold ``key_id`` (e.g. a local KMS with the key
        # unregistered). Fail closed rather than emit an unsigned/misbound bundle.
        _emit(
            f"{_PROG}: signing key {key_id!r} is not available in the KMS provider — {exc}",
            stderr=True,
        )
        return 1

    try:
        write_signed_bundle(bundle, out_path)
    except OSError as exc:
        _emit(f"{_PROG}: cannot write signed bundle to '{out_path}' — {exc}", stderr=True)
        return 1

    _emit(
        f"{_PROG}: wrote signed egress policy bundle to '{out_path}' "
        f"(key_id={bundle.key_id}, algorithm={bundle.algorithm}, doc_hash={bundle.doc_hash})."
    )
    _emit(
        "  → 배포: 이 파일을 SECUGENT_POLICY_BUNDLE_FILE 로 가리키고 "
        f"SECUGENT_POLICY_ALLOWED_KEY_IDS={bundle.key_id} 로 서명자 키를 핀(pin)하세요."
    )
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(rest: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog=_PROG,
        description=(
            "Sign an egress policy draft into a bundle through the 4-eyes/MFA gate "
            "(offline, air-gap-first). Produces the file SECUGENT_POLICY_BUNDLE_FILE "
            "points at."
        ),
    )
    parser.add_argument(
        "--draft", required=True, metavar="PATH", help="Unsigned PolicyDoc JSON (e.g. closed_net.json)."
    )
    parser.add_argument(
        "--fixtures", required=True, metavar="PATH", help="Behaviour fixtures JSON (non-empty)."
    )
    parser.add_argument(
        "--key-id",
        required=True,
        dest="key_id",
        metavar="ID",
        help="Signing key id (pin via SECUGENT_POLICY_ALLOWED_KEY_IDS).",
    )
    parser.add_argument("--out", required=True, metavar="PATH", help="Output signed bundle path.")
    parser.add_argument(
        "--approver-id",
        default="cli-admin",
        dest="approver_id",
        metavar="ID",
        help="Offline sign-off approver id (default: cli-admin).",
    )
    parser.add_argument(
        "--approver-tenant",
        default="cli-signer",
        dest="approver_tenant",
        metavar="TENANT",
        help="Approver tenant id (default: cli-signer).",
    )
    parser.add_argument(
        "--approver-role",
        default="admin",
        dest="approver_role",
        choices=["admin", "operator", "viewer"],
        help="Approver role (default: admin; sign-off requires admin).",
    )
    parser.add_argument(
        "--approver-mfa",
        default=True,
        dest="approver_mfa",
        action=argparse.BooleanOptionalAction,
        help="Affirm offline MFA/4-eyes (default: on; --no-approver-mfa fails closed).",
    )
    return parser.parse_args(rest)


def _narrow_role(role: str) -> Role:
    # argparse ``choices`` guarantees one of these three; narrow str → Role for mypy.
    if role == "admin":
        return "admin"
    if role == "operator":
        return "operator"
    return "viewer"


def main(rest: list[str]) -> int:
    """``secugent sign-policy-bundle`` entry point. Returns a process exit code."""
    args = _parse_args(rest)
    try:
        approver = Principal(
            user_id=args.approver_id,
            tenant_id=TenantId(args.approver_tenant),
            role=_narrow_role(args.approver_role),
            mfa_satisfied=args.approver_mfa,
        )
    except (ValueError, ValidationError) as exc:
        _emit(f"{_PROG}: invalid approver — {exc}", stderr=True)
        return 1

    return run_sign_policy_bundle(
        draft_path=args.draft,
        fixtures_path=args.fixtures,
        key_id=args.key_id,
        out_path=args.out,
        approver=approver,
    )


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
