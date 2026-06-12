# SPDX-License-Identifier: Apache-2.0
"""Draft → behavior preview → human sign-off (EM-04, deterministic gate).

The LLM converter only *proposes* a draft. What gets signed (and therefore
enforced, per EM-03 I-D) is the *behavior the admin approved*: ``sign_off``
refuses unless (1) every fixture passes against the compiled draft and (2) the
approver is an admin with MFA satisfied (4-eyes/MFA). The LLM is never in the
trust path.
"""

from __future__ import annotations

from dataclasses import dataclass

from secugent.audit.merkle import KmsProvider
from secugent.core.sec.policy.compiler import compile_policy
from secugent.core.sec.policy.fixtures import Fixture, run_fixtures
from secugent.core.sec.policy.schema import PolicyDoc
from secugent.core.sec.policy.signer import SignedBundle, sign_bundle
from secugent.core.tenancy import Principal

__all__ = ["BehaviorRow", "AuthoringError", "preview", "sign_off"]


class AuthoringError(Exception):
    """Raised when a draft may not be signed (fixtures failing, or bad approver)."""


@dataclass(frozen=True)
class BehaviorRow:
    """One reviewable row: 'this effect → blocked/allowed (matches expectation?)'."""

    fixture: Fixture
    outcome: str
    matches_expected: bool


def preview(draft: PolicyDoc, fixtures: list[Fixture]) -> list[BehaviorRow]:
    """Render what the compiled ``draft`` does for each fixture — the admin
    approves *behavior*, not JSON."""
    compiled = compile_policy(draft)
    rows: list[BehaviorRow] = []
    for fixture in fixtures:
        outcome = compiled.evaluate(fixture.effect, fixture.label).outcome
        rows.append(
            BehaviorRow(fixture=fixture, outcome=outcome, matches_expected=outcome == fixture.expected)
        )
    return rows


def sign_off(
    draft: PolicyDoc,
    fixtures: list[Fixture],
    *,
    approver: Principal,
    kms: KmsProvider,
    key_id: str,
) -> SignedBundle:
    """Promote ``draft`` to a signed bundle iff the approver is admin+MFA AND
    every fixture passes. Raises :class:`AuthoringError` otherwise (fail-closed)."""
    if approver.role != "admin":
        raise AuthoringError(f"sign-off requires admin role, got {approver.role!r}")
    if not approver.mfa_satisfied:
        raise AuthoringError("sign-off requires MFA-satisfied approver")
    report = run_fixtures(compile_policy(draft), fixtures)
    if not report.all_passed:
        raise AuthoringError(
            f"sign-off blocked: {len(report.failures)} fixture(s) do not match the draft's behavior"
        )
    return sign_bundle(draft, kms=kms, key_id=key_id)
