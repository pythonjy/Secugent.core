# SPDX-License-Identifier: Apache-2.0
"""Signed, compiled policy artifacts (EM-03).

Mechanical Oversight enforces only signature-verified, compiled policy — the
authority lives in a human-signed artifact, not LLM output (SECURITY_CONTRACT
§11 I-D). See ``docs/specs/2026-06-02-em-03-policy-compiler.md``.
"""

from __future__ import annotations

from secugent.core.sec.policy.authoring import AuthoringError, BehaviorRow, preview, sign_off
from secugent.core.sec.policy.compiler import compile_policy
from secugent.core.sec.policy.evaluator import CompiledPolicy, CompiledRule, Decision
from secugent.core.sec.policy.fixtures import Fixture, FixtureReport, FixtureResult, run_fixtures
from secugent.core.sec.policy.loader import (
    PolicyLoadError,
    empty_deny_policy,
    load_active_policy,
    write_signed_bundle,
)
from secugent.core.sec.policy.schema import Match, PolicyDoc, Rule
from secugent.core.sec.policy.signer import (
    PolicySignatureError,
    SignedBundle,
    sign_bundle,
    verify_bundle,
)

__all__ = [
    # schema
    "Match",
    "Rule",
    "PolicyDoc",
    # compile + evaluate
    "compile_policy",
    "CompiledPolicy",
    "CompiledRule",
    "Decision",
    # signing
    "SignedBundle",
    "PolicySignatureError",
    "sign_bundle",
    "verify_bundle",
    # loading
    "PolicyLoadError",
    "load_active_policy",
    "write_signed_bundle",
    "empty_deny_policy",
    # fixtures + authoring (EM-04)
    "Fixture",
    "FixtureResult",
    "FixtureReport",
    "run_fixtures",
    "BehaviorRow",
    "AuthoringError",
    "preview",
    "sign_off",
]
