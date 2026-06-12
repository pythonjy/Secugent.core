# SPDX-License-Identifier: Apache-2.0
"""Compile a reviewed :class:`PolicyDoc` into a deterministic matcher (EM-03)."""

from __future__ import annotations

import hashlib

from secugent.core.sec.policy._jcs import canonical_json
from secugent.core.sec.policy.evaluator import CompiledPolicy, CompiledRule
from secugent.core.sec.policy.schema import PolicyDoc

__all__ = ["compile_policy"]


def compile_policy(doc: PolicyDoc) -> CompiledPolicy:
    """Compile ``doc`` to a :class:`CompiledPolicy`.

    ``doc_hash`` is the sha256 of the canonical document JSON — the same bytes the
    signer signs, so a compiled policy and its signed bundle share one identity.
    """
    doc_json = canonical_json(doc.model_dump(mode="json"))
    doc_hash = hashlib.sha256(doc_json.encode("utf-8")).hexdigest()
    rules = tuple(
        CompiledRule(
            id=rule.id,
            effect=rule.effect,
            rationale=rule.rationale,
            kind=rule.match.kind,
            target_glob=rule.match.target_glob,
            sink_class=rule.match.sink_class,
            min_label=rule.match.min_label,
        )
        for rule in doc.rules
    )
    return CompiledPolicy(doc_hash=doc_hash, rules=rules)
