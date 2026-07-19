# SPDX-License-Identifier: Apache-2.0
"""N1 (생산자 브리지) — connector/tool payloads → run-context grounding seed.

The **producer** half of the grounding-citation path, symmetric to the consumer
:func:`secugent.orchestrator.runner._bind_plan_evidence`. A retrieval connector /
MCP tool returns a :class:`~secugent.tools.connectors.base.ConnectorResult` whose
``payload`` is ``{"evidence": [dict, ...]}``; this admits that evidence across the
same trust boundary — re-validating it fail-closed against the N2
:class:`~secugent.core.grounding.Evidence` schema — and seeds the run context
under ``grounding_evidence`` so the consumer can bind it into ``plan['evidence']``.

SecuGent builds no retrieval engine (§A-1 Non-goal): this module only *moves* an
already-validated connector result onto the run context. It is a **pure boundary
primitive** (no I/O, no global state, no wall clock, no mutation): given the same
inputs it always yields the same dict.

Invariants:

* **INV-A1 (re-validation single-source)** — all Evidence validation goes through
  :func:`~secugent.orchestrator.evidence_binding.evidence_from_connector_payload`.
  This module never re-implements the schema check.
* **INV-A2 (non-mutating, pure)** — the input ``context`` is never mutated; a new
  ``dict`` is returned.
* **INV-A3 (fail-closed all-or-nothing)** — one malformed element in any payload
  raises :class:`~secugent.orchestrator.evidence_binding.EvidenceBindingError`;
  never a partial seed (symmetric to the consumer's INV-RW-2).
* **INV-A4 (empty ⇒ no key)** — an empty payload list, or payloads whose combined
  evidence is zero, returns the context unchanged (``grounding_evidence`` NOT
  added) so an ungrounded run stays normal (the consumer treats an absent key as
  ``[]``, INV-RW-1).
* **INV-A10 (existing key ⇒ fail-closed)** — a context that already carries
  ``grounding_evidence`` is rejected fail-closed (deny-by-default): re-seeding
  would create a double-writer / provenance-mix; the caller must not seed twice.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from secugent.orchestrator.evidence_binding import (
    EvidenceBindingError,
    evidence_from_connector_payload,
)

__all__ = ["seed_grounding_evidence"]

_GROUNDING_KEY = "grounding_evidence"


def seed_grounding_evidence(
    context: Mapping[str, Any],
    connector_payloads: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Seed ``context[grounding_evidence]`` from connector result payloads.

    Each element of ``connector_payloads`` is a ``ConnectorResult.payload`` shaped
    ``{"evidence": [dict, ...]}``. Their evidence lists are re-validated (via the
    single-source :func:`evidence_from_connector_payload`) and concatenated in
    order into the returned context's ``grounding_evidence``.

    Returns a **new** dict (the input is never mutated). When the combined evidence
    is empty the context is returned unchanged (no ``grounding_evidence`` key). A
    malformed element raises :class:`EvidenceBindingError` (all-or-nothing), and a
    context that already carries ``grounding_evidence`` is rejected fail-closed.
    """
    if _GROUNDING_KEY in context:
        # INV-A10: a caller must never seed twice — an existing seed would be
        # silently shadowed/mixed. The message names only the key, never content.
        raise EvidenceBindingError(f"run context already carries {_GROUNDING_KEY!r}")

    combined: list[dict[str, Any]] = []
    for payload in connector_payloads:
        # INV-A1/A3: re-validate through the single-source boundary; a malformed
        # element propagates EvidenceBindingError for the whole batch.
        for evidence in evidence_from_connector_payload(payload):
            combined.append(evidence.model_dump(mode="json"))

    seeded = dict(context)  # INV-A2: copy, never mutate the caller's mapping.
    if combined:
        seeded[_GROUNDING_KEY] = combined
    # INV-A4: empty combined ⇒ leave the key absent (ungrounded run is normal).
    return seeded
