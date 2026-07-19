# SPDX-License-Identifier: Apache-2.0
"""N3 (갭 ④) — connector/tool payload → validated :class:`Evidence` (fail-closed).

A **pure boundary module** (no I/O, no global state, no wall clock): it re-admits
the ``evidence`` list a retrieval connector/MCP tool put on its ``ConnectorResult``
payload, re-validating every element against the N2
:class:`~secugent.core.grounding.Evidence` schema before it can ground a plan
decision.

The re-validation is deliberately defensive (§B-8): even though the connector
already validated the evidence, this injection boundary re-checks it and admits
**all-or-nothing** — a single malformed element fails the whole batch
(:class:`EvidenceBindingError`), never a partial admission (INV-N3-4). This is the
strict, injection-side counterpart to the lenient *display* projection in
:func:`secugent.api.plan_review.plan_view_from_plan` (the asymmetry is intentional
— display must not 500, injection must not trust).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from secugent.core.grounding import Evidence

__all__ = [
    "EvidenceBindingError",
    "evidence_from_connector_payload",
]


class EvidenceBindingError(ValueError):
    """A connector/tool payload's ``evidence`` violated the boundary contract.

    Raised fail-closed for a non-list ``evidence`` value or any element that fails
    :class:`~secugent.core.grounding.Evidence` validation. The message names only
    the offending position/shape — never the raw ``source_uri``/``snippet`` — so
    no retrieval content leaks through the error path.
    """


def evidence_from_connector_payload(payload: Mapping[str, Any]) -> list[Evidence]:
    """Parse ``payload['evidence']`` (N1's dict list) into validated Evidence.

    Contract (spec ``docs/specs/2026-07-12-evidence-orchestration-audit.md``):

    * ``evidence`` key **absent** → ``[]`` (a tool response with no grounding is
      normal, not an error).
    * ``evidence`` present but **not a list** (incl. an explicit ``None``) →
      :class:`EvidenceBindingError`.
    * **any** element not a mapping, or failing :class:`Evidence` validation
      (missing/blank ``source_uri``/``doc_id``, out-of-range ``score``, forbidden
      extra field, …) → :class:`EvidenceBindingError`. No partial acceptance
      (INV-N3-4).

    Order is preserved; the function is a pure function of ``payload``.
    """
    if "evidence" not in payload:
        return []
    raw = payload["evidence"]
    if not isinstance(raw, list):
        raise EvidenceBindingError("connector payload 'evidence' must be a list")
    parsed: list[Evidence] = []
    for index, element in enumerate(raw):
        if not isinstance(element, Mapping):
            raise EvidenceBindingError(f"connector payload evidence[{index}] must be a mapping")
        try:
            parsed.append(Evidence.model_validate(dict(element)))
        except ValidationError as exc:
            # Re-raise as the boundary exception; the pydantic detail is chained
            # (``from exc``) but the boundary message stays position-only.
            raise EvidenceBindingError(
                f"connector payload evidence[{index}] failed Evidence validation"
            ) from exc
    return parsed
