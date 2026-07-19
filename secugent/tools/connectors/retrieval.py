# SPDX-License-Identifier: Apache-2.0
"""Read-only retrieval (source-search) connector (P2).

Wraps an *external* RAG/search endpoint (사내 데이터팀 파이프라인·벡터DB 게이트웨이·
Glean류) in the existing :class:`~secugent.tools.connectors.base.Connector`
contract. SecuGent does **not** implement retrieval, ranking, or re-ranking
(a project Non-goal — no vector DB, no embeddings, no chunking); this connector only
*admits* an external search result across the trust boundary, forcing every hit
through the fail-closed :class:`~secugent.core.grounding.Evidence` schema so a
result with no traceable source is rejected rather than trusted. No accuracy claim
is made or implied — the numbers are the external engine's, not SecuGent's.

Same shape as :class:`~secugent.tools.connectors.docs.DocsConnector`:

* ``validate_action`` — side-effect-free allow-none whitelist over the workspace
  (=collection) and an optional sub-collection; it re-decides nothing (the central
  :class:`~secugent.io.broker.connector_transport.ConnectorTransport` remains the
  single source of truth for Rule-of-Two membership and the audit trail).
* ``execute`` — re-checks the policy, consumes one rate-limit token, requires an
  OAuth ``secret_value`` (resolved by the caller via ``SecretsManager``), resolves
  the transport fail-closed (:class:`~secugent.tools.connectors.base.ConnectorTransportUnavailable`,
  never a mock success), calls it, and turns each hit into an :class:`Evidence`.

Read-only: ``actions == ("search",)`` — no mutation, so it never touches the
2-phase staging / compensation path. Any vendor SDK/``httpx`` is a lazy import
*inside the injected transport callable only*, never at module import
(air-gapped boot — INV-R7).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from secugent.core.grounding import Evidence
from secugent.core.tenancy import Principal
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorError,
    ConnectorPolicy,
    ConnectorResult,
    WhitelistViolation,
    _RateLimitedConnector,
)

__all__ = ["RetrievalConnector"]

# The three provenance fields a hit MUST carry for its Evidence to be traceable
# (INV-R5). A hit missing any of them is rejected fail-closed — no anonymous
# evidence is admitted.
_REQUIRED_EVIDENCE_FIELDS = ("source_uri", "doc_id", "retrieved_at")
# Content fields the connector forwards when present. Only these known keys are
# passed to ``Evidence`` (which is ``extra="forbid"``), so a vendor-specific extra
# key can never smuggle unvalidated content into the payload.
_OPTIONAL_EVIDENCE_FIELDS = ("span", "score")


class RetrievalConnector(_RateLimitedConnector):
    name = "retrieval"
    actions = ("search",)

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        # Allow-none over the workspace (=collection) first: an empty allowlist
        # denies every action fail-closed (INV-R2).
        if not policy.allowed_workspace_ids:
            raise WhitelistViolation("retrieval.allowed_workspace_ids is empty (allow-none)")
        workspace = action.params.get("workspace_id")
        if workspace not in policy.allowed_workspace_ids:
            raise WhitelistViolation(f"retrieval workspace {workspace!r} not in allowlist")

        # Optional sub-collection scope, homomorphic to the docs folder gate: when
        # the caller narrows a search to a ``collection_id`` it must be on the
        # allowlist (allow-none), so a narrower query cannot escape the grant.
        collection = action.params.get("collection_id")
        if collection is not None:
            if not policy.allowed_database_ids:
                raise WhitelistViolation("retrieval.allowed_database_ids is empty (allow-none)")
            if collection not in policy.allowed_database_ids:
                raise WhitelistViolation(f"retrieval collection {collection!r} not in allowlist")

    async def execute(
        self,
        action: ConnectorAction,
        *,
        principal: Principal,
        policy: ConnectorPolicy,
        http_transport: Any | None = None,
        secret_value: str = "",
    ) -> ConnectorResult:
        await self.validate_action(action, policy)
        self._take_rate_token(principal, policy)
        if not secret_value:
            raise WhitelistViolation("retrieval connector requires OAuth token via SecretsManager")
        # Per-call transport > bound transport > fail closed (no mock success).
        transport = self._resolve_transport(http_transport)
        response = await self._call_transport(
            transport, action=action, principal=principal, secret_value=secret_value
        )
        if not isinstance(response, Mapping):
            raise ConnectorError("retrieval transport returned a non-mapping response")
        evidence = _parse_evidence(response.get("hits", []))
        return ConnectorResult(
            ok=bool(response.get("ok", True)),
            payload={"evidence": [item.model_dump(mode="json") for item in evidence]},
        )

    async def _call_transport(
        self,
        transport: Any,
        *,
        action: ConnectorAction,
        principal: Principal,
        secret_value: str,
    ) -> Any:
        # Convert any transport failure (timeout/network/vendor error) into a
        # domain ConnectorError carrying a generic message — the credential and the
        # raw vendor text must never leak through an error path. A
        # ConnectorError raised by the transport itself keeps its concrete type
        # (e.g. a nested WhitelistViolation stays a policy denial).
        try:
            return await transport(action=action, principal=principal, secret_value=secret_value)
        except ConnectorError:
            raise
        except Exception as exc:
            # Broad by design: an injected transport can fail in any vendor-specific
            # way; re-raise as a sanitized domain error rather than swallowing it.
            raise ConnectorError("retrieval search transport failed") from exc


def _parse_evidence(hits: Any) -> list[Evidence]:
    """Turn a transport ``hits`` payload into validated :class:`Evidence`.

    Fail-closed and all-or-nothing (INV-R5): a non-list ``hits``, a non-mapping
    hit, a hit missing any of :data:`_REQUIRED_EVIDENCE_FIELDS`, or a hit that
    fails :class:`Evidence` validation all raise :class:`ConnectorError` for the
    *whole* batch — no partial acceptance. Error messages name only the offending
    field, never the raw hit content or the credential.
    """
    if not isinstance(hits, list):
        raise ConnectorError("retrieval transport 'hits' must be a list")
    return [_hit_to_evidence(hit) for hit in hits]


def _hit_to_evidence(hit: Any) -> Evidence:
    if not isinstance(hit, Mapping):
        raise ConnectorError("retrieval hit must be a mapping")
    missing = [field for field in _REQUIRED_EVIDENCE_FIELDS if field not in hit]
    if missing:
        # Name only the absent field(s) (INV-R5) — never the hit content.
        raise ConnectorError(f"retrieval hit missing required evidence field(s): {sorted(missing)}")
    fields: dict[str, Any] = {field: hit[field] for field in _REQUIRED_EVIDENCE_FIELDS}
    # ``snippet`` is content that may legitimately be empty (only the three
    # provenance fields are mandatory), so default it rather than fail closed.
    fields["snippet"] = hit.get("snippet", "")
    for optional in _OPTIONAL_EVIDENCE_FIELDS:
        if optional in hit:
            fields[optional] = hit[optional]
    try:
        return Evidence(**fields)
    except ValidationError as exc:
        # Evidence rejected the hit (blank identifier / score out of range / bad
        # timestamp). Fail closed without echoing the raw value.
        raise ConnectorError("retrieval hit failed Evidence validation") from exc
