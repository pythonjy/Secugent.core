# SPDX-License-Identifier: Apache-2.0
"""N1 (갭 ①) — read-only retrieval (source-search) connector tests.

The connector wraps an *external* RAG/search endpoint in the existing
:class:`~secugent.tools.connectors.base.Connector` contract. It adds NO retrieval
or ranking logic (§A-1 Non-goal); the whole value is admitting an external result
across the trust boundary through the fail-closed
:class:`~secugent.core.grounding.Evidence` schema — a hit with no traceable source
is rejected, never trusted.

Not a §B-4a deterministic module (boundary I/O adapter), so unit + integration +
one property test cover it; no 100-run determinism regime.

Korean fixtures (§C-3): 여신심사 collection + 여신심사 PDF source URI.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker.connector_transport import ConnectorBinding
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorError,
    ConnectorPolicy,
    ConnectorTransportUnavailable,
    RateLimitExceeded,
    WhitelistViolation,
)
from secugent.tools.connectors.registry import ConnectorRegistry
from secugent.tools.connectors.retrieval import RetrievalConnector

# --------------------------------------------------------------------------- #
# Korean fixtures (§C-3)
# --------------------------------------------------------------------------- #

_WORKSPACE = "여신심사-collection"
_WORKSPACE_DENIED = "임원-대외비-collection"
_SUBCOLLECTION = "여신심사-2026-sub"
_SUBCOLLECTION_DENIED = "대외비-sub"
_SOURCE_URI = "s3://loan-review/2026/여신심사_00123.pdf"
_RETRIEVED_AT = "2026-07-12T09:30:00+09:00"  # KST


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #


def _principal(tenant: str = "acme") -> Principal:
    return Principal(user_id="alice@corp", tenant_id=TenantId(tenant), role="operator")


def _policy(
    *,
    workspaces: tuple[str, ...] = (_WORKSPACE,),
    collections: tuple[str, ...] = (),
    rate: int = 5,
) -> ConnectorPolicy:
    return ConnectorPolicy(
        allowed_workspace_ids=list(workspaces),
        allowed_database_ids=list(collections),
        rate_limit_per_sec=rate,
    )


def _action(*, workspace: str = _WORKSPACE, **params: Any) -> ConnectorAction:
    return ConnectorAction(name="search", params={"workspace_id": workspace, **params})


def _valid_hit(
    *, source_uri: str = _SOURCE_URI, doc_id: str = "여신심사_00123", **extra: Any
) -> dict[str, Any]:
    hit: dict[str, Any] = {
        "source_uri": source_uri,
        "doc_id": doc_id,
        "retrieved_at": _RETRIEVED_AT,
        "snippet": "차주 신용등급 및 담보 평가 요약",
    }
    hit.update(extra)
    return hit


def _ok_transport(hits: list[dict[str, Any]], *, ok: bool = True) -> Any:
    async def _t(*, action: ConnectorAction, principal: Principal, secret_value: str) -> dict[str, Any]:
        assert secret_value, "credential must reach the transport seam"
        return {"ok": ok, "hits": hits}

    return _t


# --------------------------------------------------------------------------- #
# INV-R1 — read-only shape
# --------------------------------------------------------------------------- #


def test_read_only_actions_invariant() -> None:
    connector = RetrievalConnector()
    assert connector.name == "retrieval"
    assert connector.actions == ("search",)


# --------------------------------------------------------------------------- #
# Happy path — evidence roundtrip
# --------------------------------------------------------------------------- #


async def test_search_admits_evidence_roundtrip() -> None:
    connector = RetrievalConnector()
    result = await connector.execute(
        _action(),
        principal=_principal(),
        policy=_policy(),
        http_transport=_ok_transport([_valid_hit(), _valid_hit(doc_id="여신심사_00124")]),
        secret_value="oauth-tok",
    )
    assert result.ok is True
    evidence = result.payload["evidence"]
    assert len(evidence) == 2
    assert evidence[0]["source_uri"] == _SOURCE_URI
    assert evidence[0]["doc_id"] == "여신심사_00123"
    assert "retrieved_at" in evidence[0]
    assert evidence[1]["doc_id"] == "여신심사_00124"


async def test_optional_span_and_score_roundtrip() -> None:
    connector = RetrievalConnector()
    result = await connector.execute(
        _action(),
        principal=_principal(),
        policy=_policy(),
        http_transport=_ok_transport([_valid_hit(span="p.3 ¶2", score=0.87)]),
        secret_value="tok",
    )
    ev = result.payload["evidence"][0]
    assert ev["span"] == "p.3 ¶2"
    assert ev["score"] == 0.87


async def test_bound_transport_used_when_no_per_call_transport() -> None:
    connector = RetrievalConnector(http_transport=_ok_transport([_valid_hit()]))
    result = await connector.execute(_action(), principal=_principal(), policy=_policy(), secret_value="tok")
    assert result.ok is True
    assert len(result.payload["evidence"]) == 1


async def test_ok_false_from_transport_propagates() -> None:
    connector = RetrievalConnector()
    result = await connector.execute(
        _action(),
        principal=_principal(),
        policy=_policy(),
        http_transport=_ok_transport([_valid_hit()], ok=False),
        secret_value="tok",
    )
    assert result.ok is False
    assert len(result.payload["evidence"]) == 1


# --------------------------------------------------------------------------- #
# INV-R2 — allow-none workspace whitelist
# --------------------------------------------------------------------------- #


async def test_empty_workspace_allowlist_denies_allow_none() -> None:
    connector = RetrievalConnector()
    with pytest.raises(WhitelistViolation):
        await connector.execute(
            _action(),
            principal=_principal(),
            policy=_policy(workspaces=()),
            http_transport=_ok_transport([_valid_hit()]),
            secret_value="tok",
        )


async def test_workspace_not_in_allowlist_denies() -> None:
    connector = RetrievalConnector()
    with pytest.raises(WhitelistViolation):
        await connector.execute(
            _action(workspace=_WORKSPACE_DENIED),
            principal=_principal(),
            policy=_policy(),
            http_transport=_ok_transport([_valid_hit()]),
            secret_value="tok",
        )


async def test_missing_workspace_param_denies() -> None:
    connector = RetrievalConnector()
    action = ConnectorAction(name="search", params={})  # no workspace_id
    with pytest.raises(WhitelistViolation):
        await connector.execute(
            action,
            principal=_principal(),
            policy=_policy(),
            http_transport=_ok_transport([_valid_hit()]),
            secret_value="tok",
        )


async def test_validate_action_is_side_effect_free() -> None:
    # Called by the transport as a pre-credential gate AND again inside execute,
    # so two calls must behave identically and consume no rate token.
    connector = RetrievalConnector()
    action = _action()
    policy = _policy()
    await connector.validate_action(action, policy)
    await connector.validate_action(action, policy)


# --------------------------------------------------------------------------- #
# Optional sub-collection gate (docs folder rule, homomorphic)
# --------------------------------------------------------------------------- #


async def test_collection_gate_allows_when_allowlisted() -> None:
    connector = RetrievalConnector()
    result = await connector.execute(
        _action(collection_id=_SUBCOLLECTION),
        principal=_principal(),
        policy=_policy(collections=(_SUBCOLLECTION,)),
        http_transport=_ok_transport([_valid_hit()]),
        secret_value="tok",
    )
    assert result.ok is True


async def test_collection_not_in_allowlist_denies() -> None:
    connector = RetrievalConnector()
    with pytest.raises(WhitelistViolation):
        await connector.execute(
            _action(collection_id=_SUBCOLLECTION_DENIED),
            principal=_principal(),
            policy=_policy(collections=(_SUBCOLLECTION,)),
            http_transport=_ok_transport([_valid_hit()]),
            secret_value="tok",
        )


async def test_collection_gate_empty_allowlist_denies() -> None:
    connector = RetrievalConnector()
    with pytest.raises(WhitelistViolation):
        await connector.execute(
            _action(collection_id=_SUBCOLLECTION),
            principal=_principal(),
            policy=_policy(collections=()),
            http_transport=_ok_transport([_valid_hit()]),
            secret_value="tok",
        )


# --------------------------------------------------------------------------- #
# INV-R3 — credential required
# --------------------------------------------------------------------------- #


async def test_missing_credential_denies() -> None:
    connector = RetrievalConnector()
    with pytest.raises(WhitelistViolation):
        await connector.execute(
            _action(),
            principal=_principal(),
            policy=_policy(),
            http_transport=_ok_transport([_valid_hit()]),
            secret_value="",
        )


# --------------------------------------------------------------------------- #
# INV-R4 — transport fail-closed (no mock success)
# --------------------------------------------------------------------------- #


async def test_no_transport_fails_closed() -> None:
    connector = RetrievalConnector()
    with pytest.raises(ConnectorTransportUnavailable):
        await connector.execute(
            _action(),
            principal=_principal(),
            policy=_policy(),
            http_transport=None,
            secret_value="tok",
        )


# --------------------------------------------------------------------------- #
# INV-R5 — grounding enforced (fail-closed on missing/invalid evidence)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("missing_field", ["source_uri", "doc_id", "retrieved_at"])
async def test_missing_required_field_raises_connector_error(missing_field: str) -> None:
    hit = _valid_hit()
    del hit[missing_field]
    connector = RetrievalConnector()
    with pytest.raises(ConnectorError) as excinfo:
        await connector.execute(
            _action(),
            principal=_principal(),
            policy=_policy(),
            http_transport=_ok_transport([hit]),
            secret_value="tok",
        )
    # A grounding failure is a plain ConnectorError, not a policy WhitelistViolation.
    assert type(excinfo.value) is ConnectorError


async def test_blank_source_uri_fails_evidence_validation() -> None:
    connector = RetrievalConnector()
    with pytest.raises(ConnectorError) as excinfo:
        await connector.execute(
            _action(),
            principal=_principal(),
            policy=_policy(),
            http_transport=_ok_transport([_valid_hit(source_uri="   ")]),
            secret_value="tok",
        )
    assert type(excinfo.value) is ConnectorError


async def test_out_of_range_score_fails_evidence_validation() -> None:
    connector = RetrievalConnector()
    with pytest.raises(ConnectorError):
        await connector.execute(
            _action(),
            principal=_principal(),
            policy=_policy(),
            http_transport=_ok_transport([_valid_hit(score=1.5)]),
            secret_value="tok",
        )


async def test_bad_retrieved_at_fails_evidence_validation() -> None:
    connector = RetrievalConnector()
    with pytest.raises(ConnectorError):
        await connector.execute(
            _action(),
            principal=_principal(),
            policy=_policy(),
            http_transport=_ok_transport([_valid_hit(retrieved_at="not-a-timestamp")]),
            secret_value="tok",
        )


async def test_one_bad_hit_rejects_the_whole_batch() -> None:
    # No partial acceptance — a single ungrounded hit fails the entire search.
    good = _valid_hit()
    bad = _valid_hit(doc_id="여신심사_00999")
    del bad["source_uri"]
    connector = RetrievalConnector()
    with pytest.raises(ConnectorError):
        await connector.execute(
            _action(),
            principal=_principal(),
            policy=_policy(),
            http_transport=_ok_transport([good, bad]),
            secret_value="tok",
        )


# --------------------------------------------------------------------------- #
# Zero hits — grounded-but-empty is a valid success
# --------------------------------------------------------------------------- #


async def test_zero_hits_returns_ok_empty_evidence() -> None:
    connector = RetrievalConnector()
    result = await connector.execute(
        _action(),
        principal=_principal(),
        policy=_policy(),
        http_transport=_ok_transport([]),
        secret_value="tok",
    )
    assert result.ok is True
    assert result.payload["evidence"] == []


async def test_missing_hits_key_returns_empty_evidence() -> None:
    async def _no_hits(*, action: ConnectorAction, principal: Principal, secret_value: str) -> dict[str, Any]:
        return {"ok": True}

    connector = RetrievalConnector()
    result = await connector.execute(
        _action(), principal=_principal(), policy=_policy(), http_transport=_no_hits, secret_value="tok"
    )
    assert result.ok is True
    assert result.payload["evidence"] == []


# --------------------------------------------------------------------------- #
# Malformed transport responses fail closed
# --------------------------------------------------------------------------- #


async def test_non_mapping_response_fails_closed() -> None:
    async def _bad(*, action: ConnectorAction, principal: Principal, secret_value: str) -> Any:
        return ["not", "a", "mapping"]

    connector = RetrievalConnector()
    with pytest.raises(ConnectorError):
        await connector.execute(
            _action(), principal=_principal(), policy=_policy(), http_transport=_bad, secret_value="tok"
        )


async def test_hits_not_a_list_fails_closed() -> None:
    async def _bad(*, action: ConnectorAction, principal: Principal, secret_value: str) -> dict[str, Any]:
        return {"ok": True, "hits": "nope"}

    connector = RetrievalConnector()
    with pytest.raises(ConnectorError):
        await connector.execute(
            _action(), principal=_principal(), policy=_policy(), http_transport=_bad, secret_value="tok"
        )


async def test_hit_not_a_mapping_fails_closed() -> None:
    async def _bad(*, action: ConnectorAction, principal: Principal, secret_value: str) -> dict[str, Any]:
        return {"ok": True, "hits": ["not-a-mapping"]}

    connector = RetrievalConnector()
    with pytest.raises(ConnectorError):
        await connector.execute(
            _action(), principal=_principal(), policy=_policy(), http_transport=_bad, secret_value="tok"
        )


# --------------------------------------------------------------------------- #
# Transport exception → sanitized ConnectorError (no credential/vendor leak)
# --------------------------------------------------------------------------- #


async def test_transport_exception_wrapped_without_leaking_secret() -> None:
    # A recognizable placeholder credential (contains "dummy") — must not trip the
    # public-release secret gate (scripts/check_public_release.py) while still
    # exercising that a real credential never leaks into the wrapped error message.
    secret = "dummy-oauth-token-value"

    async def _boom(*, action: ConnectorAction, principal: Principal, secret_value: str) -> dict[str, Any]:
        raise RuntimeError(f"vendor 500: token {secret_value} rejected")

    connector = RetrievalConnector()
    with pytest.raises(ConnectorError) as excinfo:
        await connector.execute(
            _action(), principal=_principal(), policy=_policy(), http_transport=_boom, secret_value=secret
        )
    assert secret not in str(excinfo.value)
    assert type(excinfo.value) is ConnectorError


async def test_transport_connector_error_keeps_concrete_type() -> None:
    # A ConnectorError (here a policy WhitelistViolation) raised by the transport
    # itself must propagate unchanged, not be re-wrapped as a generic ConnectorError.
    async def _deny(*, action: ConnectorAction, principal: Principal, secret_value: str) -> dict[str, Any]:
        raise WhitelistViolation("transport-side policy denial")

    connector = RetrievalConnector()
    with pytest.raises(WhitelistViolation):
        await connector.execute(
            _action(), principal=_principal(), policy=_policy(), http_transport=_deny, secret_value="tok"
        )


# --------------------------------------------------------------------------- #
# Rate limit
# --------------------------------------------------------------------------- #


async def test_rate_limit_exceeded() -> None:
    connector = RetrievalConnector()
    policy = _policy(rate=1)
    transport = _ok_transport([_valid_hit()])
    await connector.execute(
        _action(), principal=_principal(), policy=policy, http_transport=transport, secret_value="tok"
    )
    with pytest.raises(RateLimitExceeded):
        await connector.execute(
            _action(), principal=_principal(), policy=policy, http_transport=transport, secret_value="tok"
        )


# --------------------------------------------------------------------------- #
# INV-R6 — registry roundtrip
# --------------------------------------------------------------------------- #


def test_registry_roundtrip() -> None:
    reg = ConnectorRegistry()
    binding = ConnectorBinding(
        connector=RetrievalConnector(), policy=_policy(), secret_name="retrieval-oauth"
    )
    reg.register(binding)
    assert reg.is_action_known("retrieval.search") is True
    assert reg.is_action_known("retrieval.write") is False
    assert reg.get("retrieval").connector.name == "retrieval"


# --------------------------------------------------------------------------- #
# Property: success ⇔ all three provenance fields present (INV-R5 roundtrip)
# --------------------------------------------------------------------------- #


@given(has_source=st.booleans(), has_doc=st.booleans(), has_time=st.booleans())
@settings(max_examples=100)
def test_required_field_presence_roundtrip(has_source: bool, has_doc: bool, has_time: bool) -> None:
    hit: dict[str, Any] = {"snippet": "발췌"}
    if has_source:
        hit["source_uri"] = _SOURCE_URI
    if has_doc:
        hit["doc_id"] = "여신심사_00123"
    if has_time:
        hit["retrieved_at"] = _RETRIEVED_AT
    connector = RetrievalConnector(http_transport=_ok_transport([hit]))
    call = connector.execute(_action(), principal=_principal(), policy=_policy(), secret_value="tok")
    if has_source and has_doc and has_time:
        result = asyncio.run(call)
        assert result.ok is True
        assert len(result.payload["evidence"]) == 1
    else:
        with pytest.raises(ConnectorError):
            asyncio.run(call)
