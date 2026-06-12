# SPDX-License-Identifier: Apache-2.0
"""Unit tests for AgentConfig tree validation (SG-20260602-05/06)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from secugent.core.agent_config import AgentConfig, AgentNode, default_agent_config


def _head(enabled: bool = True) -> AgentNode:
    return AgentNode(id="head", kind="head", actor="head", name="HEAD", enabled=enabled)


def _sub(enabled: bool = True) -> AgentNode:
    return AgentNode(
        id="sub-a",
        kind="sub",
        actor="sub:a",
        name="A",
        parent_id="head",
        enabled=enabled,
    )


def test_default_config_is_valid() -> None:
    cfg = default_agent_config("legacy-default")
    assert any(n.kind == "head" and n.enabled for n in cfg.nodes)
    assert any(n.kind == "sub" and n.enabled for n in cfg.nodes)


def test_enabled_head_and_sub_accepted() -> None:
    cfg = AgentConfig(tenant_id="acme", nodes=[_head(), _sub()])
    assert len(cfg.nodes) == 2


def test_all_nodes_disabled_rejected() -> None:
    """SG-20260602-06: a config with every node disabled has nothing to route."""
    with pytest.raises(ValidationError, match="enabled HEAD"):
        AgentConfig(tenant_id="acme", nodes=[_head(enabled=False), _sub(enabled=False)])


def test_head_disabled_rejected() -> None:
    with pytest.raises(ValidationError, match="enabled HEAD"):
        AgentConfig(tenant_id="acme", nodes=[_head(enabled=False), _sub(enabled=True)])


def test_all_subs_disabled_rejected() -> None:
    with pytest.raises(ValidationError, match="enabled SUB"):
        AgentConfig(tenant_id="acme", nodes=[_head(enabled=True), _sub(enabled=False)])


def test_no_head_rejected() -> None:
    with pytest.raises(ValidationError, match="at least one HEAD"):
        AgentConfig(tenant_id="acme", nodes=[_sub()])


def test_sub_actor_prefix_enforced() -> None:
    """SG-20260602-05 path: validator still rejects a bad actor prefix."""
    with pytest.raises(ValidationError, match="must start with 'sub:'"):
        AgentNode(id="x", kind="sub", actor="researcher", name="X", parent_id="head")


def test_head_actor_cannot_use_sub_prefix() -> None:
    with pytest.raises(ValidationError, match="cannot start with 'sub:'"):
        AgentNode(id="x", kind="head", actor="sub:nope", name="X")


def test_validation_is_deterministic_100x() -> None:
    """Determinism (§B-4a) — identical input rejected the same way every time."""
    outcomes: set[bool] = set()
    for _ in range(100):
        try:
            AgentConfig(tenant_id="acme", nodes=[_head(enabled=False), _sub(enabled=False)])
            outcomes.add(True)
        except ValidationError:
            outcomes.add(False)
    assert outcomes == {False}
