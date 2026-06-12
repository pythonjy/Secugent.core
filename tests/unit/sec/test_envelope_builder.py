# SPDX-License-Identifier: Apache-2.0
"""EM-07 — minimal envelope derivation from a plan (deny-by-default proposal)."""

from __future__ import annotations

from secugent.core.contracts import Plan, Step
from secugent.core.sec.effects import SinkClass
from secugent.core.sec.envelope_builder import build_minimal_envelope
from secugent.core.tenancy import TenantId


def _plan(*action_types: str) -> Plan:
    steps = [
        Step(
            tenant_id=TenantId("acme"),
            run_id="r1",
            actor="sub:x",
            action_type=a,  # type: ignore[arg-type]
            target="c:/x",
        )
        for a in action_types
    ]
    return Plan(tenant_id=TenantId("acme"), run_id="r1", goal="g", steps=steps)


def test_empty_plan_authorizes_nothing() -> None:
    env = build_minimal_envelope(_plan())
    assert env.allowed_sinks == frozenset()
    assert env.allowed_actions == frozenset()
    assert env.max_irreversible == 0  # deny-by-default


def test_file_and_http_plan_derives_sinks_and_actions() -> None:
    env = build_minimal_envelope(_plan("file_write", "http_get"))
    assert SinkClass.LOCAL_SANDBOX in env.allowed_sinks
    assert SinkClass.EXTERNAL in env.allowed_sinks
    assert "file_write" in env.allowed_actions
    assert "net_recv" in env.allowed_actions  # http_get maps to NET_RECV
    assert env.max_irreversible == 0


def test_unmapped_action_not_authorized() -> None:
    env = build_minimal_envelope(_plan("unknown"))
    assert env.allowed_actions == frozenset()
    assert env.allowed_sinks == frozenset()


def test_builder_is_deterministic() -> None:
    plan = _plan("file_read", "file_write", "compute")
    envs = {build_minimal_envelope(plan).model_dump_json() for _ in range(50)}
    assert len(envs) == 1
