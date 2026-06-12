# SPDX-License-Identifier: Apache-2.0
"""ConnectorRegistry tenant-policy binding — deterministic (§B-4a).

Triple harness: unit (all branches) + property-based (hypothesis) + scenario
regression, plus a 100x determinism proof. Korean enterprise fixture (§C-3):
사내 그룹웨어 'kakaowork' + 채널 '사내-공지'.

Covers ``ConnectorRegistry.apply_tenant_policy`` / ``get_policy_for``:
* tenant isolation (A's override invisible to B),
* unregistered connector → warn + skip (no raise),
* tenant override precedence over the binding default,
* determinism over repeated apply.
"""

from __future__ import annotations

import logging
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.core.regulations import Regulations
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker.connector_transport import ConnectorBinding
from secugent.tools.connectors.base import (
    ConnectorAction,
    ConnectorPolicy,
    ConnectorResult,
)
from secugent.tools.connectors.registry import ConnectorRegistry

# --------------------------------------------------------------------------- #
# helpers / fixtures
# --------------------------------------------------------------------------- #


class _FakeConnector:
    def __init__(self, name: str, actions: tuple[str, ...]) -> None:
        self.name = name
        self.actions = actions

    async def validate_action(self, action: ConnectorAction, policy: ConnectorPolicy) -> None:
        return None

    async def execute(
        self,
        action: ConnectorAction,
        *,
        principal: Principal,
        policy: ConnectorPolicy,
        http_transport: Any | None = None,
        secret_value: str = "",
    ) -> ConnectorResult:
        return ConnectorResult(ok=True, payload={})


def _binding(name: str, *, channels: list[str] | None = None) -> ConnectorBinding:
    return ConnectorBinding(
        connector=_FakeConnector(name, ("post_message",)),
        policy=ConnectorPolicy(allowed_channels=channels if channels is not None else ["default"]),
        secret_name=f"{name}-tok",
    )


def _regs(connector_policies: dict[str, ConnectorPolicy], version: str = "v1") -> Regulations:
    return Regulations(version=version, connector_policies=connector_policies)


TENANT_A = TenantId("acme")
TENANT_B = TenantId("globex")


# --------------------------------------------------------------------------- #
# unit — apply / get
# --------------------------------------------------------------------------- #


def test_get_policy_for_returns_binding_default_when_no_override() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("kakaowork", channels=["사내-공지"]))
    policy = reg.get_policy_for("kakaowork")
    assert policy is not None
    assert policy.allowed_channels == ["사내-공지"]


def test_get_policy_for_unknown_connector_returns_none() -> None:
    reg = ConnectorRegistry()
    assert reg.get_policy_for("ghost") is None


def test_apply_tenant_policy_overrides_default_for_that_tenant() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("kakaowork", channels=["default"]))
    reg.apply_tenant_policy(
        TENANT_A, _regs({"kakaowork": ConnectorPolicy(allowed_channels=["사내-공지", "보안팀"])})
    )
    overridden = reg.get_policy_for("kakaowork", tenant_id=TENANT_A)
    assert overridden is not None
    assert overridden.allowed_channels == ["사내-공지", "보안팀"]


def test_tenant_isolation_a_policy_invisible_to_b() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("kakaowork", channels=["default"]))
    reg.apply_tenant_policy(TENANT_A, _regs({"kakaowork": ConnectorPolicy(allowed_channels=["A-only"])}))
    # B has no override → falls back to the binding default.
    b_policy = reg.get_policy_for("kakaowork", tenant_id=TENANT_B)
    assert b_policy is not None
    assert b_policy.allowed_channels == ["default"]


def test_get_policy_for_tenant_none_ignores_tenant_overrides() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("kakaowork", channels=["default"]))
    reg.apply_tenant_policy(TENANT_A, _regs({"kakaowork": ConnectorPolicy(allowed_channels=["A-only"])}))
    # tenant_id=None → binding default only, never a tenant override.
    assert reg.get_policy_for("kakaowork", tenant_id=None) == reg.get_policy_for("kakaowork")
    assert reg.get_policy_for("kakaowork", tenant_id=None).allowed_channels == ["default"]  # type: ignore[union-attr]


def test_apply_unregistered_connector_warns_and_skips(caplog: Any) -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("kakaowork", channels=["default"]))
    with caplog.at_level(logging.WARNING):
        reg.apply_tenant_policy(
            TENANT_A,
            _regs(
                {
                    "kakaowork": ConnectorPolicy(allowed_channels=["사내-공지"]),
                    "ghost": ConnectorPolicy(allowed_channels=["x"]),  # not registered
                }
            ),
        )
    # registered one applied, ghost skipped (no raise), warning logged.
    assert reg.get_policy_for("kakaowork", tenant_id=TENANT_A).allowed_channels == ["사내-공지"]  # type: ignore[union-attr]
    assert reg.get_policy_for("ghost", tenant_id=TENANT_A) is None
    assert any("ghost" in rec.getMessage() for rec in caplog.records)


def test_apply_empty_connector_policies_is_noop() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("kakaowork", channels=["default"]))
    reg.apply_tenant_policy(TENANT_A, _regs({}))
    assert reg.get_policy_for("kakaowork", tenant_id=TENANT_A).allowed_channels == ["default"]  # type: ignore[union-attr]


def test_reapply_replaces_tenant_policy() -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("kakaowork", channels=["default"]))
    reg.apply_tenant_policy(TENANT_A, _regs({"kakaowork": ConnectorPolicy(allowed_channels=["first"])}))
    reg.apply_tenant_policy(TENANT_A, _regs({"kakaowork": ConnectorPolicy(allowed_channels=["second"])}))
    assert reg.get_policy_for("kakaowork", tenant_id=TENANT_A).allowed_channels == ["second"]  # type: ignore[union-attr]


# --------------------------------------------------------------------------- #
# determinism — 100 runs
# --------------------------------------------------------------------------- #


def test_apply_get_determinism_100_runs() -> None:
    expected: list[str] | None = None
    for _ in range(100):
        reg = ConnectorRegistry()
        reg.register(_binding("kakaowork", channels=["default"]))
        reg.apply_tenant_policy(
            TENANT_A, _regs({"kakaowork": ConnectorPolicy(allowed_channels=["사내-공지", "보안팀"])})
        )
        policy = reg.get_policy_for("kakaowork", tenant_id=TENANT_A)
        assert policy is not None
        if expected is None:
            expected = policy.allowed_channels
        assert policy.allowed_channels == expected


# --------------------------------------------------------------------------- #
# property-based — isolation invariant
# --------------------------------------------------------------------------- #


@given(
    chans_a=st.lists(st.text(min_size=1, max_size=8), max_size=5),
    chans_b=st.lists(st.text(min_size=1, max_size=8), max_size=5),
)
@settings(max_examples=200)
def test_property_tenant_isolation(chans_a: list[str], chans_b: list[str]) -> None:
    reg = ConnectorRegistry()
    reg.register(_binding("c", channels=["base"]))
    reg.apply_tenant_policy(TENANT_A, _regs({"c": ConnectorPolicy(allowed_channels=chans_a)}))
    reg.apply_tenant_policy(TENANT_B, _regs({"c": ConnectorPolicy(allowed_channels=chans_b)}))
    pa = reg.get_policy_for("c", tenant_id=TENANT_A)
    pb = reg.get_policy_for("c", tenant_id=TENANT_B)
    assert pa is not None and pb is not None
    assert pa.allowed_channels == chans_a
    assert pb.allowed_channels == chans_b
