# SPDX-License-Identifier: Apache-2.0
"""EM-05 — RouterTransport delegates to ToolRouter; rejects non-router kinds."""

from __future__ import annotations

from pathlib import Path

import pytest

from secugent.core.sec.effects import Effect, EffectKind, SinkClass
from secugent.core.sec.labels import DataLabel
from secugent.core.tenancy import Principal, TenantId
from secugent.io.broker import ExecutionProfile, RouterTransport
from secugent.io.broker.request import EgressRequest
from secugent.tools.router import ToolDispatchError, ToolRouter, ToolRouterConfig

_PRINCIPAL = Principal(user_id="alice", tenant_id=TenantId("acme"), role="operator")


def _req(effect: Effect, content: bytes | None = None) -> EgressRequest:
    return EgressRequest(
        effect=effect,
        label=DataLabel.PUBLIC,
        principal=_PRINCIPAL,
        run_id="r1",
        profile=ExecutionProfile.EXTERNAL_BROKERED,
        content=content,
    )


def test_router_transport_writes_file(tmp_path: Path) -> None:
    sandbox = tmp_path / "box"
    sandbox.mkdir()
    router = ToolRouter(ToolRouterConfig(sandbox_roots=[str(sandbox)]))
    transport = RouterTransport(router)
    target = sandbox / "out.txt"
    # canonical lower-case forward-slash target (what the bridge would produce)
    eff = Effect(
        kind=EffectKind.FILE_WRITE,
        target=str(target).replace("\\", "/").lower(),
        sink_class=SinkClass.LOCAL_SANDBOX,
    )
    payload = transport.execute(_req(eff, content=b"hi"))
    assert target.read_text(encoding="utf-8") == "hi"
    assert payload is not None  # serialized ToolResult payload


def test_router_transport_rejects_net_send() -> None:
    router = ToolRouter(ToolRouterConfig())
    transport = RouterTransport(router)
    eff = Effect(kind=EffectKind.NET_SEND, target="https://x.example/a", sink_class=SinkClass.EXTERNAL)
    with pytest.raises(ToolDispatchError):
        transport.execute(_req(eff))  # connector/network transport is EM-06
