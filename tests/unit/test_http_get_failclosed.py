# SPDX-License-Identifier: Apache-2.0
"""B6 — ``http_get`` fail-closed when no allowlist is supplied.

Legacy fail-OPEN: ``http_get(allowed_domains=None)`` skipped the allowlist and
fetched any host. That path is only reachable with the egress broker DISABLED
(``SECUGENT_EGRESS_BROKER=0``; the broker is default-on and mediates every
effect), but deny-by-default (§A-2.2) means an *absent* allowlist must DENY, not
allow-all. ``ToolRouter`` passes ``_or_none([])`` → ``None`` for an empty config,
so this also closes the router's empty-config hole.
"""

from __future__ import annotations

from typing import Any

import pytest

from secugent.tools.builtin import BuiltinToolError, http_get


class _RecordingTransport:
    """A connection factory that records whether it was ever invoked."""

    def __init__(self) -> None:
        self.opened = False

    def __call__(self, host: str, port: int, *, timeout: float) -> Any:
        self.opened = True
        raise AssertionError("transport must NOT be opened when the host is denied")


def test_http_get_none_allowlist_denies_before_connecting() -> None:
    transport = _RecordingTransport()
    with pytest.raises(BuiltinToolError, match="no allowed-domains allowlist|fail-closed"):
        http_get("http://example.com/x", allowed_domains=None, transport=transport)
    assert transport.opened is False


def test_http_get_empty_allowlist_denies() -> None:
    # An explicit empty list already denied (no host matches); keep that contract.
    transport = _RecordingTransport()
    with pytest.raises(BuiltinToolError):
        http_get("http://example.com/x", allowed_domains=[], transport=transport)
    assert transport.opened is False


def test_router_empty_allowed_domains_denies_http_get() -> None:
    # ToolRouter with no configured domains must NOT silently allow-all.
    from secugent.core.contracts import Step
    from secugent.core.tenancy import TenantId
    from secugent.tools.router import ToolRouter, ToolRouterConfig

    router = ToolRouter(ToolRouterConfig(allowed_domains=[]))
    step = Step(
        tenant_id=TenantId("financial-kr"),
        run_id="r-1",
        actor="sub:web",
        action_type="http_get",
        target="https://api.vendor.example/x",
    )
    with pytest.raises(BuiltinToolError):
        router.dispatch(step)
