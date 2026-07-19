# SPDX-License-Identifier: Apache-2.0
"""Request-path tenant binding (tenant_context).

The wired dependency must be an **async** generator so FastAPI runs it in the
request's own context and the ContextVar set is visible to the async endpoint.
A sync generator dependency would be run in a worker thread, so the binding
could be invisible to the async handler (classic ContextVar footgun) and two
concurrent requests could leak each other's tenant.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

from secugent.core.tenancy import Principal, TenantId, current_tenant
from secugent.core.tenant_context import (
    bind_tenant_from_principal,
    wire_bind_tenant_dependency,
)


def _principal(tenant: str, *, role: str = "operator") -> Principal:
    return Principal(user_id=f"u:{tenant}", tenant_id=TenantId(tenant), role=role)  # type: ignore[arg-type]


def test_wired_dependency_is_async_generator() -> None:
    """FastAPI must run it in the request's own context — that requires an
    async generator function, not a sync one (sync runs in a worker thread)."""
    dependency = wire_bind_tenant_dependency()
    assert inspect.isasyncgenfunction(dependency), (
        "wired dependency must be an async generator so the ContextVar binding is visible to async endpoints"
    )


async def _drive(principal: Principal) -> TenantId:
    """Run the async-generator dependency manually (mirrors FastAPI's lifecycle)
    and read ``current_tenant()`` from *inside* the bound window."""
    dependency = wire_bind_tenant_dependency()
    agen = dependency(principal)
    bound = await agen.__anext__()  # enter: runs up to `yield`
    try:
        # Inside the dependency window the ContextVar must reflect the principal.
        assert current_tenant() == principal.tenant_id
        return bound
    finally:
        # Teardown: exhaust the generator so the context manager exits.
        with pytest.raises(StopAsyncIteration):
            await agen.__anext__()


async def test_dependency_binds_current_tenant() -> None:
    principal = _principal("acme-bank")
    bound = await _drive(principal)
    assert bound == TenantId("acme-bank")
    # Outside the window the binding is gone (fail-closed — LookupError again).
    with pytest.raises(LookupError):
        current_tenant()


async def test_concurrent_tasks_do_not_leak_tenant() -> None:
    """Two concurrent async tasks with different tenants must each observe ONLY
    their own binding — no cross-task leakage through the ContextVar."""

    async def observe(tenant: str) -> str:
        dependency = wire_bind_tenant_dependency()
        agen = dependency(_principal(tenant))
        await agen.__anext__()
        try:
            # Yield control so the tasks interleave; the binding must survive.
            await asyncio.sleep(0)
            seen = str(current_tenant())
            await asyncio.sleep(0)
            assert str(current_tenant()) == tenant  # still ours after interleave
            return seen
        finally:
            with pytest.raises(StopAsyncIteration):
                await agen.__anext__()

    results = await asyncio.gather(
        observe("tenant-alpha"),
        observe("tenant-beta"),
        observe("tenant-gamma"),
    )
    assert results == ["tenant-alpha", "tenant-beta", "tenant-gamma"]


async def test_bind_tenant_from_principal_context_manager_unchanged() -> None:
    """The underlying context manager keeps its synchronous-CM contract."""
    principal = _principal("kb-fin")
    with bind_tenant_from_principal(principal) as tenant_id:
        assert tenant_id == TenantId("kb-fin")
        assert current_tenant() == TenantId("kb-fin")
    with pytest.raises(LookupError):
        current_tenant()
