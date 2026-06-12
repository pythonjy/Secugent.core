# SPDX-License-Identifier: Apache-2.0
"""F11 — per-request tenant ContextVar binding is visible + concurrency-isolated.

The async-generator dependency from ``wire_bind_tenant_dependency`` binds
``current_tenant()`` to the verified principal's tenant for the request and
unbinds on teardown. These tests pin two properties the binding's isolation
claim rests on (it is belt-and-suspenders today, load-bearing for the future
RLS ``current_tenant()`` consumer):

1. inside the dependency's scope, ``current_tenant()`` == ``principal.tenant_id``;
2. two concurrent async tasks bound to DIFFERENT tenants never observe each
   other's binding (each asyncio task gets its own ContextVar copy).
"""

from __future__ import annotations

import asyncio

import pytest

from secugent.core.tenancy import Principal, TenantId, current_tenant
from secugent.core.tenant_context import wire_bind_tenant_dependency


def _principal(tenant: str) -> Principal:
    return Principal(user_id=f"u-{tenant}", tenant_id=TenantId(tenant), role="operator")


async def _run_under_binding(tenant: str) -> TenantId:
    """Drive the async-generator dependency the way FastAPI would, then read the
    bound tenant from inside its scope."""
    dependency = wire_bind_tenant_dependency()
    gen = dependency(_principal(tenant))
    bound = await gen.__anext__()
    try:
        # The binding is visible to code running inside the dependency's scope.
        assert current_tenant() == TenantId(tenant)
        return bound
    finally:
        with pytest.raises(StopAsyncIteration):
            await gen.__anext__()  # teardown unbinds


async def test_binding_visible_inside_scope() -> None:
    bound = await _run_under_binding("acme")
    assert bound == TenantId("acme")
    # Outside any binding the ContextVar is unset (fail-closed).
    with pytest.raises(LookupError):
        current_tenant()


async def test_concurrent_tasks_do_not_observe_each_others_tenant() -> None:
    # Each task binds a different tenant and yields control repeatedly; if the
    # ContextVar leaked across tasks, one would observe the other's tenant.
    observed: dict[str, list[str]] = {"acme": [], "contoso": []}

    async def worker(tenant: str) -> None:
        dependency = wire_bind_tenant_dependency()
        gen = dependency(_principal(tenant))
        await gen.__anext__()
        try:
            for _ in range(20):
                await asyncio.sleep(0)  # interleave with the other task
                observed[tenant].append(str(current_tenant()))
        finally:
            with pytest.raises(StopAsyncIteration):
                await gen.__anext__()

    await asyncio.gather(worker("acme"), worker("contoso"))

    # Each task only ever saw its OWN tenant — no cross-task bleed.
    assert set(observed["acme"]) == {"acme"}
    assert set(observed["contoso"]) == {"contoso"}


async def test_nested_bindings_restore_outer_tenant() -> None:
    # A nested binding restores the outer tenant on exit (no leak within a task).
    from secugent.core.tenant_context import bind_tenant_from_principal

    with bind_tenant_from_principal(_principal("acme")):
        assert current_tenant() == TenantId("acme")
        with bind_tenant_from_principal(_principal("contoso")):
            assert current_tenant() == TenantId("contoso")
        assert current_tenant() == TenantId("acme")
    with pytest.raises(LookupError):
        current_tenant()
