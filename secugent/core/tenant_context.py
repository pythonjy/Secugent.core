# SPDX-License-Identifier: Apache-2.0
"""Request-path tenant binding.

A single, reusable place to bind ``current_tenant`` from the authenticated
:class:`~secugent.core.tenancy.Principal`. Every request handler / pipeline
task must run *inside* this binding so that downstream tenant checks
(oversight, approval, query, RLS) compare against the principal's tenant
rather than trusting a transport header.

The actual mounting into the FastAPI request lifecycle is the integration
lane's job; this module only exposes the reusable factory + context manager
for it to mount. Keeping the binding logic here (not in ``main.py``) means a
single audited code path performs the bind, so a route can never accidentally
skip it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import contextmanager

from secugent.core.tenancy import Principal, TenantId, set_current_tenant

__all__ = [
    "bind_tenant_from_principal",
    "wire_bind_tenant_dependency",
]


@contextmanager
def bind_tenant_from_principal(principal: Principal) -> Iterator[TenantId]:
    """Bind ``principal.tenant_id`` to ``current_tenant`` for the block.

    Use as ``with bind_tenant_from_principal(principal): ...``. On exit the
    previous binding (or "unset") is restored, so ``current_tenant()`` raises
    :class:`LookupError` again outside the block (fail-closed — a missing
    binding is never silently treated as a default tenant).
    """
    with set_current_tenant(principal.tenant_id) as tenant_id:
        yield tenant_id


def wire_bind_tenant_dependency() -> Callable[[Principal], AsyncIterator[TenantId]]:
    """Return an **async** generator dependency the integration lane mounts on routes.

    FastAPI runs a generator dependency as a context manager: the code up to
    ``yield`` executes before the handler, and the code after ``yield`` runs on
    teardown. Mounting this as ``Depends(...)`` therefore binds the tenant for
    the whole request and unbinds it afterwards, mirroring
    :func:`bind_tenant_from_principal`.

    It MUST be an ``async`` generator: FastAPI runs *sync* generator dependencies
    in a worker thread, so a ContextVar set there would not be visible to the
    async endpoint (and could leak across concurrent requests). An async
    generator runs in the request's own context, so the binding is both visible
    to the handler and isolated per request (each async task gets its own
    ContextVar copy). The wrapped synchronous context manager
    :func:`bind_tenant_from_principal` is reused unchanged.

    F11: today every request-path tenant check reads the tenant from the verified
    ``principal`` *explicitly*, so this ContextVar binding is belt-and-suspenders;
    it is retained for the FUTURE RLS consumer (``current_tenant()`` will scope
    Postgres row-level-security), and its per-task isolation is pinned by
    ``tests/core/test_tenant_context_isolation.py``.
    """

    async def _dependency(principal: Principal) -> AsyncIterator[TenantId]:
        with bind_tenant_from_principal(principal) as tenant_id:
            yield tenant_id

    return _dependency
