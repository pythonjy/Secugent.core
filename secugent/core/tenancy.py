# SPDX-License-Identifier: Apache-2.0
"""Tenancy primitives (PHASE 9).

Three pieces:

* :class:`TenantId` — narrow string subtype enforcing the canonical tenant
  identifier shape (``^[a-z0-9][a-z0-9-]{1,62}$``). Constructed everywhere
  domain objects are built; misformed inputs raise immediately.
* :class:`Principal` — the authenticated caller. Carries ``tenant_id`` so
  every downstream check (oversight, approval, query) can compare against
  it without trusting transport headers.
* :func:`current_tenant` / :func:`set_current_tenant` — a
  :class:`contextvars.ContextVar` so async tasks each see their own tenant
  binding (FastAPI request handler scope, orchestrator pipeline task scope,
  etc.).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Literal

from pydantic import BaseModel, ConfigDict, GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

__all__ = [
    "Principal",
    "Role",
    "TenantId",
    "current_tenant",
    "set_current_tenant",
]

_logger = logging.getLogger(__name__)


Role = Literal["admin", "operator", "viewer"]


# ---------------------------------------------------------------------------
# TenantId
# ---------------------------------------------------------------------------


_TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


class TenantId(str):
    """Strict, lower-case tenant identifier.

    Format: ``^[a-z0-9][a-z0-9-]{1,62}$`` — 2 to 63 chars, must start with a
    lower-case alphanumeric, may contain hyphens. Raises :class:`ValueError`
    on any other input.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> TenantId:
        if not isinstance(value, str):
            raise ValueError(f"tenant_id must be str, got {type(value).__name__}")
        if not _TENANT_ID_RE.fullmatch(value):
            raise ValueError(f"tenant_id {value!r} violates ^[a-z0-9][a-z0-9-]{{1,62}}$")
        return super().__new__(cls, value)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"TenantId({str(self)!r})"


# Pydantic v2 cooperation: register a JSON schema + validator so models that
# declare ``tenant_id: TenantId`` validate inputs through the regex.
def _tenant_id_validate(value: object) -> TenantId:
    if isinstance(value, TenantId):
        return value
    if isinstance(value, str):
        return TenantId(value)
    raise ValueError(f"tenant_id must be str, got {type(value).__name__}")


# Pydantic core schema hook — must accept (cls, source_type, handler) when
# bound as a classmethod. We use the after-validator pattern so any string
# input from JSON or kwargs flows through ``_tenant_id_validate`` before
# being stored as a :class:`TenantId`.
def _tenant_id_core_schema(cls: type, source_type: type, handler: GetCoreSchemaHandler) -> CoreSchema:
    return core_schema.no_info_after_validator_function(
        _tenant_id_validate,
        core_schema.str_schema(),
    )


TenantId.__get_pydantic_core_schema__ = classmethod(_tenant_id_core_schema)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------


class Principal(BaseModel):
    """Authenticated caller (post-OIDC verification or dev-auth)."""

    model_config = ConfigDict(extra="forbid")

    user_id: str
    tenant_id: TenantId
    role: Role
    groups: list[str] = []
    mfa_satisfied: bool = False


# ---------------------------------------------------------------------------
# ContextVar
# ---------------------------------------------------------------------------


_CURRENT_TENANT: ContextVar[TenantId] = ContextVar("secugent.current_tenant")


def current_tenant() -> TenantId:
    """Return the tenant bound to the current async context.

    Raises :class:`LookupError` if no tenant is bound — callers either
    explicitly :func:`set_current_tenant` or accept the failure as evidence
    of a missing principal (fail-closed).
    """
    return _CURRENT_TENANT.get()


@contextmanager
def set_current_tenant(tenant_id: TenantId) -> Iterator[TenantId]:
    """Bind ``tenant_id`` to the current async context for the block.

    Use as ``with set_current_tenant(tid): ...``. After exit the previous
    binding (or "unset") is restored. The :class:`Token` returned by
    :meth:`ContextVar.set` is private to this helper.
    """
    if not isinstance(tenant_id, TenantId):
        tenant_id = TenantId(tenant_id)
    token: Token[TenantId] = _CURRENT_TENANT.set(tenant_id)
    try:
        yield tenant_id
    finally:
        try:
            _CURRENT_TENANT.reset(token)
        except ValueError as exc:
            # Cross-Context teardown (SSE/StreamingResponse): reset() was called
            # from a different asyncio Context than the one that called set().
            # Per-task ContextVar isolation is preserved — each Context carries its
            # own copy of the var — so absorbing this error is safe.  Log a warning
            # so the anomaly is visible in audit logs without crashing the handler.
            _logger.warning("tenant ctx reset skipped (cross-context teardown): %s", exc)
