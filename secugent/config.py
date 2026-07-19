# SPDX-License-Identifier: Apache-2.0
"""Runtime configuration for SecuGent.

Aggregates orchestrator and virtual-desktop settings. v0.1 keeps the schema
in plain dataclasses (no external config loader) — callers either build
:class:`SecuGentConfig` from defaults or override individual fields.

Per the orchestrator/desktop spec, the defaults are:

* ``orchestrator.auto_approve`` = False (fail-closed)
* ``orchestrator.approval_timeout_sec`` = 600
* ``orchestrator.max_concurrent_runs`` = 10
* ``orchestrator.run_state_backend`` = None (unconfigured → dev:memory / prod:sqlite)
* ``orchestrator.run_state_db_path`` = "data/run_state.db" (sqlite backend only)
* ``orchestrator.fail_fast`` = True
* ``virtual_desktop.backend`` = "stub" (CI/dev default)
* ``virtual_desktop.lifecycle`` = "per_run"
* ``virtual_desktop.docker.image`` = "secugent/sandbox:latest"
* ``virtual_desktop.docker.network_mode`` = "none"
* ``virtual_desktop.docker.read_only_root`` = True
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

__all__ = [
    "DockerBackendConfig",
    "HaBackend",
    "MountSpec",
    "OrchestratorConfig",
    "RunStateBackend",
    "SecuGentConfig",
    "VirtualDesktopConfig",
    "VirtualDesktopBackendName",
    "VirtualDesktopLifecycle",
]


RunStateBackend = Literal["memory", "sqlite"]
HaBackend = Literal["memory", "sqlite", "pg"]
VirtualDesktopBackendName = Literal["docker", "windows_sandbox", "stub"]
VirtualDesktopLifecycle = Literal["per_run", "per_sub", "persistent"]

# Deny-by-default truthy tokens for boolean env flags. Only these explicit values
# enable a flag; anything else (unset/blank/"0"/"false"/typo) stays off so a
# misspelled env can never silently activate a multi-node code path.
_TRUTHY_ENV_TOKENS: frozenset[str] = frozenset({"1", "true", "yes"})


def _default_ha_enabled() -> bool:
    """Resolve HA (multi-replica) mode from ``SECUGENT_HA_ENABLED``.

    This is the SINGLE source of truth for ``ha_enabled``. The field
    was previously a bare ``False`` default with no env reader, so create_app's
    ``config or SecuGentConfig()`` boot never activated the single-writer guard
    (``_assert_ha_single_writer_safe``) — a shipped container running HA on per-pod
    SQLite would silently fork the audit chain. Deny-by-default: only the explicit
    truthy tokens (1/true/yes, case-insensitive) enable HA; unset/blank/unknown →
    False so existing single-node installs are byte-for-byte unaffected."""
    raw = os.environ.get("SECUGENT_HA_ENABLED", "").strip().lower()
    return raw in _TRUTHY_ENV_TOKENS


@dataclass
class OrchestratorConfig:
    """Configuration for :class:`secugent.orchestrator.runner.RunOrchestrator`."""

    auto_approve: bool = False
    approval_timeout_sec: int = 600
    max_concurrent_runs: int = 10
    # F8/F13: ``None`` = UNCONFIGURED (the operator did not pick a backend). The
    # boot path upgrades unconfigured to ``"sqlite"`` in prod (durable) and to
    # in-memory in dev. An EXPLICIT ``"memory"`` is honoured verbatim — so in prod
    # it fails fast (RunStateConfigError) rather than being silently upgraded. The
    # previous default was a bare ``"memory"``, which was indistinguishable from an
    # explicit choice and so silently swallowed the prod fail-fast path.
    run_state_backend: RunStateBackend | None = None
    # Filesystem path for the ``"sqlite"`` run-state backend. Ignored by the
    # ``"memory"`` backend. ``":memory:"`` selects an ephemeral in-process
    # SQLite DB. Resolved into a store by
    # :func:`secugent.orchestrator.wiring.resolve_run_state_store`.
    run_state_db_path: str = "data/run_state.db"
    fail_fast: bool = True
    # HA single-leader lease. OFF by default = single-node, so existing boots
    # are unchanged. ``resolve_lease_manager`` returns ``None`` while
    # ``ha_enabled`` is falsy; when enabled it selects a lease backend by
    # ``ha_backend`` (falling back to ``run_state_backend``). In-memory HA is
    # dev-only (it cannot guarantee a single leader across nodes); ``"pg"``
    # requires a PG event store exposing the lease primitives.
    #
    # read from ``SECUGENT_HA_ENABLED`` at construction (via
    # :func:`_default_ha_enabled`) so create_app's ``config or SecuGentConfig()``
    # default reflects the operator's HA choice and the single-writer boot guard
    # becomes reachable. An explicit ``OrchestratorConfig(ha_enabled=…)`` still
    # overrides the env (callers/tests keep full control).
    ha_enabled: bool = field(default_factory=_default_ha_enabled)
    ha_backend: HaBackend = "memory"


@dataclass
class MountSpec:
    """Declarative bind-mount for the Docker backend.

    ``mode`` is ``"ro"`` (default) or ``"rw"``. Read-write mounts are only
    accepted if ``host`` is within one of the configured ``sandbox_roots``
    (validated in :mod:`secugent.desktop.security`).
    """

    host: str
    guest: str
    mode: Literal["ro", "rw"] = "ro"


@dataclass
class DockerBackendConfig:
    """Docker-specific virtual-desktop settings."""

    image: str = "secugent/sandbox:latest"
    network_mode: str = "none"
    memory_limit: str = "1g"
    cpu_limit: float = 1.0
    mount_paths: list[MountSpec] = field(default_factory=list)
    read_only_root: bool = True
    # The sandbox_roots cross-check — orchestrator
    # populates this from the workspace's sandbox configuration. Empty means
    # "no rw mounts allowed".
    sandbox_roots: list[str] = field(default_factory=list)
    # Extra capabilities or security opts MUST stay empty; populated configs
    # are rejected by validate_security().
    cap_add: list[str] = field(default_factory=list)
    extra_security_opts: list[str] = field(default_factory=list)


@dataclass
class VirtualDesktopConfig:
    backend: VirtualDesktopBackendName = "stub"
    lifecycle: VirtualDesktopLifecycle = "per_run"
    docker: DockerBackendConfig = field(default_factory=DockerBackendConfig)


def _default_platform_tenant() -> str:
    """Resolve the PLATFORM-admin tenant id from ``SECUGENT_PLATFORM_TENANT``.

    Tenant-lifecycle operations (create/soft-delete/assign-regulations/set-budget)
    are reserved for an admin whose own tenant equals this id — a normal tenant's
    admin must NOT be able to manage other tenants (cross-tenant privilege
    escalation, F2). Defaults to ``"platform"`` when the env var is unset/blank."""
    raw = os.environ.get("SECUGENT_PLATFORM_TENANT", "").strip()
    return raw or "platform"


@dataclass
class SecuGentConfig:
    """Top-level runtime configuration."""

    orchestrator: OrchestratorConfig = field(default_factory=OrchestratorConfig)
    virtual_desktop: VirtualDesktopConfig = field(default_factory=VirtualDesktopConfig)
    # F2: the single tenant whose admins may perform platform-level tenant
    # lifecycle operations. Read once from ``SECUGENT_PLATFORM_TENANT`` (fallback
    # "platform"); a deployment can override per-config without touching code.
    platform_tenant_id: str = field(default_factory=_default_platform_tenant)
