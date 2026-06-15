# SPDX-License-Identifier: Apache-2.0
"""Tool / desktop execution router (Flowchart §11).

Decision order:

1. Built-in tools (file_read / file_write / http_get) — preferred.
2. Virtual desktop — the injected :class:`VirtualDesktopBackend` (defaults to
   :class:`StubBackend` for tests / dev).
3. Real desktop — DISABLED by default. The router refuses to dispatch real
   desktop actions unless explicitly opted in. v0.1 ships with no real
   desktop driver, so this path raises :class:`RealDesktopDisabledError`.

The router does NOT re-run regulations checks — Mechanical Oversight has
already authorised the action by the time we get here. The router DOES
enforce deny-by-default for unknown action types.

PHASE-Orchestrator note: ``virtual_desktop`` constructor kwarg is retained as
a deprecated alias of ``desktop_backend`` so that callers like
``test_sub_agent.py`` that import :data:`VirtualDesktopStub` keep working.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from secugent.core.contracts import ActionType, Step
from secugent.tools import builtin

if TYPE_CHECKING:  # pragma: no cover - typing-only import, no runtime dependency
    # ``secugent.desktop`` is a deferred (non-Core) tier and is NOT shipped in
    # the public OSS Core wheel. Importing it at module load would (a) break
    # standalone ``pip install`` (ModuleNotFoundError: secugent.desktop) and
    # (b) leak the desktop tier into Apache-2.0 Core (open-core boundary I2/I8).
    # The annotation-only reference here is erased at runtime; the runtime
    # backend is resolved lazily via :func:`_load_desktop_backend_types` only
    # when a caller actually needs a desktop/compute sandbox.
    from secugent.desktop.base import VirtualDesktopBackend

__all__ = [
    "ToolRouter",
    "ToolRouterConfig",
    "ToolDispatchError",
    "UnknownActionError",
    "RealDesktopDisabledError",
    "DesktopBackendUnavailableError",
    # Resolved lazily via module __getattr__ (PEP 562) so the optional desktop
    # tier is not imported at load; F822 (name not defined at module level) is
    # the intended shape here, not a bug.
    "VirtualDesktopStub",  # noqa: F822 - lazy attr via __getattr__
]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ToolDispatchError(RuntimeError):
    """Generic dispatch failure."""


class UnknownActionError(ToolDispatchError):
    """The action_type does not map to any known tool — deny-by-default."""


class RealDesktopDisabledError(ToolDispatchError):
    """Real desktop automation is disabled in v0.1 by default."""


class DesktopBackendUnavailableError(ToolDispatchError):
    """A desktop/compute step was dispatched but no backend is available.

    Raised when the caller injected no backend AND the optional
    ``secugent.desktop`` tier is not installed (the public Core wheel ships
    without it). Built-in tool paths (file_read/file_write/http_get) and the
    connector path never reach this — Core stays fully usable without desktop.
    """


# ---------------------------------------------------------------------------
# Optional desktop tier — lazy loader
# ---------------------------------------------------------------------------


def _load_desktop_backend_types() -> tuple[type, type]:
    """Import ``(VirtualDesktopBackend, StubBackend)`` from the optional desktop
    tier on demand.

    Kept out of module import so Core does not hard-depend on ``secugent.desktop``
    (open-core boundary I2/I8). Raises a clear, actionable
    :class:`DesktopBackendUnavailableError` when the tier is absent rather than a
    bare ``ModuleNotFoundError`` (fail-closed with a useful message).
    """
    try:
        from secugent.desktop.base import VirtualDesktopBackend
        from secugent.desktop.stub_backend import StubBackend
    except ModuleNotFoundError as exc:  # desktop tier not installed (public Core).
        raise DesktopBackendUnavailableError(
            "desktop/compute steps require the optional 'secugent.desktop' tier, "
            "which is not installed; inject a desktop_backend or install the "
            "desktop extra. Built-in file/http/connector tools work without it."
        ) from exc
    return VirtualDesktopBackend, StubBackend


def __getattr__(name: str) -> Any:
    """Module-level lazy attribute access (PEP 562).

    Resolves the historical ``VirtualDesktopStub`` alias (== ``StubBackend``)
    without importing the optional desktop tier at module load. Imports that
    reference it (``from secugent.tools.router import VirtualDesktopStub``) keep
    working when desktop is installed, and raise an actionable error otherwise.
    """
    if name == "VirtualDesktopStub":
        _, stub_backend = _load_desktop_backend_types()
        return stub_backend
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class ToolRouterConfig:
    """Runtime configuration for the router.

    ``sandbox_roots`` is the list of directory prefixes file_write may target.
    ``allowed_domains`` is the list http_get may reach.
    ``enable_real_desktop`` MUST be False in v0.1 unless explicitly opted in
    by an operator (and even then is stubbed).
    """

    sandbox_roots: list[str] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    allow_subdomains: bool = True
    enable_real_desktop: bool = False
    real_desktop_driver: Callable[[Step], builtin.ToolResult] | None = None


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


class ToolRouter:
    """Dispatches a :class:`Step` to the correct execution path."""

    def __init__(
        self,
        config: ToolRouterConfig | None = None,
        *,
        desktop_backend: VirtualDesktopBackend | None = None,
        virtual_desktop: VirtualDesktopBackend | None = None,  # deprecated alias
        builtin_overrides: Mapping[ActionType, Callable[..., builtin.ToolResult]] | None = None,
    ) -> None:
        self._config = config or ToolRouterConfig()
        injected = desktop_backend or virtual_desktop
        if injected is not None:
            # Validate the injected backend against the ABC (lazy import: only
            # callers that actually use the desktop tier pay for importing it).
            backend_abc, _ = _load_desktop_backend_types()
            if not isinstance(injected, backend_abc):
                raise TypeError(
                    f"desktop_backend must be a VirtualDesktopBackend (got {type(injected).__name__})"
                )
        # When no backend is injected, defer resolution: the default StubBackend
        # is constructed lazily on first desktop/compute dispatch (see
        # :meth:`_require_backend`) so Core never imports secugent.desktop just to
        # route a file/http/connector step.
        self._backend: VirtualDesktopBackend | None = injected
        self._overrides = dict(builtin_overrides or {})

    # ------------------------------------------------------------------ #
    # Public
    # ------------------------------------------------------------------ #

    @property
    def config(self) -> ToolRouterConfig:
        return self._config

    @property
    def desktop_backend(self) -> VirtualDesktopBackend:
        """Currently active backend (resolving the lazy default if needed).

        Accessing this constructs the default :class:`StubBackend` on demand,
        which requires the optional desktop tier — see :meth:`_require_backend`.
        """
        return self._require_backend()

    @property
    def virtual_desktop(self) -> VirtualDesktopBackend:
        """Deprecated alias of :attr:`desktop_backend`."""
        return self._require_backend()

    def _require_backend(self) -> VirtualDesktopBackend:
        """Return the active backend, constructing the default stub on demand.

        Raises :class:`DesktopBackendUnavailableError` if no backend was injected
        and the optional ``secugent.desktop`` tier is not installed (public Core
        wheel). Memoises the resolved default so repeated desktop steps reuse one
        stub instance (preserves call-recording semantics older tests rely on).
        """
        if self._backend is None:
            _, stub_backend = _load_desktop_backend_types()
            self._backend = stub_backend()
        return self._backend

    def dispatch(
        self,
        step: Step,
        *,
        content: str | bytes | None = None,
        http_transport: Any | None = None,
    ) -> builtin.ToolResult:
        """Route ``step`` to the appropriate executor.

        ``content`` is required for ``file_write`` steps.
        ``http_transport`` is an optional injection point for tests.
        """
        action: ActionType = step.action_type
        if action == "unknown":
            raise UnknownActionError(f"unknown action_type on step {step.id}")

        if action == "connector_action":
            # Deny-by-default, checked BEFORE overrides: connector egress is
            # external communication and must flow through the mediated, audited
            # EgressBroker → ConnectorTransport path (EM-06), never the in-process
            # ToolRouter. Refused explicitly so the boundary is auditable.
            raise ToolDispatchError("connector_action must go through EgressBroker, not ToolRouter")

        if action in self._overrides:
            return self._overrides[action](step, content=content, http_transport=http_transport)

        if action == "file_read":
            if not step.target:
                raise ToolDispatchError("file_read requires target")
            return builtin.file_read(step.target, sandbox_roots=_or_none(self._config.sandbox_roots))

        if action == "file_write":
            if not step.target:
                raise ToolDispatchError("file_write requires target")
            if content is None:
                content = step.context.get("content", "")
            return builtin.file_write(
                step.target,
                content,
                sandbox_roots=self._config.sandbox_roots,
            )

        if action == "http_get":
            if not step.target:
                raise ToolDispatchError("http_get requires target")
            return builtin.http_get(
                step.target,
                allowed_domains=_or_none(self._config.allowed_domains),
                allow_subdomains=self._config.allow_subdomains,
                transport=http_transport,
            )

        if action == "compute":
            # No real compute backend in v0.1 — backend stub for repeatability.
            # Narrow at the call site: the desktop protocol (secugent.desktop.base)
            # is an excluded tier in the public core, so execute_step is typed Any.
            result: builtin.ToolResult = self._require_backend().execute_step(step)
            return result

        if action == "desktop":
            if not self._config.enable_real_desktop:
                # Fall back to the virtual desktop sandbox. Narrow at the call site
                # (excluded desktop tier types execute_step as Any in public core).
                fallback_result: builtin.ToolResult = self._require_backend().execute_step(step)
                return fallback_result
            driver = self._config.real_desktop_driver
            if driver is None:
                raise RealDesktopDisabledError("real desktop enabled but no driver configured")
            return driver(step)

        raise UnknownActionError(f"unsupported action_type {action} on step {step.id}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _or_none(seq: Iterable[str]) -> list[str] | None:
    items = list(seq)
    return items if items else None
