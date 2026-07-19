# SPDX-License-Identifier: Apache-2.0
"""S5 — real httpx egress transport for the first-party connectors.

Each connector's ``execute`` receives an injectable ``http_transport`` callable
``(action, principal, secret_value) -> dict``. Before S5 that callable was always
``None`` in production and the connector fell back to a mock-success — a
false-green. This module supplies the REAL callable:

* :class:`HttpxConnectorTransport` maps an unqualified
  :class:`~secugent.tools.connectors.base.ConnectorAction` to a vendor HTTP request
  (URL/method/body via a small per-connector request mapper), performs it over
  ``httpx``, classifies the response, and retries transients.
* **SSRF guard** (INV-6): loopback / link-local (cloud IMDS) / CGNAT are ALWAYS
  refused; RFC-1918 private addresses are allowed only when ``allow_internal=True``
  (the closed-network on-prem opt-in for 사내 메신저·ERP·ITSM). Embedded-v4 IPv6
  forms are normalized to their real target before the check.
* **4xx = permanent** (:class:`ConnectorHttpError`, no retry — the request is
  wrong); **5xx / timeout / network = transient** (:class:`ConnectorHttpTransient`,
  retried up to ``max_attempts`` then terminal) (INV-4).
* **Credential non-leak** (INV-5): ``secret_value`` is sent only as a Bearer
  header and never appears in any raised error message or log.

``httpx`` is imported **lazily** (only when the transport actually fires), so
importing this module — and therefore the connector package and ``secugent.core``
— never requires ``httpx`` to be installed (INV-8, air-gapped boot).
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from secugent.core.tenancy import Principal
from secugent.tools.connectors.base import ConnectorAction, ConnectorError

if TYPE_CHECKING:
    import httpx

__all__ = [
    "ConnectorEndpoint",
    "ConnectorHttpError",
    "ConnectorHttpTransient",
    "ConnectorSettings",
    "HttpxConnectorTransport",
    "SsrfBlocked",
    "build_connector_transport",
    "guard_url_host",
]


class SsrfBlocked(ConnectorError):
    """A request target resolved to an SSRF-blocked address (INV-6).

    Shared by the connector transport and the MCP/A2A adapters so the
    closed-network egress guard lives in exactly one place. Each adapter wraps it
    into its own terminal type, but the classification is identical everywhere.
    """


_log = logging.getLogger("secugent.tools.connectors.transport")


class ConnectorHttpError(ConnectorError):
    """Permanent connector egress failure (4xx / config error). Not retried."""


class ConnectorHttpTransient(ConnectorError):
    """Transient connector egress failure (5xx / timeout / network). Retryable."""


# --------------------------------------------------------------------------- #
# SSRF guard (INV-6) — minimal, self-contained (notifier's full guard is out of
# scope here; this keeps the connector layer's guard in ONE place).
# --------------------------------------------------------------------------- #

_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Always blocked, even with allow_internal=True — canonical SSRF pivot targets.
_ALWAYS_BLOCKED: list[_IpNetwork] = [
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # link-local + AWS IMDS 169.254.169.254
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),  # CGNAT
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("fc00::/7"),
]
_PRIVATE: list[_IpNetwork] = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


def _effective_addresses(ip: _IpAddress) -> list[_IpAddress]:
    """Decompose embedded-v4 IPv6 forms to their real v4 target.

    A v6 literal embedding a v4 address (IPv4-mapped / 6to4 / Teredo / NAT64)
    routes to that underlying v4 host; range-checking the bare v6 literal would
    miss it. Returns the embedded v4 target(s) when present, else the original.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        embedded: list[_IpAddress] = []
        for mapped in (ip.ipv4_mapped, ip.sixtofour):
            if mapped is not None:
                embedded.append(mapped)
        teredo = ip.teredo
        if teredo is not None:
            embedded.extend(teredo)
        if ip in _NAT64:
            embedded.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if embedded:
            return embedded
    return [ip]


def _is_always_blocked(addr: _IpAddress) -> bool:
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return True
    return any(addr in net for net in _ALWAYS_BLOCKED)


def _guard_host(host: str, *, allow_internal: bool) -> None:
    """Raise :class:`SsrfBlocked` if ``host`` is an SSRF-blocked target.

    Only literal IPs are classified directly; a DNS name is left to httpx (the
    endpoints are operator-configured, not attacker-supplied — this guard is
    defence-in-depth against a misconfigured private/metadata endpoint).
    """
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # hostname, not a literal IP — operator-configured endpoint
    for effective in _effective_addresses(ip):
        if _is_always_blocked(effective):
            raise SsrfBlocked(
                f"endpoint host {host} (effective {effective}) is an SSRF-blocked "
                "target (loopback / link-local / metadata / CGNAT) — always refused"
            )
        if not allow_internal and any(effective in net for net in _PRIVATE):
            raise SsrfBlocked(
                f"endpoint host {host} is an RFC-1918 private address; "
                "set allow_internal=True for a closed-network on-prem endpoint"
            )


def guard_url_host(url: str, *, allow_internal: bool) -> None:
    """Public SSRF guard over a full URL — extracts the host and classifies it.

    Shared by the MCP/A2A adapters (which receive a full URL) so the closed-network
    egress policy is identical to the connector transport's. Raises
    :class:`SsrfBlocked` on a blocked target.
    """
    host = urlparse(url).hostname or ""
    _guard_host(host, allow_internal=allow_internal)


# --------------------------------------------------------------------------- #
# Per-connector request mapping (action -> URL path / method / body)
# --------------------------------------------------------------------------- #


class _Mapped(BaseModel):
    """The vendor request a connector action maps to (path is appended to base)."""

    model_config = ConfigDict(extra="forbid")

    method: str
    path: str
    json_body: dict[str, Any] = Field(default_factory=dict)


def _default_mapper(action: ConnectorAction) -> _Mapped:
    """Generic mapper used by every first-party connector.

    The first-party vendors differ in exact REST shape; rather than encode each
    vendor's API surface (out of scope for S5, which is about *wiring* a real
    transport — not modelling six SaaS APIs), every action POSTs to
    ``/{action_name}`` with the action params as the JSON body. The action name
    is already gated by the connector's ``actions`` tuple + the broker membership
    gate, so this is a safe, uniform shape an operator can point at a vendor
    proxy / on-prem relay. A connector-specific mapper can later override this.
    """
    return _Mapped(method="POST", path=f"/{action.name}", json_body=dict(action.params))


# --------------------------------------------------------------------------- #
# Endpoint config + settings
# --------------------------------------------------------------------------- #


class ConnectorEndpoint(BaseModel):
    """One connector's vendor base URL (the JSON path is appended per action)."""

    model_config = ConfigDict(extra="forbid")

    base_url: str

    @field_validator("base_url")
    @classmethod
    def _non_empty_url(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("ConnectorEndpoint.base_url must be a non-empty URL")
        return value.rstrip("/")


class ConnectorSettings(BaseModel):
    """Operator config for the production connector transport (boot-time).

    ``endpoints`` maps a connector name to its vendor base URL. ``allow_internal``
    is False by default (deny-by-default §A-2.2); set True only for closed-network
    on-prem connectors (사내 메신저·ERP·ITSM) whose endpoints are RFC-1918.
    """

    model_config = ConfigDict(extra="forbid")

    endpoints: dict[str, str] = Field(default_factory=dict)
    timeout_sec: float = 10.0
    max_attempts: int = 3
    allow_internal: bool = False

    @field_validator("endpoints")
    @classmethod
    def _non_empty_endpoint_urls(cls, value: dict[str, str]) -> dict[str, str]:
        for name, url in value.items():
            if not url or not url.strip():
                raise ValueError(f"ConnectorSettings.endpoints[{name!r}] must be a non-empty URL")
        return value

    @field_validator("timeout_sec")
    @classmethod
    def _positive_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("ConnectorSettings.timeout_sec must be positive")
        return value

    @field_validator("max_attempts")
    @classmethod
    def _at_least_one_attempt(cls, value: int) -> int:
        if value < 1:
            raise ValueError("ConnectorSettings.max_attempts must be >= 1")
        return value


# --------------------------------------------------------------------------- #
# The transport
# --------------------------------------------------------------------------- #


class HttpxConnectorTransport:
    """Async ``http_transport`` callable backed by ``httpx`` (lazy import).

    Built per-connector (``connector_name`` selects the endpoint + mapper). The
    same instance is reused across calls; an injected ``_mock_transport`` lets a
    test drive responses via :class:`httpx.MockTransport` without real sockets.
    """

    def __init__(
        self,
        endpoints: Mapping[str, ConnectorEndpoint],
        *,
        connector_name: str,
        timeout_sec: float,
        max_attempts: int,
        allow_internal: bool,
        _mock_transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._endpoints = dict(endpoints)
        self._connector_name = connector_name
        self._timeout = timeout_sec
        self._max_attempts = max_attempts
        self._allow_internal = allow_internal
        # Test seam: an httpx.MockTransport injected so no real socket is opened.
        self._mock_transport = _mock_transport

    async def __call__(
        self, *, action: ConnectorAction, principal: Principal, secret_value: str
    ) -> dict[str, Any]:
        endpoint = self._endpoints.get(self._connector_name)
        if endpoint is None:
            # No endpoint configured ⇒ no target ⇒ fail closed (never a mock success).
            raise ConnectorHttpError(f"no endpoint configured for connector {self._connector_name!r}")
        try:
            _guard_host(urlparse(endpoint.base_url).hostname or "", allow_internal=self._allow_internal)
        except SsrfBlocked as exc:
            # Surface as the connector's permanent type (a blocked endpoint is a
            # config error, never retried) while keeping the shared classification.
            raise ConnectorHttpError(str(exc)) from exc

        mapped = _default_mapper(action)
        url = f"{endpoint.base_url}{mapped.path}"
        last_transient: ConnectorHttpTransient | None = None
        for attempt in range(1, self._max_attempts + 1):
            try:
                return await self._fire_once(url, mapped, secret_value)
            except ConnectorHttpTransient as exc:
                last_transient = exc
                _log.warning(
                    "connector %s transient failure (attempt %d/%d)",
                    self._connector_name,
                    attempt,
                    self._max_attempts,
                )
        # Retries exhausted → terminal transient (message is already secret-free).
        assert last_transient is not None  # loop ran at least once (max_attempts >= 1)
        raise last_transient

    async def _fire_once(self, url: str, mapped: _Mapped, secret_value: str) -> dict[str, Any]:
        """Perform ONE request. 4xx → permanent; 5xx/timeout/network → transient."""
        httpx = _import_httpx()
        headers = {
            "Authorization": f"Bearer {secret_value}",
            "Content-Type": "application/json",
        }
        # Build a client over the (optional) injected mock transport so tests
        # never open a socket; production uses the real default transport.
        client_kwargs: dict[str, Any] = {"timeout": self._timeout}
        if self._mock_transport is not None:
            client_kwargs["transport"] = self._mock_transport
        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.request(mapped.method, url, json=mapped.json_body, headers=headers)
        except httpx.TimeoutException as exc:
            raise ConnectorHttpTransient(f"{self._connector_name} request timed out") from exc
        except httpx.TransportError as exc:
            # Connection refused/reset/DNS — no response. Fixed category, no URL/secret.
            raise ConnectorHttpTransient(f"{self._connector_name} transport failure: no response") from exc

        status = response.status_code
        if status >= 500:
            raise ConnectorHttpTransient(f"{self._connector_name} vendor returned {status}")
        if status >= 400:
            # 4xx is a permanent client error — never retried (auth/bad-request).
            raise ConnectorHttpError(f"{self._connector_name} vendor returned {status}")
        return self._parse_body(response)

    def _parse_body(self, response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except ValueError:
            # 2xx with a non-JSON body — wrap so the connector still gets a dict.
            return {"ok": True, "raw_status": response.status_code}
        if isinstance(body, dict):
            return body
        return {"ok": True, "content": body}


def _import_httpx() -> Any:
    """Lazy ``httpx`` import (INV-8: never eager at module import)."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise ConnectorHttpError(
            "httpx is required for the production connector transport; install it or inject a transport"
        ) from exc
    return httpx


def build_connector_transport(settings: ConnectorSettings, *, connector_name: str) -> HttpxConnectorTransport:
    """Materialise the production connector transport described by ``settings``.

    The integration step calls this per connector (``connector_name``) and injects
    the result into ``ConnectorTransport.dispatch(..., http_transport=...)`` — this
    module never reaches ``api/main.py`` itself (S5 lane boundary).
    """
    endpoints = {name: ConnectorEndpoint(base_url=url) for name, url in settings.endpoints.items()}
    return HttpxConnectorTransport(
        endpoints,
        connector_name=connector_name,
        timeout_sec=settings.timeout_sec,
        max_attempts=settings.max_attempts,
        allow_internal=settings.allow_internal,
    )
