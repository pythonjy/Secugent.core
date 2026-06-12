# SPDX-License-Identifier: Apache-2.0
"""Built-in tools for SUB execution.

Per master prompt PHASE 3 DoD:

* ``file_write`` is **only** allowed to write under a configured sandbox root.
* ``http_get`` must honour the active :class:`DomainPolicy` and refuse to
  follow cross-domain redirects (we just refuse all redirects at this level).
* ``file_read`` reads bytes up to a configurable byte limit; large files are
  truncated and a logical hash returned, mirroring redaction policy.

These tools intentionally do NOT re-check the regulations — that's the SUB
agent's job (Mechanical Oversight runs before tool dispatch). They DO enforce
their *own* fail-closed envelopes (sandbox + redirect + size).
"""

from __future__ import annotations

import hashlib
import http.client
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from secugent.core.mechanical_oversight import (
    NormalizationError,
    normalize_domain,
    normalize_path,
)

__all__ = [
    "BuiltinToolError",
    "SandboxViolationError",
    "ToolResult",
    "file_read",
    "file_write",
    "http_get",
    "DEFAULT_READ_LIMIT",
    "DEFAULT_WRITE_LIMIT",
]


DEFAULT_READ_LIMIT = 1 * 1024 * 1024  # 1 MiB
DEFAULT_WRITE_LIMIT = 1 * 1024 * 1024  # 1 MiB
HTTP_TIMEOUT = 10.0


class BuiltinToolError(RuntimeError):
    """Raised on non-recoverable tool failures."""


class SandboxViolationError(BuiltinToolError):
    """Raised when a write target escapes the sandbox roots."""


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    payload: dict[str, Any]


# ---------------------------------------------------------------------------
# file_read
# ---------------------------------------------------------------------------


def file_read(
    target: str,
    *,
    sandbox_roots: Iterable[str] | None = None,
    byte_limit: int = DEFAULT_READ_LIMIT,
) -> ToolResult:
    """Read up to ``byte_limit`` bytes from ``target``.

    If ``sandbox_roots`` is provided, the target must be within at least one
    of them. Otherwise the read is allowed (Mechanical Oversight is presumed
    to have constrained the target list).
    """
    try:
        normalised = normalize_path(target)
    except NormalizationError as exc:
        raise BuiltinToolError(f"path normalisation failed: {exc}") from exc

    if sandbox_roots is not None and not _within_any(normalised, sandbox_roots):
        raise SandboxViolationError(f"target {normalised} not within any sandbox root {list(sandbox_roots)}")

    path = Path(target)
    if not path.exists():
        raise BuiltinToolError(f"file_read: {target} does not exist")
    if not path.is_file():
        raise BuiltinToolError(f"file_read: {target} is not a regular file")

    data = path.read_bytes()
    truncated = len(data) > byte_limit
    if truncated:
        data = data[:byte_limit]

    text: str | None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    return ToolResult(
        ok=True,
        payload={
            "bytes": len(data),
            "truncated": truncated,
            "sha256": hashlib.sha256(data).hexdigest(),
            "text_preview": (text[:1024] if text is not None else None),
        },
    )


# ---------------------------------------------------------------------------
# file_write
# ---------------------------------------------------------------------------


def file_write(
    target: str,
    content: str | bytes,
    *,
    sandbox_roots: Iterable[str],
    byte_limit: int = DEFAULT_WRITE_LIMIT,
    create_parents: bool = True,
) -> ToolResult:
    """Write ``content`` to ``target`` only if inside a sandbox root.

    ``sandbox_roots`` is required (not optional) for writes — there is no
    "wide-open" mode.
    """
    if not list(sandbox_roots):
        raise SandboxViolationError("file_write requires at least one sandbox root")

    try:
        normalised = normalize_path(target)
    except NormalizationError as exc:
        raise BuiltinToolError(f"path normalisation failed: {exc}") from exc

    if not _within_any(normalised, sandbox_roots):
        raise SandboxViolationError(f"target {normalised} not within sandbox roots {list(sandbox_roots)}")

    payload_bytes = content.encode("utf-8") if isinstance(content, str) else bytes(content)
    if len(payload_bytes) > byte_limit:
        raise BuiltinToolError(f"file_write: {len(payload_bytes)} bytes exceeds limit {byte_limit}")

    path = Path(target)
    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload_bytes)

    return ToolResult(
        ok=True,
        payload={
            "bytes": len(payload_bytes),
            "sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "target": str(path),
        },
    )


# ---------------------------------------------------------------------------
# http_get
# ---------------------------------------------------------------------------


def http_get(
    url: str,
    *,
    allowed_domains: Iterable[str] | None = None,
    allow_subdomains: bool = True,
    timeout: float = HTTP_TIMEOUT,
    max_bytes: int = DEFAULT_READ_LIMIT,
    follow_redirects: bool = False,
    transport: Any = None,
) -> ToolResult:
    """Fetch ``url`` via stdlib ``http.client``. No redirects by default.

    ``transport`` lets tests inject a fake connection factory. It must be a
    callable ``(host, port, *, timeout) -> connection`` returning an object
    with ``request``, ``getresponse``, and ``close``.
    """
    try:
        host, is_ip = normalize_domain(url)
    except NormalizationError as exc:
        raise BuiltinToolError(f"url normalisation failed: {exc}") from exc

    parsed = urlsplit(url if "://" in url else f"http://{url}")
    if allowed_domains is not None and not _domain_in_list(
        host, allowed_domains, allow_subdomains=allow_subdomains, allow_ip=False
    ):
        raise BuiltinToolError(f"host {host} not in allowed domains")

    if is_ip:
        # Routers may pass IP literals through if explicitly allowed; we still
        # refuse here because PHASE 3 builtin treats IPs as fail-closed.
        raise BuiltinToolError(f"http_get refuses IP literal host {host}")

    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    conn = _open_connection(scheme, parsed.hostname or host, port, timeout, transport)
    try:
        conn.request("GET", path, headers={"Host": parsed.hostname or host})
        response = conn.getresponse()
        status = response.status
        location = response.getheader("Location") or ""
        if 300 <= status < 400 and not follow_redirects:
            raise BuiltinToolError(
                f"http_get refused to follow redirect (status={status} location={location})"
            )
        body = response.read(max_bytes + 1)
    except (OSError, http.client.HTTPException) as exc:
        raise BuiltinToolError(f"http_get failed: {exc}") from exc
    finally:
        conn.close()

    truncated = len(body) > max_bytes
    if truncated:
        body = body[:max_bytes]

    text: str | None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    return ToolResult(
        ok=200 <= status < 300,
        payload={
            "status": status,
            "bytes": len(body),
            "truncated": truncated,
            "host": host,
            "sha256": hashlib.sha256(body).hexdigest(),
            "text_preview": (text[:1024] if text is not None else None),
        },
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _within_any(normalised: str, roots: Iterable[str]) -> bool:
    for raw_root in roots:
        try:
            root = normalize_path(raw_root)
        except NormalizationError:
            continue
        if not root.endswith("/"):
            root_with_slash = root + "/"
        else:
            root_with_slash = root
        if normalised == root or normalised.startswith(root_with_slash):
            return True
    return False


def _domain_in_list(
    host: str,
    domains: Iterable[str],
    *,
    allow_subdomains: bool = True,
    allow_ip: bool = False,
) -> bool:
    host = host.lower().rstrip(".")
    for raw in domains:
        entry = raw.strip().lower().rstrip(".")
        if entry.startswith("*."):
            base = entry[2:]
            if host == base or host.endswith("." + base):
                return True
            continue
        if host == entry:
            return True
        if allow_subdomains and host.endswith("." + entry):
            return True
    return False


def _open_connection(scheme: str, host: str, port: int, timeout: float, transport: Any) -> Any:
    if transport is not None:
        return transport(host, port, timeout=timeout)
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout)
    return http.client.HTTPConnection(host, port, timeout=timeout)
