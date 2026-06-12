# SPDX-License-Identifier: Apache-2.0
"""Credential delegation (EM-06) — the workload never holds a token.

EM-05 made the broker the single egress path. EM-06 strips credentials from the
workload: :class:`CredentialBroker` fetches a secret from the secrets layer,
lends the plaintext to a call **only for the duration of that call**, and
**scrubs** the token from whatever the call returns. Even a compromised
connector that echoes the token into its payload cannot leak it back — the
plaintext never crosses the return boundary (SECURITY_CONTRACT §11.3).

Failure is closed: if the secret cannot be resolved (missing/empty/backend
error) the call is never made.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any, Protocol

from pydantic import SecretStr

__all__ = ["SecretsProvider", "CredentialError", "CredentialBroker", "scrub_secret"]

_PLACEHOLDER = "***REDACTED***"

# Standard control-flow exceptions whose TYPE must be preserved (cancellation /
# shutdown semantics) rather than coerced into CredentialError — but whose message
# is still scrubbed, because a hostile connector could raise one with the token in
# it (SG-20260605-06). Everything else that is not in the caller's ``reraise_types``
# allowlist fails closed as CredentialError.
_PRESERVE_TYPES: tuple[type[BaseException], ...] = (
    KeyboardInterrupt,
    SystemExit,
    asyncio.CancelledError,
)


class SecretsProvider(Protocol):
    """Structural contract satisfied by :class:`secugent.core.secrets.SecretsManager`."""

    async def get(self, name: str, version: str | None = ...) -> SecretStr: ...


class CredentialError(RuntimeError):
    """Raised when a credential cannot be resolved → fail-closed (no call made)."""


def _scrub_key(key: Any, token: str, placeholder: str) -> Any:
    # Scrub only str/bytes keys (the JSON-representable ones a payload can carry).
    # Other key types (int, tuple, ...) are returned UNCHANGED — they stay
    # hashable (rebuilding them could yield an unhashable list and crash) and are
    # not JSON-serializable anyway, so they never reach the workload/audit as JSON.
    if isinstance(key, str):
        return key.replace(token, placeholder)
    if isinstance(key, bytes):
        return key.replace(token.encode("utf-8"), placeholder.encode("utf-8"))
    return key


def _scrub_value(value: Any, token: str, placeholder: str) -> Any:
    # A hostile connector controls the *shape* of its payload, so the token must
    # be scrubbed wherever it can hide: string/bytes leaves, list/tuple/set items,
    # AND dict keys (not just values) — `{token: "x"}` would otherwise leak.
    if isinstance(value, str):
        return value.replace(token, placeholder)
    if isinstance(value, bytes):
        return value.replace(token.encode("utf-8"), placeholder.encode("utf-8"))
    if isinstance(value, dict):
        return {
            _scrub_key(key, token, placeholder): _scrub_value(item, token, placeholder)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        # Collapse every sequence/set to a list of scrubbed items (sets are not
        # JSON-serializable; a list preserves the values without an unhashable trap).
        return [_scrub_value(item, token, placeholder) for item in value]
    return value


def scrub_secret(payload: dict[str, Any], token: str, *, placeholder: str = _PLACEHOLDER) -> dict[str, Any]:
    """Recursively replace every occurrence of ``token`` with ``placeholder``.

    Defense-in-depth: callers must never rely on connectors *not* echoing the
    token — this guarantees every JSON-representable leaf AND string/bytes key of
    the returned structure is token-free. An empty token is a no-op.
    """
    if not token:
        return payload
    return {
        _scrub_key(key, token, placeholder): _scrub_value(item, token, placeholder)
        for key, item in payload.items()
    }


class CredentialBroker:
    """Fetches a secret and lends it to a call without ever returning it."""

    def __init__(self, secrets: SecretsProvider) -> None:
        self._secrets = secrets

    async def with_credential(
        self,
        name: str,
        *,
        call: Callable[[str], Awaitable[dict[str, Any]]],
        scrub: bool = True,
        reraise_types: tuple[type[Exception], ...] = (),
    ) -> dict[str, Any]:
        """Resolve secret ``name``, run ``call(token)``, and return its payload
        with the token scrubbed out. Raises :class:`CredentialError` (without
        invoking ``call``) if the secret is missing, empty, or the backend
        fails — fail-closed.

        ``reraise_types`` is an opt-in allowlist of *domain* exception types the
        caller wants to survive the credential boundary with their **type intact**
        (e.g. a connector policy denial like ``WhitelistViolation`` /
        ``RateLimitExceeded`` raised *inside* ``call`` so the caller can branch on
        it and audit it). Each listed type SHOULD accept a single ``str`` message
        argument; if its constructor cannot, the broker fails closed to
        :class:`CredentialError` rather than leak.

        Token safety holds for **every** exit: any in-call ``BaseException`` (not
        only ``Exception``) is caught, its message scrubbed, and a FRESH instance
        raised OUTSIDE the except block, so no plaintext token survives via the
        message, args, instance attributes, or ``__context__``/traceback. Standard
        control-flow exceptions (``KeyboardInterrupt``/``SystemExit``/
        ``asyncio.CancelledError``) keep their TYPE (scrubbed) so cancellation and
        shutdown are not swallowed; any other non-allowlisted exception (and the
        default empty allowlist) is sanitised into :class:`CredentialError`."""
        try:
            secret = await self._secrets.get(name)
        except Exception as exc:  # noqa: BLE001 - any backend failure ⇒ fail-closed
            raise CredentialError(f"secret {name!r} could not be resolved") from exc
        token = secret.get_secret_value()
        if not token:
            raise CredentialError(f"secret {name!r} resolved to an empty value")
        # The token is in scope only for this call. A connector error must never
        # carry the plaintext token out — not via its message, args, NOR the
        # implicit ``__context__``. So we capture only the scrubbed message (and,
        # for an allowlisted domain type, the bare type) inside the except, let the
        # token-bearing exception go out of scope, and raise a fresh sanitized error
        # OUTSIDE the except block (no active exception ⇒ no __context__/__cause__
        # referencing the original, and no custom token-bearing attributes copied).
        try:
            payload = await call(token)
        except BaseException as exc:  # noqa: BLE001 - sanitize + fail-closed; NOTHING may carry the token out
            # ``BaseException`` (not just ``Exception``) is caught so a connector
            # raising a ``BaseException`` subclass cannot bypass scrubbing
            # (SG-20260605-06). Capture ONLY token-free primitives here; the
            # token-bearing ``exc`` is deleted when this block ends. Reconstruction +
            # raising happen BELOW, OUTSIDE the except — so even a hostile exception
            # type whose constructor itself raises cannot chain the original through
            # ``__context__``/traceback (SG-20260605-05).
            #
            # Render defensively: ``__str__`` is attacker-controlled (connectors are
            # outside the trust boundary). A hostile ``__str__`` that itself raises
            # must NOT escape this block carrying the token — fall back to a constant
            # (SG-20260605-07). The ``.replace`` then scrubs whatever was rendered.
            try:
                raw = str(exc)
            except BaseException:  # noqa: BLE001 - hostile __str__ must not leak the token
                raw = "<unrenderable connector exception>"
            scrubbed = raw.replace(token, _PLACEHOLDER)
            if isinstance(exc, reraise_types) or isinstance(exc, _PRESERVE_TYPES):
                # Caller-allowlisted domain type (e.g. a connector policy denial) OR a
                # standard control-flow exception (cancellation / shutdown): preserve
                # the TYPE so the caller / event loop keeps its semantics — message
                # still scrubbed.
                preserve_type: type[BaseException] | None = type(exc)
            else:
                # Ordinary connector failure OR a non-standard hostile BaseException
                # ⇒ fail closed as CredentialError.
                preserve_type = None
        else:
            return scrub_secret(payload, token) if scrub else payload
        # No active exception is in scope here ⇒ nothing can reference the token via
        # the implicit context. Default fail-closed to CredentialError; reconstruct
        # the preserved type only if its constructor cooperates, else keep the
        # CredentialError fallback (never leak on a hostile constructor).
        error: BaseException = CredentialError(f"credential-scoped call failed: {scrubbed}")
        if preserve_type is not None:
            try:
                error = preserve_type(scrubbed)
            except BaseException:  # noqa: BLE001 - odd/hostile constructor ⇒ fail-closed as CredentialError
                error = CredentialError(f"credential-scoped call failed: {scrubbed}")
        raise error from None
