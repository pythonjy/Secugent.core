# SPDX-License-Identifier: Apache-2.0
"""``secugent rotate-secret <name>`` — honest secret-rotation wrapper (DA-H6).

This is a *thin, honest* wrapper over :meth:`SecretsManager.rotate` — it never
fakes success. The three backends have genuinely different rotation realities,
and this command surfaces each one truthfully (INV-ROTATE-1):

* **Env** (:class:`EnvSecretsBackend`): rotation is performed out-of-band by the
  operator (restart the process with the new value). ``rotate`` is a deliberate
  no-op; we say so plainly and exit 0 (a no-op is not a failure, but the operator
  must know *nothing happened in-process*).
* **Vault / AWS**: rotation is driven out-of-band (dynamic-secrets engine /
  rotation Lambda / schedule). Their ``rotate`` raises ``NotImplementedError``;
  we surface that message verbatim and exit 1 — never a fabricated success.

On success the cache entry is invalidated so the next read re-consults the
backend (the value itself is never printed — SecretStr masking is preserved).

Import closure is PUBLIC_CORE only: ``secugent.core.secrets`` + ``secugent.cli``.
"""

from __future__ import annotations

import argparse
import asyncio

from secugent.cli.verify import _emit
from secugent.core.secrets import (
    EnvSecretsBackend,
    SecretNotFoundError,
    SecretsManager,
    SecretsSettings,
    build_secrets_backend,
)

__all__ = ["run_rotate_secret", "main"]


def run_rotate_secret(*, name: str) -> int:
    """Rotate (or honestly report the inability to rotate) secret ``name``.

    Returns a process exit code: 0 only for a genuinely-completed action or an
    explicit no-op backend; 1 for an out-of-band backend, a missing secret, or a
    secrets misconfiguration. The secret value is never emitted.
    """
    try:
        backend = build_secrets_backend(SecretsSettings.from_env())
    except ValueError as exc:
        # Misconfig (e.g. VAULT_ADDR without auth, or Vault+AWS both set).
        _emit(f"secugent rotate-secret: secrets backend misconfigured — {exc}", stderr=True)
        return 1

    manager = SecretsManager(backend)
    is_env = isinstance(backend, EnvSecretsBackend)

    try:
        asyncio.run(manager.rotate(name))
    except NotImplementedError as exc:
        # Vault / AWS: rotation is out-of-band. Surface the message verbatim and
        # fail closed — do NOT pretend a rotation happened.
        _emit(f"secugent rotate-secret: rotation not performed in-process — {exc}", stderr=True)
        _emit(
            "  → rotate this secret out-of-band (Vault dynamic engine / AWS rotation "
            "Lambda or schedule), then evict the cache. See docs/runbooks/key_rotation.md.",
            stderr=True,
        )
        return 1
    except SecretNotFoundError as exc:
        _emit(f"secugent rotate-secret: secret not found — {exc}", stderr=True)
        return 1

    # Cache eviction belt-and-suspenders (rotate already evicts on success).
    manager.invalidate(name)

    if is_env:
        _emit(
            f"secugent rotate-secret: '{name}' — env backend no-op. Rotation is "
            "external: restart the process with the new value. Nothing changed in-process."
        )
    else:
        _emit(f"secugent rotate-secret: '{name}' rotated; cache invalidated.")
    return 0


def _parse_args(rest: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="secugent rotate-secret",
        description="Rotate a secret via the configured backend, honestly (DA-H6).",
    )
    parser.add_argument("name", help="Secret name/path to rotate.")
    return parser.parse_args(rest)


def main(rest: list[str]) -> int:
    """``secugent rotate-secret`` entry point. Returns a process exit code."""
    args = _parse_args(rest)
    return run_rotate_secret(name=args.name)


if __name__ == "__main__":
    raise SystemExit(main(__import__("sys").argv[1:]))
