# SPDX-License-Identifier: Apache-2.0
"""Load only signed-and-verified policy bundles (EM-03, invariant I-D).

``load_active_policy`` reads a :class:`SignedBundle` from disk, verifies it, and
compiles it. Anything off — missing file, malformed JSON, an unsigned plain
``PolicyDoc``, or a tampered/invalid signature — raises :class:`PolicyLoadError`
(fail-closed). ``empty_deny_policy`` is the deny-by-default boot fallback when no
bundle is configured.
"""

from __future__ import annotations

import json
from collections.abc import Set as AbstractSet
from dataclasses import asdict
from pathlib import Path

from secugent.audit.merkle import KmsProvider
from secugent.core.sec.policy.compiler import compile_policy
from secugent.core.sec.policy.evaluator import CompiledPolicy
from secugent.core.sec.policy.schema import PolicyDoc
from secugent.core.sec.policy.signer import (
    PolicySignatureError,
    SignedBundle,
    verify_bundle,
)

__all__ = ["PolicyLoadError", "load_active_policy", "write_signed_bundle", "empty_deny_policy"]


class PolicyLoadError(Exception):
    """Raised when a signed policy bundle cannot be loaded/verified (fail-closed)."""


def write_signed_bundle(bundle: SignedBundle, path: str | Path) -> None:
    """Serialize a :class:`SignedBundle` to ``path`` as JSON."""
    Path(path).write_text(json.dumps(asdict(bundle)), encoding="utf-8")


_BUNDLE_FIELDS: tuple[str, ...] = (
    "doc_json",
    "doc_hash",
    "signature_hex",
    "key_id",
    "algorithm",
)


def _load_signed_bundle(path: str | Path) -> SignedBundle:
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("signed bundle must be a JSON object")
    # SignedBundle is a plain dataclass, so SignedBundle(**data)
    # only catches missing/extra keys (TypeError) — not wrong field *value* types.
    # A bundle whose doc_json is a JSON object (dict) would construct fine, then
    # blow up later in verify_bundle with an AttributeError that escapes the
    # declared (OSError, ValueError, TypeError, PolicySignatureError) handler and
    # breaks the PolicyLoadError fail-closed contract. Validate every field is a
    # str up front and surface violations as ValueError.
    for field_name in _BUNDLE_FIELDS:
        if field_name not in data:
            raise ValueError(f"signed bundle missing field {field_name!r}")
        if not isinstance(data[field_name], str):
            raise ValueError(
                f"signed bundle field {field_name!r} must be a string, got {type(data[field_name]).__name__}"
            )
    return SignedBundle(**data)  # extra keys (e.g. a plain PolicyDoc) → TypeError


def load_active_policy(
    path: str | Path, *, kms: KmsProvider, allowed_key_ids: AbstractSet[str]
) -> CompiledPolicy:
    """Load, verify, and compile the signed policy at ``path`` (fail-closed).

    ``allowed_key_ids`` pins the authorized signing keys — a bundle signed with
    any other key (even one the KMS knows) is rejected.
    """
    try:
        bundle = _load_signed_bundle(path)
        doc = verify_bundle(bundle, kms=kms, allowed_key_ids=allowed_key_ids)
    except (OSError, ValueError, TypeError, PolicySignatureError) as exc:
        raise PolicyLoadError(f"cannot load signed policy from {path}: {exc}") from exc
    return compile_policy(doc)


def empty_deny_policy() -> CompiledPolicy:
    """Deny-by-default policy used at boot when no signed bundle is configured."""
    return compile_policy(PolicyDoc(version="empty", tenant_id="_base", rules=[]))
