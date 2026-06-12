# SPDX-License-Identifier: Apache-2.0
"""On-behalf-of identity (EM-06) — attribute effects to the real user, not "one bot".

When the broker calls a downstream system it should carry *who* the action is
for. :class:`IdentityStrategy` resolves a :class:`CallIdentity`:

* **OBO inject** — only when the connector genuinely supports user-token
  delegation (``supports_obo``). Reserved for user-scoped OAuth connectors.
* **Attribution-only** — the honest default for bot-token connectors
  (Slack/Notion/Jira): we do not fake user delegation; we force the real
  ``user_id`` into the call metadata + audit so attribution is never "one bot".

Either way the attributed user is recorded — we never lose who acted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from secugent.core.tenancy import Principal

__all__ = ["CallIdentity", "IdentityStrategy"]

IdentityMode = Literal["obo", "attribution"]


@dataclass(frozen=True)
class CallIdentity:
    """How a downstream call is attributed to the acting user."""

    mode: IdentityMode
    on_behalf_of: str
    tenant_id: str
    run_id: str
    injected: bool
    audit_meta: dict[str, str]


class IdentityStrategy:
    """Resolves the on-behalf-of identity for a connector call (deterministic)."""

    def resolve(self, principal: Principal, *, supports_obo: bool, run_id: str) -> CallIdentity:
        if not principal.user_id:
            raise ValueError("on-behalf-of attribution requires a non-empty principal.user_id")
        mode: IdentityMode = "obo" if supports_obo else "attribution"
        tenant_id = str(principal.tenant_id)
        audit_meta = {
            "on_behalf_of": principal.user_id,
            "tenant_id": tenant_id,
            "run_id": run_id,
            "mode": mode,
        }
        return CallIdentity(
            mode=mode,
            on_behalf_of=principal.user_id,
            tenant_id=tenant_id,
            run_id=run_id,
            injected=supports_obo,
            audit_meta=audit_meta,
        )
