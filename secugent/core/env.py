# SPDX-License-Identifier: Apache-2.0
"""Single source of truth for the dev/prod environment decision (DA-C2).

This is the CORE-level decider so that both the API layer (:mod:`secugent.api.env`,
which re-exports it) and core/library modules (e.g. :mod:`secugent.core.llm_client`)
share **one** function — satisfying INV-C2-1 ("a single function decides dev/prod;
no other copy of the literal exists"). It lives in ``core`` (not ``api``) because
``core`` must never import ``api`` (§D-2); the API layer is free to import core.

The leaf module has **no import-time side effects and no guard**, so any module may
import it safely — including in production and including modules that load before
auth is wired.

The default is **INVERTED** relative to the historical helpers (§A-2.2
deny-by-default): production is the safe default and dev must explicitly OPT IN
with ``SECUGENT_ENV=dev``. The previous default of ``"dev"`` silently selected the
permissive path (the ``X-User-*`` header shim in the API, a ``MockLLMClient`` in the
LLM resolver) whenever an operator forgot to set the variable — the exact opposite
of fail-closed.
"""

from __future__ import annotations

import os

__all__ = ["is_dev_env"]

#: The environment variable selecting the dev shim. Any value other than an
#: exact (trimmed, case-insensitive) ``"dev"`` is treated as production.
_ENV_VAR: str = "SECUGENT_ENV"


def is_dev_env() -> bool:
    """Return ``True`` iff ``SECUGENT_ENV`` is explicitly ``"dev"``.

    Unset / blank / any non-``dev`` value → ``False`` (production, fail-closed).
    The comparison is trimmed and case-insensitive, so ``"DEV"`` and ``" dev "``
    are dev, while ``"dev-1"``, ``"development"``, ``"prod"`` and ``""`` are all
    production (exact match only — no prefix/substring leniency).
    """
    return os.environ.get(_ENV_VAR, "").strip().lower() == "dev"
