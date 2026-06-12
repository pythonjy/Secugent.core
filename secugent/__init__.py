# SPDX-License-Identifier: Apache-2.0
"""SecuGent — Human-in-the-loop Enterprise Agent Platform.

This is the **Apache-2.0 open-core** entry point. Importing this package must
stay side-effect-free and must never require any Enterprise extra: the Core
(policy engine, Rule of Two, hash-chain audit) boots standalone. Enterprise
features (console, multitenant admin, compliance reports, external KMS, SSO)
are gated behind the ``enterprise`` extra and the lazy guard below — see
``docs/OPEN_CORE.md`` for the tier mapping and license boundary (BDP_01 item 1).
"""

from __future__ import annotations

import importlib.util

__version__ = "0.1.0"

__all__ = ["EnterpriseFeatureUnavailable", "require_enterprise", "__version__"]


class EnterpriseFeatureUnavailable(ImportError):
    """Raised when an Enterprise-tier feature is used without its extra.

    Subclasses :class:`ImportError` so callers may catch it as a missing
    dependency while still getting an actionable, install-specific message.
    """


def require_enterprise(*, feature: str, module: str, extra: str = "enterprise") -> None:
    """Fail-soft guard for Enterprise-only features (lazy, call-time only).

    Call this at the top of an Enterprise code path. If ``module`` is not
    importable, raise :class:`EnterpriseFeatureUnavailable` with guidance to
    install the extra; otherwise return ``None`` (the dependency is present).

    This is intentionally a *runtime* check — it imports nothing at package
    import time, so ``import secugent`` stays side-effect-free and works on a
    Core-only install (BDP_01 invariant I1).

    Args:
        feature: Human-readable feature name, surfaced in the error (e.g.
            ``"AWS KMS signing"``).
        module: The importable dependency name to probe (e.g. ``"boto3"``).
        extra: The pip extra that provides the dependency (default
            ``"enterprise"``).

    Raises:
        EnterpriseFeatureUnavailable: if ``module`` cannot be found.
    """
    if importlib.util.find_spec(module) is not None:
        return
    raise EnterpriseFeatureUnavailable(
        f"The Enterprise feature {feature!r} requires the optional dependency "
        f"{module!r}, which is not installed. Install the Enterprise extra with:\n"
        f"    pip install 'secugent[{extra}]'\n"
        f"The Apache-2.0 Core does not include Enterprise (BSL-1.1) dependencies; "
        f"see docs/OPEN_CORE.md for the edition boundary."
    )
