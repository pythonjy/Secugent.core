# SPDX-License-Identifier: Apache-2.0
"""Deterministic taint-provenance producer for Rule of Two axis① (§A-2.1).

Axis① (``untrusted_input``) of the Rule of Two used to require an **explicit**
declaration on ``Step.context``; it had no live producer (the deferred
"Stage 6 / G-C4" note in :mod:`secugent.core.rule_of_two`). This module is that
live producer: it turns *data-flow provenance* — where a step's input came from —
into a deterministic taint bit, so a step whose input derives from an untrusted
source (a web fetch, a connector response, an untrusted file, or a prior tainted
step) automatically activates axis①.

It is a **pure leaf module**: every function here is a referentially-transparent
function of its arguments — no I/O, no global state, no mutation. The single
upstream consumer is :meth:`secugent.core.rule_of_two.RuleOfTwoContext.from_step`,
which OR-combines this taint with any explicit ``untrusted_input`` declaration
(explicit ``True`` still wins; auto-taint can only ADD, never clear).

Design choices (deny-by-default, monotone):

* **I1 — monotonicity**: taint only ever turns ON. :func:`derive_taint` returns
  ``True`` whenever the parent was already tainted, regardless of the source — no
  derivation hop can clear an existing taint.
* **I3 — deny-by-default**: a ``None`` / ambiguous source must never *clear* an
  existing taint. On a clean parent an absent source does not invent taint (we
  cannot prove untrustedness), but it can never remove it either.

Only :attr:`TaintSource.USER_DIRECT` is trusted; every other source is untrusted.
The string values are wire-stable because provenance metadata is JSON-serialized
into ``Step.context``.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["TaintSource", "is_untrusted", "derive_taint"]


class TaintSource(StrEnum):
    """Where a step's input data came from (data-flow provenance).

    String values are wire-stable: they are serialized into ``Step.context``
    provenance blocks and parsed back by
    :meth:`secugent.core.rule_of_two.RuleOfTwoContext.from_step`.
    """

    WEB_FETCH = "web_fetch"
    CONNECTOR_RESPONSE = "connector_response"
    FILE_UNTRUSTED = "file_untrusted"
    USER_DIRECT = "user_direct"  # the only trusted source


def is_untrusted(source: TaintSource) -> bool:
    """True iff ``source`` is untrusted — everything except ``USER_DIRECT``.

    Pure and deterministic.
    """
    return source is not TaintSource.USER_DIRECT


def derive_taint(parent_tainted: bool, source: TaintSource | None) -> bool:
    """Deterministic taint propagation for one derivation hop.

    Rules (monotone, deny-by-default):

    * **I1 (monotone)**: if ``parent_tainted`` is ``True`` the result is ``True`` —
      taint only turns ON, never OFF, no matter the ``source``.
    * if ``source`` is not ``None`` and :func:`is_untrusted`, the result is
      ``True`` (untrusted input taints downstream).
    * **I3 (deny-by-default)**: a ``None`` / ambiguous source never *clears* an
      existing taint — it simply returns ``parent_tainted`` (so it cannot invent
      taint on a clean parent, nor remove it from a tainted one).
    """
    if parent_tainted:
        return True
    if source is not None and is_untrusted(source):
        return True
    return parent_tainted
