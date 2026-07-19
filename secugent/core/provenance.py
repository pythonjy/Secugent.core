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

G-C4 (2026-06-13): :func:`taint_source_for_action` is the new deterministic
action-type → taint-source mapping used by ``HeadAgent._parse_plan`` to
automatically inject provenance taint from plan structure. See
``docs/specs/2026-06-13-gc4-axis1-live-provenance.md`` for the full design
rationale (§A-2 근거).
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import assert_never

from secugent.core.contracts import ActionType

__all__ = ["TaintSource", "is_untrusted", "derive_taint", "taint_source_for_action"]


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


def _untrusted_file_flagged(context: Mapping[str, object]) -> bool:
    """Return True iff the context carries an explicit untrusted_file=True flag.

    Reads from BOTH the flat (top-level) context AND the nested ``rule_of_two``
    block — symmetric with how :func:`secugent.core.rule_of_two._flag_declared`
    OR-combines axis flags across both locations. Only an exact ``is True`` value
    counts (deny-by-default: truthy-but-not-``True`` is ``False`` so an
    attacker-controlled truthy value cannot silently enable axis①).
    """
    if context.get("untrusted_file") is True:
        return True
    nested = context.get("rule_of_two")
    if isinstance(nested, dict) and nested.get("untrusted_file") is True:
        return True
    return False


def taint_source_for_action(
    action_type: ActionType,
    context: Mapping[str, object],
) -> TaintSource | None:
    """Deterministic action-type → taint-source mapping (G-C4, §A-2.1 Rule-of-Two).

    Returns the :class:`TaintSource` that a step with the given ``action_type``
    should carry for axis① (``untrusted_input``), or ``None`` if the action is
    not an untrusted-input source and should carry no automatic taint.

    This function is called by ``HeadAgent._parse_plan`` immediately after each
    :class:`~secugent.core.contracts.Step` is constructed. It closes the §A-2.1
    producer gap for ``http_get`` (→ :attr:`TaintSource.WEB_FETCH`) and
    ``connector_action`` (→ :attr:`TaintSource.CONNECTOR_RESPONSE`) — both are
    definitionally untrusted and activate axis① without any explicit flag.

    **Live coverage and bounded follow-ups:**

    * ``"http_get"`` and ``"connector_action"`` are fully wired live: every plan
      step of these types automatically activates axis① via the live producer.
    * ``"file_read"`` taint is **gated on an explicit** ``untrusted_file: true``
      flag (checked in both flat and nested ``rule_of_two`` locations). The live
      producer that sets this flag for genuinely-untrusted-source reads (uploads
      dir, email attachments, external mounts) is a **tracked follow-up** —
      it is not shipped in this cycle. Cross-step ``mark_derived_from`` propagation
      is also a tracked follow-up (requires a ``depends_on`` field on ``Step``).
    * ``"file_write"``, ``"desktop"``, ``"compute"``, ``"unknown"`` → ``None`` —
      these are not untrusted-**input** sources.

    **§A-2 근거:**

    * ``"http_get"`` → :attr:`TaintSource.WEB_FETCH` — web content is
      **definitionally** external/untrusted.
    * ``"connector_action"`` → :attr:`TaintSource.CONNECTOR_RESPONSE` — external
      connector responses arrive from third-party systems outside the trust boundary.
    * ``"file_read"`` with explicit flag → :attr:`TaintSource.FILE_UNTRUSTED` —
      plain config/policy reads are trusted; tainting all ``file_read`` would cause
      false-positive HITL storms. The flag is checked in both flat and nested
      ``rule_of_two`` locations (symmetric with the reader). Only ``is True`` counts
      (deny-by-default: truthy-but-not-``True`` cannot silently activate axis①).
    * No-taint cases are **explicit** (match arms) — adding a future
      :data:`~secugent.core.contracts.ActionType` without updating this function
      will fail mypy (via the ``assert_never`` exhaustiveness guard) rather than
      silently defaulting to no-taint.

    Pure, deterministic, side-effect-free (no I/O, no global state, no mutation).
    Invariants: I2 (determinism), I3 (deny-by-default), I4 (no false positives on
    trusted reads/writes).
    """
    match action_type:
        case "http_get":
            return TaintSource.WEB_FETCH
        case "connector_action":
            return TaintSource.CONNECTOR_RESPONSE
        case "file_read":
            # Only explicit boolean True activates taint (deny-by-default). Reads
            # from both flat and nested rule_of_two locations — symmetric with the
            # reader (RuleOfTwoContext.from_step OR-combines both).
            return TaintSource.FILE_UNTRUSTED if _untrusted_file_flagged(context) else None
        case "file_write" | "desktop" | "compute" | "unknown":
            # These are not untrusted-input sources; no taint produced.
            return None
        case _ as unreachable:  # pragma: no cover
            # Exhaustiveness guard: a new ActionType member that is not handled
            # above will fail mypy here (assert_never). This prevents a future
            # extension from silently defaulting to no-taint on a P0 security path.
            # Marked no-cover: this arm is structurally unreachable for any valid
            # ActionType value — Pydantic rejects out-of-Literal values at Step
            # construction. The guard exists for mypy/CI, not runtime coverage.
            assert_never(unreachable)
