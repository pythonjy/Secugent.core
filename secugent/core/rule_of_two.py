# SPDX-License-Identifier: Apache-2.0
"""Deterministic Rule of Two 3-axis isolation engine (architecture rule 1).

Rule of Two: in a single task/session, at most **two** of the
following three axes may be active without human review; if all three are needed,
HITL is **forced**:

  ① ``UNTRUSTED_INPUT``  — processing untrusted input (web/document/tool output)
  ② ``SENSITIVE_ACCESS`` — sensitive data / system access
  ③ ``EXTERNAL_COMM``    — state change / external communication

This module is the deterministic core that classifies a :class:`Step` into its
active axes and decides whether the Rule of Two demands HITL. It is a **pure leaf
module**: classification is a referentially-transparent function of the Step (and
an explicit context overlay) — no I/O, no global state, no mutation. The single
upstream consumer (``agents.sub_agent``) generalizes the legacy single-axis
``connector_action`` carve-out by calling :func:`classify_axes` and forcing a
fresh, step-scoped HITL approval whenever :func:`requires_hitl` is true.

The axis string values are wired into the audit schema field
``rule_of_two_axes`` via :func:`axes_to_audit`; they MUST stay byte-for-byte equal
to that schema (``untrusted_input`` / ``sensitive_access`` / ``external_comm``).

Design choices (deny-by-default, conservative):

* Axis ③ (external comm) is ON for any state-changing / egress action type
  (``connector_action``/``http_get``/``file_write``/``desktop``). Read-only
  ``file_read``/``compute`` are not egress by themselves.
* Axis ② (sensitive access) is ON for any action that touches a sensitive system
  surface (``file_read``/``file_write``/``desktop``/``connector_action``).
  ``http_get``/``compute`` are OFF unless an explicit sensitive label is declared.
* Axis ① (untrusted input) is ON when either (a) the planner / orchestrator
  **explicitly declares** it via ``Step.context`` (or a :class:`RuleOfTwoContext`),
  or (b) a deterministic **provenance producer** (:mod:`secugent.core.provenance`)
  taints the step because its input derives from an untrusted source. An action
  type alone cannot tell us whether its input is trusted, so it is never inferred
  from ``action_type`` — only from declared provenance / an explicit flag.

.. note:: Axis ① provenance auto-derivation.

   Axis ① (``untrusted_input``) has a **deterministic provenance reader**:
   :meth:`RuleOfTwoContext.from_step` reads a ``provenance`` block from
   ``Step.context`` and OR-combines :func:`secugent.core.provenance.derive_taint`
   with any explicit ``untrusted_input`` declaration. A step whose input derives
   from a web fetch / connector response / untrusted file, or whose parent step
   was already tainted, automatically activates axis ①. The combination is
   monotone: explicit ``True`` still wins, and auto-taint can only ADD axis ①,
   never clear it (deny-by-default — an ambiguous / absent source can never turn
   an inherited taint off), and a ``provenance`` block in BOTH the flat and nested
   locations is OR-combined (neither can clear the other's taint).

   **Live producer status (2026-06-13):** ``HeadAgent._parse_plan`` now
   calls ``taint_source_for_action`` after each ``Step`` is constructed and wires
   the result into ``mark_untrusted_source``. ``http_get`` and
   ``connector_action`` steps automatically activate axis① with no explicit flag.
   ``file_read`` axis① fires only when an explicit ``untrusted_file: true`` flag
   is present (flat or nested); the ingest-layer producer and cross-step
   ``mark_derived_from`` propagation remain bounded follow-ups.
* Explicit context flags and provenance-derived taint are purely **additive**
  overlays — they can only add an axis, never remove one (monotone, regression-safe).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from secugent.core.contracts import ActionType, Step
from secugent.core.provenance import TaintSource, derive_taint

__all__ = [
    "Axis",
    "RuleOfTwoContext",
    "classify_axes",
    "requires_hitl",
    "axes_to_audit",
    "axes_for_steps",
]


class Axis(StrEnum):
    """The three Rule of Two axes.

    String values are the audit-schema tokens for ``rule_of_two_axes`` and
    must not be renamed without a coordinated schema change.
    """

    UNTRUSTED_INPUT = "untrusted_input"
    SENSITIVE_ACCESS = "sensitive_access"
    EXTERNAL_COMM = "external_comm"


# Action types whose effect changes state / leaves the workload (axis ③).
_EXTERNAL_COMM_ACTIONS: frozenset[ActionType] = frozenset(
    {"connector_action", "http_get", "file_write", "desktop"}
)
# Action types that touch a sensitive data / system surface (axis ②).
_SENSITIVE_ACCESS_ACTIONS: frozenset[ActionType] = frozenset(
    {"file_read", "file_write", "desktop", "connector_action"}
)


@dataclass(frozen=True)
class RuleOfTwoContext:
    """Explicit, declared overlay for axis classification.

    These flags are declared by the planner / orchestrator (they encode
    knowledge the action type alone cannot carry, e.g. "this input came from an
    untrusted web fetch" or "this payload is PII"). All default to ``False``
    (deny-by-default — an absent declaration never *adds* an axis).
    """

    untrusted_input: bool = False
    sensitive: bool = False
    declares_external_comm: bool = False

    @classmethod
    def from_step(cls, step: Step) -> RuleOfTwoContext:
        """Extract a context from ``Step.context`` (deny-by-default).

        Axis ① (``untrusted_input``) is the OR of two deterministic sources:

        * an **explicit** boolean ``True`` declaration, and
        * a **provenance-derived** taint: a ``provenance`` block
          naming an untrusted :class:`~secugent.core.provenance.TaintSource` (or a
          parent that was already tainted) auto-activates axis ① via
          :func:`~secugent.core.provenance.derive_taint`.

        The combination is monotone — explicit ``True`` wins and auto-taint can
        only ADD axis ①, never clear it (deny-by-default: an ambiguous/absent
        source can never turn an inherited taint off).

        Recognized shapes (only an explicit boolean ``True`` counts for the
        boolean flags — a truthy non-``True`` value is treated as ``False`` so an
        ambiguous/attacker-controlled value can never silently enable an axis):

        * a nested ``{"rule_of_two": {"untrusted_input": True, ...}}`` block, or
        * flat top-level keys ``untrusted_input`` / ``sensitive`` /
          ``declares_external_comm``;
        * a ``provenance`` block ``{"source": "web_fetch", "parent_tainted": bool}``
          either top-level or nested under ``rule_of_two`` (provenance producer).

        The boolean flags are **OR-combined** across the flat and nested
        locations, exactly like provenance taint: for each axis the flag is ON iff
        an explicit boolean ``True`` appears in *either* location. A nested
        ``False`` can therefore never clear a flat ``True`` (and vice-versa) —
        declarations can only ADD an axis, never drop a HITL-forcing one (I1
        monotonicity / I3 deny-by-default). Provenance taint is combined the same
        way: a ``provenance`` block may appear in *both* locations and the two are
        OR-combined (neither location can clear the other's taint).
        """
        flat = step.context
        nested = flat.get("rule_of_two")
        explicit_untrusted = _flag_declared(flat, nested, "untrusted_input")
        provenance_tainted = _provenance_taint(flat, nested)
        return cls(
            untrusted_input=explicit_untrusted or provenance_tainted,
            sensitive=_flag_declared(flat, nested, "sensitive"),
            declares_external_comm=_flag_declared(flat, nested, "declares_external_comm"),
        )


def _flag_declared(flat: dict[str, object], nested: object, key: str) -> bool:
    """OR-combine a boolean axis flag across the flat and nested locations.

    The flag is ON iff an explicit boolean ``True`` is declared in *either* the
    top-level context or the nested ``rule_of_two`` block (monotone, I1/I3): a
    nested ``False`` can never clear a flat ``True`` (and vice-versa), so a
    self-contradicting ``Step.context`` can only ADD a HITL-forcing axis, never
    drop one. Only an explicit ``is True`` counts — a truthy non-``True`` value is
    deny-by-default ``False`` so an ambiguous/attacker-controlled value can never
    silently enable an axis.
    """
    flat_flag = flat.get(key) is True
    nested_flag = isinstance(nested, dict) and nested.get(key) is True
    return flat_flag or nested_flag


def _parse_taint_source(value: object) -> TaintSource | None:
    """Map a provenance ``source`` value to a :class:`TaintSource`, else ``None``.

    Deny-by-default: an unknown / non-string source is ``None`` (ambiguous) — it
    can never *clear* an inherited taint (see :func:`provenance.derive_taint`), and
    on a clean parent it does not invent taint.
    """
    if isinstance(value, TaintSource):
        return value
    if isinstance(value, str):
        try:
            return TaintSource(value)
        except ValueError:
            return None
    return None


def _provenance_taint(flat: dict[str, object], nested: object) -> bool:
    """Deterministically derive axis-① taint from a ``provenance`` block.

    Looks for a ``provenance`` dict in **both** the top-level context and the
    ``rule_of_two`` nested block and **OR-combines** their derived taints. The two
    locations are purely additive (monotone, deny-by-default): the taint is the
    logical OR of ``derive_taint`` over each present block, so a clean / trusted
    provenance block in one location can **never** clear a genuine untrusted-input
    taint declared in the other (I1 monotonicity / I3 deny-by-default — an earlier
    bug let the nested block *replace* the flat one and silently drop an inherited
    taint). Each block reads ``source`` (a :class:`TaintSource` value) and
    ``parent_tainted`` (only an explicit boolean ``True`` counts — a truthy
    non-``True`` value is deny-by-default ``False``). A missing / non-dict
    provenance block in either location contributes ``False`` (no auto-taint), and
    with no provenance block at all the result is ``False``.
    """
    nested_block = nested.get("provenance") if isinstance(nested, dict) else None
    flat_taint = _block_taint(flat.get("provenance"))
    nested_taint = _block_taint(nested_block)
    return flat_taint or nested_taint


def _block_taint(block: object) -> bool:
    """Derive axis-① taint from a single ``provenance`` block (or ``False``).

    A missing / non-dict block contributes no taint. This is the per-location
    primitive that :func:`_provenance_taint` OR-combines across the flat and
    nested locations (so neither can clear the other's taint).
    """
    if not isinstance(block, dict):
        return False
    parent_tainted = block.get("parent_tainted") is True
    source = _parse_taint_source(block.get("source"))
    return derive_taint(parent_tainted, source)


def classify_axes(step: Step, context: RuleOfTwoContext | None = None) -> frozenset[Axis]:
    """Return the set of active Rule of Two axes for ``step`` (pure, deterministic).

    Same ``(step, context)`` always yields the same ``frozenset`` and never
    mutates the input. ``context=None`` is equivalent to an all-``False``
    :class:`RuleOfTwoContext`.
    """
    ctx = context if context is not None else RuleOfTwoContext()
    axes: set[Axis] = set()

    if step.action_type in _EXTERNAL_COMM_ACTIONS or ctx.declares_external_comm:
        axes.add(Axis.EXTERNAL_COMM)
    if step.action_type in _SENSITIVE_ACCESS_ACTIONS or ctx.sensitive:
        axes.add(Axis.SENSITIVE_ACCESS)
    # Axis ① is carried entirely by ``ctx.untrusted_input``, which is itself the OR
    # of an explicit declaration and a deterministic provenance-derived taint (see
    # ``RuleOfTwoContext.from_step``). The classifier logic here is unchanged: it
    # only reads the already-resolved boolean, so the axis②③ table stays intact.
    if ctx.untrusted_input:
        axes.add(Axis.UNTRUSTED_INPUT)

    return frozenset(axes)


def requires_hitl(axes: frozenset[Axis]) -> bool:
    """True iff all three axes are active — the Rule of Two HITL boundary.

    There are exactly three axes, so ``len(axes) >= 3`` is equivalent to all
    three being present (the boundary is at 3).
    """
    return len(axes) >= 3


def axes_to_audit(axes: frozenset[Axis]) -> list[str]:
    """Sorted, stable list of axis string values for the audit payload."""
    return sorted(axis.value for axis in axes)


def axes_for_steps(steps: Iterable[Step]) -> tuple[str, ...]:
    """Sorted, de-duplicated audit axis tokens for the union of axes over ``steps``.

    The value :class:`~secugent.core.contracts.ApprovalScope` stamps into
    its immutable ``rule_of_two_axes`` field at approval-creation time. It is the
    union of :func:`classify_axes` over each step (each combined with its own
    deterministic, provenance-derived :class:`RuleOfTwoContext` via
    :meth:`RuleOfTwoContext.from_step`), mapped through :func:`axes_to_audit`.

    Pure and deterministic: same ``steps`` (in any order) → identical tuple, with
    no wall-clock / uuid / I/O. An empty or wholly axis-free step set yields the
    empty tuple ``()`` — an honest "no axes", never a fabricated fill (INV-M4-4).
    """
    union: set[Axis] = set()
    for step in steps:
        union |= classify_axes(step, RuleOfTwoContext.from_step(step))
    return tuple(axes_to_audit(frozenset(union)))
