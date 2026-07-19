# SPDX-License-Identifier: Apache-2.0
"""Per-tenant REGULATIONS with base + override inheritance.

Directory layout::

    regulations/
        _base/active.json          (organisation-wide defaults)
        <tenant_id>/active.json    (tenant-specific full document)
        <tenant_id>/overrides.json (delta on top of base — additive only)

The override file may add rules / raise severity but MUST NOT relax existing
protections; doing so is rejected at load time with
:class:`RegulationsSchemaError` (fail-closed). PHASE 12 will harden this
further with hypothesis-based property tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from secugent.core.regulations import (
    BannedCommand,
    BannedPath,
    DataLabel,
    DomainPolicy,
    Regulations,
    RegulationsLoadError,
    load_regulations,
    load_regulations_from_dict,
)
from secugent.core.tenancy import TenantId
from secugent.tools.connectors.base import ConnectorPolicy

__all__ = [
    "RegulationsBundle",
    "RegulationsLoader",
    "RegulationsSchemaError",
    "default_packs_dir",
    "load_pack",
    "load_packs_from_dir",
    "merge_packs",
]


_SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class RegulationsSchemaError(Exception):
    """Raised when an override relaxes the base policy or is otherwise unsafe."""


@dataclass(frozen=True)
class RegulationsBundle:
    base: Regulations
    overrides: Regulations | None
    effective: Regulations


class RegulationsLoader:
    """Loads tenant-aware REGULATIONS bundles from disk."""

    def __init__(self, root: Path) -> None:
        self._root = root

    def load_base(self) -> Regulations:
        path = self._root / "_base" / "active.json"
        if not path.exists():
            raise RegulationsLoadError(f"missing base regulations at {path}")
        return load_regulations(path)

    def for_tenant(self, tenant_id: TenantId) -> RegulationsBundle:
        base = self.load_base()
        tenant_dir = self._root / str(tenant_id)
        override_path = tenant_dir / "overrides.json"
        active_path = tenant_dir / "active.json"
        if active_path.exists():
            # full-document override
            overrides = load_regulations(active_path)
        elif override_path.exists():
            data = json.loads(override_path.read_text(encoding="utf-8"))
            overrides = load_regulations_from_dict({**_default_root(base.version + "-override"), **data})
        else:
            overrides = None
        effective = self._merge(base, overrides)
        return RegulationsBundle(base=base, overrides=overrides, effective=effective)

    def for_run(
        self,
        *,
        run_id: str,
        tenant_id: TenantId,
        canary_payload: dict[str, object] | None = None,
        canary_share: float = 0.0,
    ) -> RegulationsBundle:
        """PHASE 12 — pick the canary bundle deterministically by ``run_id``.

        ``canary_payload`` is the *full* proposed Regulations dict. When the
        deterministic hash of ``run_id`` falls below ``canary_share`` (in
        ``[0, 1]``), the canary policy is returned merged on top of the
        tenant baseline (relaxation guard still applies). Otherwise the
        normal :meth:`for_tenant` bundle is returned.
        """
        # an activated canary (share > 0) with no payload is a
        # wiring bug — fail fast instead of silently masking it with the baseline.
        if canary_share > 0.0 and canary_payload is None:
            raise RegulationsLoadError(
                "for_run: canary_share > 0 but canary_payload is None — "
                "카나리 경로 활성화 시 canary_payload를 반드시 전달해야 합니다"
            )
        if canary_payload is None or canary_share <= 0.0:
            return self.for_tenant(tenant_id)
        import hashlib

        digest = hashlib.sha256(run_id.encode("utf-8")).digest()
        ratio = int.from_bytes(digest[:8], "big") / 2**64
        if ratio >= min(1.0, canary_share):
            return self.for_tenant(tenant_id)
        # SG-04: merge the canary on top of the tenant *effective* policy (base
        # + tenant overrides), not the bare organisation base. Otherwise a
        # canary run silently drops tenant-strengthened protections. The
        # relaxation guard in _merge still applies — now against the (stricter)
        # tenant baseline.
        tenant_bundle = self.for_tenant(tenant_id)
        canary_regs = load_regulations_from_dict(canary_payload)
        effective = self._merge(tenant_bundle.effective, canary_regs)
        return RegulationsBundle(base=tenant_bundle.base, overrides=canary_regs, effective=effective)

    # ------------------------------------------------------------------ #
    # Merge rules — additive-only, no relaxation
    # ------------------------------------------------------------------ #

    @classmethod
    def _merge(cls, base: Regulations, override: Regulations | None) -> Regulations:
        if override is None:
            return base

        merged_paths = {bp.rule_id: bp for bp in base.banned_paths}
        for op in override.banned_paths:
            old = merged_paths.get(op.rule_id)
            if old is not None:
                cls._reject_banned_path_relaxation(old, op)
            merged_paths[op.rule_id] = op

        merged_commands = {bc.rule_id: bc for bc in base.banned_commands}
        for oc in override.banned_commands:
            old_cmd = merged_commands.get(oc.rule_id)
            if old_cmd is not None:
                cls._reject_banned_command_relaxation(old_cmd, oc)
            merged_commands[oc.rule_id] = oc

        domain_policy = base.domain_policy
        if override.domain_policy is not None:
            cls._reject_domain_policy_relaxation(base.domain_policy, override.domain_policy)
            domain_policy = override.domain_policy

        data_labels = cls._merge_data_labels(base.data_labels, override.data_labels)

        connector_policies = cls._merge_connector_policies(
            base.connector_policies, override.connector_policies
        )

        # version = f"{base}+{override}" can exceed the schema's max_length=64 when
        # either token is long or many merges fold (for_tenant / for_run / merge_packs
        # all reach here). Bound BOTH tokens FIRST so ``Regulations(...)`` never raises
        # a RAW pydantic.ValidationError. Bounding lives
        # in ``_merge`` — the single source of truth for the composite version — so
        # every caller is protected, not just merge_packs. The bound is the identity
        # when the raw tokens already fit, so short-version checksums are unchanged.
        running_v, next_v = _bound_versions_for_merge(base.version, override.version)

        return Regulations(
            version=f"{running_v}+{next_v}",
            banned_paths=list(merged_paths.values()),
            domain_policy=domain_policy,
            banned_commands=list(merged_commands.values()),
            data_labels=data_labels,
            connector_policies=connector_policies,
        )

    # ------------------------------------------------------------------ #
    # data_labels — strengthen-only (mirrors banned_paths / banned_commands)
    # ------------------------------------------------------------------ #

    @classmethod
    def _merge_data_labels(cls, base: list[DataLabel], override: list[DataLabel]) -> list[DataLabel]:
        """Merge ``data_labels`` strengthen-only, keyed by ``rule_id``.

        Mirrors the ``banned_paths`` (:meth:`_merge` ``:139-145``) and
        ``banned_commands`` guards. For every ``rule_id`` present in ``base``:

        * ``merged.severity`` rank ``>=`` base — downgrade is rejected.
        * ``base.hard_block ⇒ merged.hard_block`` — removing ``hard_block`` is
          rejected.
        * ``allowed_actions`` may only *narrow* (override must be a subset of
          base). ``mechanical_oversight._match_data_label`` treats a non-empty
          ``allowed_actions`` as an *allowlist* (an action in it bypasses the
          violation), so a wider list is strictly more permissive; an empty list
          is the strictest (every action violates). Widening therefore loosens
          protection and is rejected. The direction is unambiguous, so the guard
          is applied here (conservative choice documented per spec §2.1).
        * ``path_patterns`` may only *widen* (override must be a **superset** of
          base). ``_match_data_label`` raises a violation only when one of
          ``label.path_patterns`` matches the normalised path, so MORE patterns
          ⇒ MORE protected paths ⇒ MORE protection. Removing any base pattern
          shrinks the protected scope (a silent deny-by-default relaxation:
          previously-blocked paths become allowed) and is rejected.
          Order and duplicates are ignored.

        ``rule_id``\\s absent from ``base`` are appended as new labels. The result
        is deterministic: base order is preserved (with in-place strengthening),
        then genuinely-new override labels follow in override order.
        """
        merged: dict[str, DataLabel] = {dl.rule_id: dl for dl in base}
        base_keys = list(merged.keys())
        appended: list[str] = []
        for ol in override:
            old = merged.get(ol.rule_id)
            if old is None:
                merged[ol.rule_id] = ol
                appended.append(ol.rule_id)
                continue
            cls._reject_data_label_relaxation(old, ol)
            merged[ol.rule_id] = ol
        ordered_keys = base_keys + [k for k in appended if k not in base_keys]
        return [merged[k] for k in ordered_keys]

    @staticmethod
    def _reject_data_label_relaxation(base: DataLabel, override: DataLabel) -> None:
        """Raise :class:`RegulationsSchemaError` if ``override`` relaxes ``base``."""
        if _SEVERITY_RANK[override.severity] < _SEVERITY_RANK[base.severity]:
            raise RegulationsSchemaError(
                f"data_label {base.rule_id!r} override severity={override.severity} "
                f"is weaker than base severity={base.severity}"
            )
        if base.hard_block and not override.hard_block:
            raise RegulationsSchemaError(f"data_label {base.rule_id!r} override disables hard_block")
        widened = [a for a in override.allowed_actions if a not in base.allowed_actions]
        if widened:
            raise RegulationsSchemaError(
                f"data_label {base.rule_id!r} override widens allowed_actions "
                f"{widened!r} (allowlist may only narrow; widening loosens protection)"
            )
        # path_patterns is the protected *scope*. More patterns =
        # more matched paths = more protection (see _match_data_label). An override
        # must be a superset of base; removing any pattern narrows protection and
        # is a deny-by-default relaxation. ``removed`` keeps base order for
        # deterministic error messages.
        override_patterns = set(override.path_patterns)
        removed = [p for p in base.path_patterns if p not in override_patterns]
        if removed:
            raise RegulationsSchemaError(
                f"data_label {base.rule_id!r} override removes path_patterns "
                f"{removed!r} (narrowing the protected scope loosens protection)"
            )

    # ------------------------------------------------------------------ #
    # banned_paths / banned_commands / domain_policy — strengthen-only
    #
    # a same-``rule_id`` override
    # previously replaced a banned_path / banned_command wholesale after only
    # checking severity-downgrade and hard_block-removal. The mechanical_oversight
    # matcher decides a HARD BLOCK from ``pattern`` (both) and ``actions``
    # (banned_path), so an override carrying the SAME rule_id/severity/hard_block
    # but a narrower ``pattern`` / narrowed ``actions`` silently weakened the base
    # control (deny-by-default bypass). These guards close that hole, mirroring
    # :meth:`_reject_data_label_relaxation` and ``_union_or_reject``.
    # ------------------------------------------------------------------ #

    @staticmethod
    def _reject_banned_path_relaxation(base: BannedPath, override: BannedPath) -> None:
        """Raise if a same-rule_id ``banned_path`` override relaxes ``base``.

        Dimensions the matcher uses (``mechanical_oversight._match_banned_path``):

        * ``severity`` — rank must not drop.
        * ``hard_block`` — must not be removed.
        * ``pattern`` — drives the glob match. A regex/glob superset is
          undecidable, so any change is rejected; widening coverage requires a
          NEW rule_id (fail-closed, conservative).
        * ``actions`` — an EMPTY list matches every action (strictest). A
          non-empty list scopes the rule to those actions only. So an empty base
          must stay empty, and a non-empty base may only be widened (override
          ⊇ base) or emptied; narrowing/dropping an action loosens coverage.
        """
        if _SEVERITY_RANK[override.severity] < _SEVERITY_RANK[base.severity]:
            raise RegulationsSchemaError(
                f"banned_path {base.rule_id!r} override severity={override.severity} "
                f"is weaker than base severity={base.severity}"
            )
        if base.hard_block and not override.hard_block:
            raise RegulationsSchemaError(f"banned_path {base.rule_id!r} override disables hard_block")
        if override.pattern != base.pattern:
            raise RegulationsSchemaError(
                f"banned_path {base.rule_id!r} override changes pattern "
                f"{base.pattern!r}->{override.pattern!r} (coverage change must use a new rule_id)"
            )
        RegulationsLoader._reject_action_scope_narrowing(
            "banned_path", base.rule_id, list(base.actions), list(override.actions)
        )

    @staticmethod
    def _reject_action_scope_narrowing(
        category: str, rule_id: str, base_actions: list[Any], override_actions: list[Any]
    ) -> None:
        """Reject narrowing the action scope of a rule (empty = all = strictest)."""
        if not base_actions:
            # Base blocks ALL actions — override must keep blocking all (empty).
            if override_actions:
                raise RegulationsSchemaError(
                    f"{category} {rule_id!r} override narrows actions to {override_actions!r} "
                    f"(base blocks all actions; scoping to a subset loosens protection)"
                )
            return
        # Base is scoped — override must keep blocking all (empty) or be a superset.
        if override_actions:
            dropped = [a for a in base_actions if a not in set(override_actions)]
            if dropped:
                raise RegulationsSchemaError(
                    f"{category} {rule_id!r} override drops actions {dropped!r} "
                    f"(narrowing the blocked-action set loosens protection)"
                )

    @staticmethod
    def _reject_banned_command_relaxation(base: BannedCommand, override: BannedCommand) -> None:
        """Raise if a same-rule_id ``banned_command`` override relaxes ``base``.

        The matcher (``_match_banned_command``) decides a HARD BLOCK purely from
        the regex ``pattern``. Regex-superset is undecidable, so any ``pattern``
        change is rejected (widening must use a new rule_id). Severity-downgrade
        and hard_block-removal are also rejected.
        """
        if _SEVERITY_RANK[override.severity] < _SEVERITY_RANK[base.severity]:
            raise RegulationsSchemaError(
                f"banned_command {base.rule_id!r} override severity={override.severity} "
                f"is weaker than base severity={base.severity}"
            )
        if base.hard_block and not override.hard_block:
            raise RegulationsSchemaError(f"banned_command {base.rule_id!r} override disables hard_block")
        if override.pattern != base.pattern:
            raise RegulationsSchemaError(
                f"banned_command {base.rule_id!r} override changes pattern "
                f"{base.pattern!r}->{override.pattern!r} (coverage change must use a new rule_id)"
            )

    @staticmethod
    def _reject_domain_policy_relaxation(base: DomainPolicy | None, override: DomainPolicy) -> None:
        """Raise if ``override`` relaxes the ``domain_policy`` (matcher-aware).

        ``_match_domain`` consults EVERY field below, so the guard must too —
        overlooking one (e.g. ``allow_subdomains``) re-opens a
        deny-by-default hole.

        * ``mode``: a change between ``allow_list`` and ``deny_list`` inverts the
          block predicate. ``deny_list -> allow_list`` is trivially relaxing when
          the new allowlist contains a formerly-denied host, and the general case
          is undecidable. So ANY mode change is rejected fail-closed —
          a coverage/mode change must use an
          explicit operator-reviewed full document, not a strengthen-only merge.
        * ``allow_list`` mode: a host is blocked unless it is in ``domains``.
          ADDING a domain widens what is permitted = relaxation (reject). Removing
          a domain tightens the allowlist = strengthening (allowed).
        * ``deny_list`` mode: a host is blocked when it is in ``domains``.
          REMOVING a domain shrinks the blocked set = relaxation (reject).
        * ``allow_subdomains`` (``_domain_matches`` ``host.endswith('.'+entry)``):
          in ``deny_list`` mode it EXPANDS the matched/blocked set, so True->False
          un-blocks subdomains of every denied host = relaxation (reject). In
          ``allow_list`` mode it EXPANDS the permitted set, so False->True permits
          subdomains of every allowlisted host = relaxation (reject). (Because any
          mode change is already rejected above, both modes here are equal.)
        * ``block_ip_literal`` / ``block_punycode`` / ``hard_block``: turning any
          off loosens protection (reject).

        With no base policy, an override only ADDS a control and cannot relax.
        """
        if base is None:
            return
        if base.hard_block and not override.hard_block:
            raise RegulationsSchemaError("override disables domain_policy.hard_block")
        if base.mode != override.mode:
            raise RegulationsSchemaError(
                f"override switches domain_policy.mode from {base.mode} to {override.mode} "
                f"(a mode change cannot be proven non-relaxing - use an explicit full document)"
            )
        if base.block_ip_literal and not override.block_ip_literal:
            raise RegulationsSchemaError("override disables domain_policy.block_ip_literal")
        if base.block_punycode and not override.block_punycode:
            raise RegulationsSchemaError("override disables domain_policy.block_punycode")
        # allow_subdomains — mode is identical here (mode change already rejected).
        if base.mode == "deny_list" and base.allow_subdomains and not override.allow_subdomains:
            raise RegulationsSchemaError(
                "override disables domain_policy.allow_subdomains in deny_list mode "
                "(subdomains of denied hosts become reachable = relaxation)"
            )
        if base.mode == "allow_list" and override.allow_subdomains and not base.allow_subdomains:
            raise RegulationsSchemaError(
                "override enables domain_policy.allow_subdomains in allow_list mode "
                "(subdomains of allowlisted hosts become permitted = relaxation)"
            )
        if base.mode == "allow_list":
            base_domains = set(base.domains)
            added = [d for d in override.domains if d not in base_domains]
            if added:
                raise RegulationsSchemaError(
                    f"override widens domain_policy allow_list by adding {added!r} "
                    f"(a wider allowlist permits more hosts = relaxation)"
                )
        if base.mode == "deny_list":
            override_domains = set(override.domains)
            removed = [d for d in base.domains if d not in override_domains]
            if removed:
                raise RegulationsSchemaError(
                    f"override shrinks domain_policy deny_list by removing {removed!r} "
                    f"(a smaller deny_list blocks fewer hosts = relaxation)"
                )

    # ------------------------------------------------------------------ #
    # connector_policies — strengthen-only (additive allowlists)
    # ------------------------------------------------------------------ #

    @classmethod
    def _merge_connector_policies(
        cls,
        base: dict[str, ConnectorPolicy],
        override: dict[str, ConnectorPolicy],
    ) -> dict[str, ConnectorPolicy]:
        """Merge per-connector policies, rejecting any relaxation (fail-closed).

        Strengthen-only rules per connector:

        * A connector absent from ``base`` may be *added* by the override.
        * Every allowlist field (channels / workspace / database / project /
          transitions / redact_patterns) in the override MUST be a **superset**
          of the base list — adding entries strengthens (a wider redact set is
          stricter, a wider allowlist is a deliberate operator expansion that is
          still recorded explicitly); *removing* an entry (a proper subset)
          shrinks protection and is rejected with :class:`RegulationsSchemaError`.
        * ``rate_limit_per_sec`` may only be *lowered* (stricter); raising it
          loosens the throttle and is rejected.

        The merged list is deterministic: base order is preserved, then any
        genuinely-new override entries are appended in override order.
        """
        merged: dict[str, ConnectorPolicy] = dict(base)
        for name, op in override.items():
            bp = base.get(name)
            if bp is None:
                merged[name] = op
                continue
            merged[name] = cls._strengthen_policy(name, bp, op)
        return merged

    @classmethod
    def _strengthen_policy(
        cls, name: str, base: ConnectorPolicy, override: ConnectorPolicy
    ) -> ConnectorPolicy:
        if override.rate_limit_per_sec > base.rate_limit_per_sec:
            raise RegulationsSchemaError(
                f"connector_policy {name!r} override rate_limit_per_sec="
                f"{override.rate_limit_per_sec} loosens base={base.rate_limit_per_sec}"
            )
        list_fields = (
            "allowed_channels",
            "redact_patterns",
            "allowed_workspace_ids",
            "allowed_database_ids",
            "allowed_projects",
            "allowed_transitions",
        )
        merged_lists: dict[str, list[str]] = {}
        for field in list_fields:
            base_list: list[str] = getattr(base, field)
            override_list: list[str] = getattr(override, field)
            merged_lists[field] = cls._union_or_reject(name, field, base_list, override_list)
        return base.model_copy(update={**merged_lists, "rate_limit_per_sec": override.rate_limit_per_sec})

    @staticmethod
    def _union_or_reject(name: str, field: str, base_list: list[str], override_list: list[str]) -> list[str]:
        """Return base ∪ override (base order + new entries) or reject a removal."""
        override_set = set(override_list)
        dropped = [entry for entry in base_list if entry not in override_set]
        if dropped:
            raise RegulationsSchemaError(
                f"connector_policy {name!r} override removes {field} entries "
                f"{dropped!r} (allowlist may not shrink)"
            )
        merged = list(base_list)
        for entry in override_list:
            if entry not in base_list:
                merged.append(entry)
        return merged


def _default_root(version: str) -> dict[str, Any]:
    return {
        "version": version,
        "banned_paths": [],
        "banned_commands": [],
        "data_labels": [],
    }


# --------------------------------------------------------------------------- #
# Korean policy packs — YAML pack loading + strengthen-only merge
# --------------------------------------------------------------------------- #
#
# A *pack* is a ready-to-apply REGULATIONS template shipped under
# ``secugent/regulations/packs/`` as a YAML document conforming to the EXISTING
# :class:`~secugent.core.regulations.Regulations` schema (no new fields). Packs
# are merged onto an organisation/tenant base with the SAME strengthen-only
# :meth:`RegulationsLoader._merge` used by ``for_tenant`` / ``for_run`` — the
# merge logic is reused verbatim, never re-implemented (single source of truth).


def default_packs_dir() -> Path:
    """Return the directory holding the bundled Korean policy packs.

    Resolved relative to this module so it works from any working directory and
    inside an installed wheel (air-gapped / closed-network first).
    """
    return Path(__file__).resolve().parent / "packs"


def load_pack(path: str | Path) -> Regulations:
    """Load a single REGULATIONS *pack* (YAML) into a validated ``Regulations``.

    Reuses :func:`load_regulations_from_dict` for schema validation so packs are
    held to the exact same contract as JSON regulations. Any read / parse /
    schema failure is surfaced as :class:`RegulationsLoadError` (fail-closed):
    the caller must NOT apply a pack it could not fully validate.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegulationsLoadError(f"cannot read regulations pack {p}: {exc}") from exc
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise RegulationsLoadError(f"regulations pack {p} is not valid YAML: {exc}") from exc
    if data is None:
        raise RegulationsLoadError(f"regulations pack {p} is empty")
    return load_regulations_from_dict(data, source=str(p))


def load_packs_from_dir(directory: str | Path) -> list[Regulations]:
    """Load every ``*.yaml`` pack in ``directory`` in deterministic filename order.

    An empty directory (no YAML files) yields ``[]`` — the identity element for
    a multi-pack union. A missing directory is a wiring error and raises
    :class:`RegulationsLoadError` (fail-closed). README files and non-YAML
    artefacts are ignored.
    """
    d = Path(directory)
    if not d.is_dir():
        raise RegulationsLoadError(f"packs directory not found: {d}")
    pack_paths = sorted(p for p in d.iterdir() if p.suffix.lower() in (".yaml", ".yml"))
    return [load_pack(p) for p in pack_paths]


def merge_packs(base: Regulations, packs: list[Regulations]) -> Regulations:
    """Fold ``packs`` onto ``base`` with the strengthen-only merge (union of controls).

    Each pack is merged via :meth:`RegulationsLoader._merge`, so:

    * the result is a SUPERSET of ``base`` controls (merge only strengthens);
    * any relaxation (data-label severity downgrade, ``hard_block`` removal,
      ``allowed_actions`` widening, ``path_patterns`` narrowing, domain
      allow→deny switch) is rejected with :class:`RegulationsSchemaError`;
    * the order is deterministic (base order preserved, new controls appended in
      pack order), so an identical ``(base, packs)`` yields an identical
      :meth:`Regulations.checksum`.

    An empty ``packs`` list returns ``base`` unchanged (identity).

    The composite version never overflows the schema's ``max_length=64``: the
    version-bounding now lives inside :meth:`RegulationsLoader._merge` (the single
    source of truth for the merged version label), so ``merge_packs`` simply folds
    each pack through ``_merge`` and the same protection covers ``for_tenant`` /
    ``for_run``. Controls are untouched.
    """
    effective = base
    for pack in packs:
        effective = RegulationsLoader._merge(effective, pack)
    return effective


# Schema cap on ``Regulations.version`` (mirrors regulations.py Field max_length).
_VERSION_MAX_LEN = 64
# Fixed-width stable token: a single char tag + '~' + 16 hex of a SHA-256 prefix.
_DIGEST_HEX_LEN = 16
_BOUNDED_TOKEN_LEN = 1 + 1 + _DIGEST_HEX_LEN  # e.g. "b~0123456789abcdef" → 18


def _stable_short_token(value: str) -> str:
    """Map ``value`` to a fixed-width (18-char) deterministic token.

    ``<first-char-or-'x'>~<16-hex SHA-256 prefix>``. A given string always maps
    to the same token, so a fixed ``(base, packs)`` sequence yields a
    deterministic ``checksum``. Width is bounded and < 64.
    """
    import hashlib

    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:_DIGEST_HEX_LEN]
    head = value[0] if value else "x"
    return f"{head}~{digest}"


def _bound_versions_for_merge(running: str, next_version: str) -> tuple[str, str]:
    """Return ``(running, next)`` labels whose ``running+'+'+next`` fits in 64 chars.

    Guarantees ``len(out_running) + 1 + len(out_next) <= _VERSION_MAX_LEN`` for ANY
    schema-valid inputs (each ``<= 64``). The composite is built from at most one
    raw token plus one fixed-width hash token, so it never exceeds the bound:

    * If both raw tokens already fit (``len+1+len <= 64``) they are returned as-is.
    * Otherwise ``running`` is replaced with its 18-char stable hash token. If
      ``next_version`` still cannot fit beside an 18-char running token
      (``next_version >= 64 - 18 - 1 = 45`` chars), ``next_version`` is ALSO
      replaced with its 18-char token, yielding a worst case of ``18+1+18 = 37``.

    Deterministic: identical inputs → identical outputs (pure function of the two
    strings), so the merged ``checksum`` is stable across runs (finding 3/4/7/8).
    """
    if len(running) + 1 + len(next_version) <= _VERSION_MAX_LEN:
        return running, next_version
    bounded_running = _stable_short_token(running)
    if len(bounded_running) + 1 + len(next_version) <= _VERSION_MAX_LEN:
        return bounded_running, next_version
    # next_version itself is too long to sit beside even a hashed running token.
    bounded_next = _stable_short_token(next_version)
    return bounded_running, bounded_next
