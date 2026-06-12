# SPDX-License-Identifier: Apache-2.0
"""Deterministic Mechanical Oversight engine.

Per Flowcharts §7 and SECURITY_CONTRACT §8, this module is the **first gate**
every step must pass. It runs *before* RISKANALYZER, applies pattern matching
against ``REGULATIONS.json``, and raises :class:`HardBlockException` on
explicit violations so the LLM-based stages can never "score down" a clearly
forbidden action.

Bypass defenses (master prompt PHASE 1 §3 DoD):

* ``..`` traversal → resolved before match
* UNC paths (``\\\\server\\share\\...``) → recognised, matched verbatim
* Windows 8.3 short paths (``PROGRA~1``) → refused as non-normalisable
* Case variations on Windows-style paths → lowercased before match
* Environment variables (``%USERPROFILE%``) → refused as non-deterministic
* Punycode domains → decoded; configurable to block punycode entirely
* Subdomain probing → matched against the policy's ``allow_subdomains`` flag
* IP-literal direct access → blocked when ``block_ip_literal=True``
* HTTP redirects to other domains → out of scope here; SUB router enforces

All "cannot normalise" paths fail closed (treated as a banned-path violation
with category ``normalization``).
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from secugent.core.contracts import (
    ActionType,
    HardBlockException,
    SessionRegulationPatch,
    Step,
    Violation,
)
from secugent.core.regulations import BannedCommand, Regulations
from secugent.core.regulations import DataLabel as RegDataLabel
from secugent.core.sec.effects import Effect
from secugent.core.sec.labels import DataLabel
from secugent.core.sec.policy import CompiledPolicy, Decision

__all__ = [
    "OversightEngine",
    "OversightResult",
    "NormalizationError",
]


# ---------------------------------------------------------------------------
# Output / errors
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OversightResult:
    """Return type of :meth:`OversightEngine.evaluate`."""

    allowed: bool
    violation: Violation | None = None
    hard_block: bool = False

    def raise_if_blocked(self) -> None:
        if self.hard_block and self.violation is not None:
            raise HardBlockException(self.violation)


class NormalizationError(ValueError):
    """Raised when a target/command cannot be safely normalised."""


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------

# 8.3 short-name token like FOO~1, BAR~12
_SHORT_NAME_RE = re.compile(r"~\d")
# `%VAR%` or `$VAR` environment-variable expansion is refused as
# non-deterministic. Defenders should resolve before submitting.
_ENV_VAR_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")


def normalize_path(target: str) -> str:
    """Normalize a file path defensively.

    Returns a forward-slash, lowercase representation suitable for glob match.
    Raises :class:`NormalizationError` when the path contains a construct that
    we refuse to evaluate (8.3 short names, environment expansions, NUL).
    """
    if not isinstance(target, str) or not target:
        raise NormalizationError("path must be a non-empty string")
    if "\x00" in target:
        raise NormalizationError("path contains NUL byte")
    if _ENV_VAR_RE.search(target):
        raise NormalizationError("path contains environment-variable expansion")
    if _SHORT_NAME_RE.search(target):
        raise NormalizationError("path contains 8.3 short-name token (e.g., FOO~1)")

    # Detect UNC before forward-slash normalization (so '\\srv' stays distinct).
    is_unc = target.startswith("\\\\") or target.startswith("//")

    # Unify separators
    unified = target.replace("\\", "/")
    # Collapse repeated slashes (preserve a single leading // for UNC)
    if is_unc:
        prefix = "//"
        rest = unified.lstrip("/")
        unified = prefix + re.sub(r"/+", "/", rest)
    else:
        unified = re.sub(r"/+", "/", unified)

    # Resolve `..` and `.` segments without touching the filesystem.
    parts: list[str] = []
    segments = unified.split("/")
    leading_root = ""
    idx_start = 0
    if is_unc:
        leading_root = "//"
        idx_start = 2  # skip the two empty parts from '//'
    elif unified.startswith("/"):
        leading_root = "/"
        idx_start = 1
    elif len(segments) > 0 and re.fullmatch(r"[A-Za-z]:", segments[0]):
        # Windows drive letter, e.g. "C:"
        leading_root = segments[0].lower() + "/"
        idx_start = 1
        if len(segments) > 1 and segments[1] == "":
            idx_start = 2

    for seg in segments[idx_start:]:
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            # else: silently anchor at root; never escape
            continue
        parts.append(seg)

    normalised = leading_root + "/".join(parts)
    # Lowercase the whole thing — Windows file matching is case-insensitive
    # and many of our defensive globs assume lower-case.
    return normalised.lower()


# ---------------------------------------------------------------------------
# Domain normalisation
# ---------------------------------------------------------------------------


def normalize_domain(raw: str) -> tuple[str, bool]:
    """Return (canonical domain, is_ip_literal).

    Raises :class:`NormalizationError` on malformed inputs.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise NormalizationError("domain must be a non-empty string")
    # Allow either a URL or a bare hostname.
    candidate = raw.strip()
    if "://" in candidate:
        try:
            parsed = urlsplit(candidate)
        except ValueError as exc:
            raise NormalizationError(f"invalid URL: {exc}") from exc
        host = parsed.hostname or ""
    else:
        host = candidate.split("/", 1)[0]

    host = host.strip().rstrip(".")
    if not host:
        raise NormalizationError("empty host in URL")
    # Strip user-info if present
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    # Strip port
    if host.startswith("["):
        # IPv6 literal in brackets — keep as-is
        pass
    elif ":" in host:
        host = host.rsplit(":", 1)[0]

    # IP literal?
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host.lower(), True
    except ValueError:
        pass

    # IDN: encode to ASCII (punycode) so we can detect both forms.
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError) as exc:
        raise NormalizationError(f"invalid IDN: {exc}") from exc

    return ascii_host.lower(), False


# ---------------------------------------------------------------------------
# Command normalisation
# ---------------------------------------------------------------------------


def normalize_command(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise NormalizationError("command must be a non-empty string")
    # Collapse whitespace.
    out = re.sub(r"\s+", " ", raw).strip()
    return out


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class OversightEngine:
    """Deterministic evaluator. Construct once per Regulations version.

    Evaluation is a pure function of (base regulations, session patches, step):
    same input → same output. The only mutable state is the session-patch list,
    appended by STEER via :meth:`add_session_patch`. Because G-H4 routes STEER
    writes to the SAME live per-run engine the SUB workers read, that list is
    accessed concurrently: writes swap it copy-on-write under ``_patches_lock``
    and matcher reads take a lock-free per-evaluation snapshot, so a STEER write
    is serialised, never tearing an in-flight evaluation (SG-20260606-10).
    """

    def __init__(
        self,
        regulations: Regulations,
        *,
        session_patches: list[SessionRegulationPatch] | None = None,
        compiled_policy: CompiledPolicy | None = None,
    ) -> None:
        self._regs = regulations
        # ``_patches`` is rebound copy-on-write (never mutated in place). Writers
        # (STEER ``add_session_patch``, running on its own ``asyncio.to_thread``)
        # take ``_patches_lock`` and swap in a fresh list; readers (SUB workers in
        # the Dispatcher ``ThreadPoolExecutor``) take a lock-free local snapshot of
        # the attribute reference at matcher entry. The attribute rebind is atomic
        # in CPython, so a concurrent write can never tear an in-flight evaluation
        # (SG-20260606-10).
        self._patches: list[SessionRegulationPatch] = list(session_patches or [])
        self._patches_lock = threading.Lock()
        # EM-03: signed, compiled egress policy (consumed by the EM-05 broker via
        # ``evaluate_effect``). None ⇒ deny-by-default for the effect surface; the
        # legacy ``evaluate(step)`` path is unaffected either way.
        self._compiled_policy = compiled_policy

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    @property
    def regulations(self) -> Regulations:
        """The (immutable) base Regulations this engine evaluates against.

        Read-only accessor used by the per-run wiring (G-H4) to stamp the
        effective ``version`` onto audit events without reaching into the
        private ``_regs`` field. Session patches are layered on top at evaluate
        time and are intentionally NOT reflected here.
        """
        return self._regs

    def add_session_patch(self, patch: SessionRegulationPatch) -> None:
        """Add a session-scoped patch (copy-on-write, thread-safe).

        Patches add additional banned paths/commands but never relax the base
        regulations. Used by STEER (PHASE 6).

        STEER may call this from a different thread than the SUB workers that are
        concurrently reading ``_patches`` (G-H4 routes the write to the live
        per-run engine the workers evaluate against). We therefore build a NEW
        list under ``_patches_lock`` and atomically rebind ``self._patches`` —
        never mutate the existing list in place. The lock only serialises
        concurrent writers (so no two appends lose each other); readers stay
        lock-free and always observe a consistent, length-stable snapshot
        (SG-20260606-10). Determinism is unaffected — single input still yields a
        single output; the lock merely orders concurrent writes.
        """
        with self._patches_lock:
            self._patches = [*self._patches, patch]

    def evaluate(self, step: Step) -> OversightResult:
        """Evaluate ``step`` against regulations + session patches.

        On hard-block returns an :class:`OversightResult` with
        ``hard_block=True``; the caller should invoke
        :meth:`OversightResult.raise_if_blocked` or propagate the result.
        """
        action = step.action_type
        if action == "unknown":
            return _violation(
                rule_id="unknown-action",
                category="unknown_action",
                message=f"unknown action_type for step {step.id}",
            )

        # 1. Path-based rules (file_read/file_write/desktop)
        if action in ("file_read", "file_write", "desktop") and step.target is not None:
            try:
                normalised = normalize_path(step.target)
            except NormalizationError as exc:
                return _violation(
                    rule_id="path-normalisation",
                    category="normalization",
                    message=str(exc),
                )
            hit = self._match_banned_path(normalised, action)
            if hit is not None:
                return hit
            label_hit = self._match_data_label(normalised, action)
            if label_hit is not None:
                return label_hit

        # 2. Domain-based rules (http_get)
        if action == "http_get" and step.target is not None:
            try:
                host, is_ip = normalize_domain(step.target)
            except NormalizationError as exc:
                return _violation(
                    rule_id="domain-normalisation",
                    category="normalization",
                    message=str(exc),
                )
            hit = self._match_domain(host, is_ip)
            if hit is not None:
                return hit

        # 3. Command-based rules (any action with a command attached)
        if step.command:
            try:
                cmd = normalize_command(step.command)
            except NormalizationError as exc:
                return _violation(
                    rule_id="command-normalisation",
                    category="normalization",
                    message=str(exc),
                )
            hit = self._match_banned_command(cmd)
            if hit is not None:
                return hit

        return OversightResult(allowed=True, violation=None, hard_block=False)

    def evaluate_effect(self, effect: Effect, label: DataLabel) -> Decision:
        """Evaluate a normalized :class:`Effect` against the signed, compiled
        policy (EM-03). Deny-by-default when no policy is loaded.

        This is the surface the EM-05 egress broker calls; the legacy
        Step-based :meth:`evaluate` is intentionally left unchanged.
        """
        if self._compiled_policy is None:
            return Decision(outcome="deny", rule_id=None, rationale="no_compiled_policy:deny_by_default")
        return self._compiled_policy.evaluate(effect, label)

    # ------------------------------------------------------------------ #
    # Matchers
    # ------------------------------------------------------------------ #

    def _match_banned_path(self, normalised: str, action: ActionType) -> OversightResult | None:
        candidates: list[BannedPathLike] = [
            _BannedPathLike.from_regulation(b) for b in self._regs.banned_paths
        ]
        # Single atomic read of the COW-swapped attribute → consistent, length-
        # stable snapshot for this evaluation even if STEER swaps in a new list
        # concurrently (SG-20260606-10). Never re-reference ``self._patches`` below.
        patches = self._patches
        for patch in patches:
            for rule in patch.rules:
                if rule.get("category") == "banned_path":
                    candidates.append(_BannedPathLike.from_dict(rule))

        for cand in candidates:
            if cand.actions and action not in cand.actions:
                continue
            if _glob_match(cand.pattern, normalised):
                return _violation(
                    rule_id=cand.rule_id,
                    category="banned_path",
                    message=f"banned path matched: {cand.pattern} (target={normalised})",
                    severity=cand.severity,
                    hard_block=cand.hard_block,
                )
        return None

    def _match_data_label(self, normalised: str, action: ActionType) -> OversightResult | None:
        """Evaluate all data labels against *normalised* path + *action*.

        Collect every label whose path_patterns match, classify each as
        "allow" or "deny", then apply **deny-overrides**: if any matching
        label denies the action, return the *most-severe* deny label chosen
        by a deterministic total order that is independent of list position:

          1. hard_block=True  before  hard_block=False
          2. higher severity  before  lower  (critical > high > medium > low)
          3. rule_id ascending  (lexicographic tiebreak)

        Single-label behaviour is unchanged: one allow → None, one deny →
        that violation.  Only the multi-match deny-overrides path is new.
        """
        deny_labels: list[RegDataLabel] = []
        any_match = False

        for label in self._regs.data_labels:
            for pattern in label.path_patterns:
                if _glob_match(pattern.lower(), normalised):
                    any_match = True
                    if label.allowed_actions and action in label.allowed_actions:
                        # This label allows the action — note it but keep scanning.
                        pass
                    else:
                        deny_labels.append(label)
                    break  # one matching pattern per label is enough

        if not any_match:
            return None  # no label matched the path at all

        if not deny_labels:
            return None  # every matching label allows this action

        # deny-overrides: pick the most-severe deny deterministically.
        winner = _pick_strongest_deny(deny_labels)
        return _violation(
            rule_id=winner.rule_id,
            category="data_label",
            message=(f"data label '{winner.label}' forbids action '{action}' on {normalised}"),
            severity=winner.severity,
            hard_block=winner.hard_block,
        )

    def _match_domain(self, host: str, is_ip: bool) -> OversightResult | None:
        policy = self._regs.domain_policy
        if policy is None:
            return None
        if is_ip and policy.block_ip_literal:
            return _violation(
                rule_id=policy.rule_id,
                category="domain_policy",
                message=f"IP-literal access blocked: {host}",
                hard_block=policy.hard_block,
            )

        # If the host is punycode and policy blocks it, refuse.
        if policy.block_punycode and "xn--" in host:
            return _violation(
                rule_id=policy.rule_id,
                category="domain_policy",
                message=f"punycode host blocked: {host}",
                hard_block=policy.hard_block,
            )

        matched = _domain_matches(host, policy.domains, policy.allow_subdomains)
        if policy.mode == "allow_list":
            if not matched:
                return _violation(
                    rule_id=policy.rule_id,
                    category="domain_policy",
                    message=f"host {host} not in allow-list",
                    hard_block=policy.hard_block,
                )
            return None
        # deny_list
        if matched:
            return _violation(
                rule_id=policy.rule_id,
                category="domain_policy",
                message=f"host {host} matched deny-list",
                hard_block=policy.hard_block,
            )
        return None

    def _match_banned_command(self, cmd: str) -> OversightResult | None:
        all_rules: list[BannedCommand] = list(self._regs.banned_commands)
        # Single atomic read of the COW-swapped attribute → consistent snapshot
        # (see ``_match_banned_path``); never re-reference ``self._patches`` below.
        patches = self._patches
        for patch in patches:
            for rule in patch.rules:
                if rule.get("category") == "banned_command":
                    all_rules.append(_make_banned_command_from_rule(rule))
        for cmd_rule in all_rules:
            try:
                if re.search(cmd_rule.pattern, cmd, flags=re.IGNORECASE):
                    return _violation(
                        rule_id=cmd_rule.rule_id,
                        category="banned_command",
                        message=f"banned command matched: {cmd_rule.pattern}",
                        severity=cmd_rule.severity,
                        hard_block=cmd_rule.hard_block,
                    )
            except re.error:
                return _violation(
                    rule_id=cmd_rule.rule_id,
                    category="schema",
                    message=f"invalid command regex in rule {cmd_rule.rule_id}",
                )
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _violation(
    *,
    rule_id: str,
    category: str,
    message: str,
    severity: str = "high",
    hard_block: bool = True,
) -> OversightResult:
    v = Violation(
        rule_id=rule_id,
        category=category,
        message=message,
        severity=severity,
        hard_block=hard_block,
    )
    return OversightResult(allowed=False, violation=v, hard_block=hard_block)


def _glob_match(pattern: str, target: str) -> bool:
    # All comparisons happen on already-normalised, lower-case paths.
    return fnmatch.fnmatchcase(target, pattern.lower())


# Severity ranks used for deterministic "strongest deny" selection.
# Higher rank = more severe.  Must match secugent.regulations.tenant_loader.
_SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _pick_strongest_deny(deny_labels: list[RegDataLabel]) -> RegDataLabel:
    """Return the most-severe deny label from *deny_labels* using a total order
    that is independent of list position:

      1. hard_block=True  >  hard_block=False
      2. higher severity  >  lower severity  (critical > high > medium > low)
      3. rule_id ascending  (lexicographic tiebreak for equal rank)

    The input must be non-empty (caller's responsibility).
    """

    def _key(lbl: RegDataLabel) -> tuple[int, int, str]:
        hard = 1 if lbl.hard_block else 0
        sev = _SEVERITY_RANK.get(lbl.severity, 0)
        return (hard, sev, lbl.rule_id)

    # We want: hard_block desc, severity desc, rule_id asc.
    best = deny_labels[0]
    for lbl in deny_labels[1:]:
        kb = _key(best)
        kl = _key(lbl)
        # Compare (hard desc, sev desc): higher numeric value is stronger.
        if (kl[0], kl[1]) > (kb[0], kb[1]):
            best = lbl
        elif (kl[0], kl[1]) == (kb[0], kb[1]) and kl[2] < kb[2]:
            # Same hard+sev: pick lexicographically smaller rule_id.
            best = lbl
    return best


def _domain_matches(host: str, domains: list[str], allow_subdomains: bool) -> bool:
    host = host.lower()
    for entry in domains:
        if entry.startswith("*."):
            base = entry[2:]
            if host == base or host.endswith("." + base):
                return True
            continue
        if host == entry:
            return True
        if allow_subdomains and host.endswith("." + entry):
            return True
    return False


# ---------------------------------------------------------------------------
# Internal: unified rule view
# ---------------------------------------------------------------------------


@dataclass
class _BannedPathLike:
    rule_id: str
    pattern: str
    actions: list[ActionType]
    severity: str
    hard_block: bool

    @classmethod
    def from_regulation(cls, b: object) -> _BannedPathLike:
        from secugent.core.regulations import BannedPath as _BP

        assert isinstance(b, _BP)
        return cls(
            rule_id=b.rule_id,
            pattern=b.pattern,
            actions=list(b.actions),
            severity=b.severity,
            hard_block=b.hard_block,
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> _BannedPathLike:
        return cls(
            rule_id=str(d.get("rule_id", "patch-path")),
            pattern=str(d["pattern"]),
            actions=list(d.get("actions", [])),
            severity=str(d.get("severity", "high")),
            hard_block=bool(d.get("hard_block", True)),
        )


def _make_banned_command_from_rule(rule: dict[str, Any]) -> BannedCommand:
    return BannedCommand(
        rule_id=str(rule.get("rule_id", "patch-cmd")),
        pattern=str(rule["pattern"]),
        severity=str(rule.get("severity", "high")),
        hard_block=bool(rule.get("hard_block", True)),
    )


# Public alias used at top of module
BannedPathLike = _BannedPathLike
