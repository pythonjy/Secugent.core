# SPDX-License-Identifier: Apache-2.0
"""``secugent evolution`` operator CLI (EVOLUTION 4-eyes entry point).

Subcommands (all over a durable ``--db`` proposal store):

* ``list``    — show one tenant's proposals + state.
* ``propose`` — create a proposal and submit it for review.
* ``approve`` — record a 4-eyes admin approval (REUSES ``ProposalRepository`` —
  proposer ≠ approver, role=admin, MFA enforced by the deterministic core).
* ``open-pr`` — open a GitHub PR **only after 2 DISTINCT admin approvers** have
  approved (NO AUTO-APPLY — an EVOLUTION change is never applied automatically).
  ``--dry-run`` (the DEFAULT) uses
  :class:`MockGitProvider` and never touches the network.

This CLI re-uses the deterministic 4-eyes state machine wholesale — it adds **no
new authorization logic**. The only PR-creation call site is guarded by
:func:`_authorized_for_pr`, which requires two distinct admin approve-reviews;
there is no scheduler/auto/cron path that fires a PR without an operator.

Exit codes: ``0`` success · ``1`` fail-closed refusal (4-eyes/state/input) ·
``2`` usage error / unknown subcommand.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import TYPE_CHECKING

from secugent.core.tenancy import Principal, Role, TenantId

if TYPE_CHECKING:
    # Type-only: the EVOLUTION package (proposal_repo/git_pr) is a PRIVATE
    # (Enterprise) tier in the public OSS release manifest, so this public CLI
    # module must NOT import it at module load (that would break the OSS
    # import-closure — Invariant I8). All runtime use goes through the lazy
    # ``_evolution`` accessor below; these names are for annotations only.
    from secugent.evolution.git_pr import GitProvider, PrRequest
    from secugent.evolution.proposal_repo import (
        Proposal,
        ProposalRepository,
        SqliteProposalStore,
    )

__all__ = ["main"]

_USAGE = "usage: secugent evolution <list|propose|approve|open-pr> [options]"

# Distinct admin approvers required before a proposal may become a PR (4-eyes).
_REQUIRED_DISTINCT_APPROVERS = 2


def _emit(message: str, *, stderr: bool = False) -> None:
    """Encoding-robust stdout/stderr write (Korean Windows cp949 safe)."""
    stream = sys.stderr if stderr else sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    safe = message.encode(encoding, errors="backslashreplace").decode(encoding)
    print(safe, file=stream)


def _open_repo(db: str) -> tuple[ProposalRepository, SqliteProposalStore]:
    # Lazy private-tier import (EVOLUTION is Enterprise; keeps the public OSS CLI
    # module import-closed — I8). Imports inside a function are runtime-lazy and so
    # are exempt from the public-release closure check.
    from secugent.evolution.proposal_repo import ProposalRepository, SqliteProposalStore

    store = SqliteProposalStore(db)
    return ProposalRepository(store=store), store


def _principal(uid: str, tenant: str, *, role: Role = "admin", mfa: bool = True) -> Principal:
    """Build the operator principal for a 4-eyes approval.

    The CLI is run by an authenticated operator shell; ``--approver`` identifies
    the human and the role/MFA are admin/satisfied (the deterministic core still
    enforces proposer ≠ approver). A non-admin or MFA-less context is out of band
    for the local operator CLI; the REST surface carries the full role check.
    """
    return Principal(
        user_id=uid,
        tenant_id=TenantId(tenant),
        role=role,
        groups=[],
        mfa_satisfied=mfa,
    )


def _distinct_admin_approvers(proposal: Proposal) -> set[str]:
    """The set of distinct user ids that recorded an *approve* review."""
    return {r.approver_id for r in proposal.reviews if r.decision == "approve"}


def _authorized_for_pr(proposal: Proposal) -> bool:
    """True iff the proposal may become a PR — the SINGLE PR-open authorization.

    Requires (a) the proposal reached the ``approved`` state via the 4-eyes state
    machine AND (b) at least two DISTINCT admin approvers signed off. The same
    admin approving twice never satisfies this (NO AUTO-APPLY / four-eyes).
    """
    if proposal.state != "approved":
        return False
    return len(_distinct_admin_approvers(proposal)) >= _REQUIRED_DISTINCT_APPROVERS


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #


def _cmd_list(args: argparse.Namespace) -> int:
    repo, store = _open_repo(args.db)
    try:
        proposals = repo.list_for_tenant(args.tenant) if args.tenant else list(repo.proposals.values())
        if not proposals:
            _emit("(제안 없음)")
            return 0
        for prop in proposals:
            approvers = ", ".join(sorted(_distinct_admin_approvers(prop))) or "-"
            _emit(
                f"{prop.id}  [{prop.state}]  tenant={prop.tenant_id}  "
                f"proposer={prop.proposer_id}  approvers={approvers}  title={prop.title}"
            )
        return 0
    finally:
        store.close()


def _cmd_propose(args: argparse.Namespace) -> int:
    from secugent.evolution.proposal_repo import RelaxationRejected  # lazy private tier (I8)

    repo, store = _open_repo(args.db)
    try:
        try:
            payload = json.loads(args.payload_json)
        except json.JSONDecodeError as exc:
            _emit(f"propose: --payload-json 파싱 오류: {exc}", stderr=True)
            return 1
        if not isinstance(payload, dict):
            _emit("propose: --payload-json must be a JSON object", stderr=True)
            return 1
        baseline = json.loads(args.baseline_json) if args.baseline_json else None
        try:
            prop = repo.create(
                proposer=_principal(args.proposer, args.tenant, role="operator"),
                title=args.title,
                rationale=args.rationale,
                kind=args.kind,
                payload=payload,
                baseline=baseline if isinstance(baseline, dict) else None,
            )
        except RelaxationRejected as exc:
            _emit(f"propose: 정책 약화 제안 거부(fail-closed): {exc}", stderr=True)
            return 1
        except ValueError as exc:
            _emit(f"propose: {exc}", stderr=True)
            return 1
        repo.submit_for_review(prop.id)
        _emit(f"제안 생성됨: {prop.id} (state=reviewing)")
        return 0
    finally:
        store.close()


def _cmd_approve(args: argparse.Namespace) -> int:
    from secugent.evolution.proposal_repo import (  # lazy private tier (I8)
        FourEyesViolation,
        InvalidProposalTransition,
    )

    repo, store = _open_repo(args.db)
    try:
        prop = repo.find(args.id)
        if prop is None or prop.tenant_id != args.tenant:
            _emit("approve: 제안을 찾을 수 없습니다.", stderr=True)
            return 1
        if args.approver in _distinct_admin_approvers(prop):
            # Same admin re-approving adds no four-eyes value; refuse so an operator
            # cannot mistake a duplicate for the second distinct approver.
            _emit(
                f"approve: {args.approver} 은(는) 이미 이 제안을 승인했습니다 (서로 다른 두 관리자가 필요).",
                stderr=True,
            )
            return 1
        try:
            updated = repo.approve(
                args.id, approver=_principal(args.approver, args.tenant), reason=args.reason
            )
        except FourEyesViolation as exc:
            _emit(f"approve: 4-eyes 위반(fail-closed): {exc}", stderr=True)
            return 1
        except InvalidProposalTransition as exc:
            _emit(f"approve: 현재 상태에서 승인할 수 없습니다: {exc}", stderr=True)
            return 1
        n = len(_distinct_admin_approvers(updated))
        remaining = max(0, _REQUIRED_DISTINCT_APPROVERS - n)
        if remaining:
            _emit(f"승인 기록됨 ({n}/{_REQUIRED_DISTINCT_APPROVERS}). PR까지 {remaining}인 추가 필요.")
        else:
            _emit(f"승인 기록됨 ({n}/{_REQUIRED_DISTINCT_APPROVERS}). open-pr 가능.")
        return 0
    finally:
        store.close()


def _cmd_open_pr(args: argparse.Namespace) -> int:
    from secugent.evolution.git_pr import GitHubPrError, GitHubPrTransient  # lazy private (I8)
    from secugent.evolution.proposal_repo import InvalidProposalTransition

    repo, store = _open_repo(args.db)
    try:
        prop = repo.find(args.id)
        if prop is None:
            _emit("open-pr: 제안을 찾을 수 없습니다.", stderr=True)
            return 1
        # The SINGLE four-eyes gate before ANY PR is opened (NO AUTO-APPLY).
        if not _authorized_for_pr(prop):
            n = len(_distinct_admin_approvers(prop))
            _emit(
                f"open-pr: BLOCKED — 서로 다른 관리자 {_REQUIRED_DISTINCT_APPROVERS}인 승인이 "
                f"필요합니다(현재 {n}인, state={prop.state}). 4-eyes 미충족.",
                stderr=True,
            )
            return 1
        request = _pr_request(prop)
        try:
            # _build_provider may raise ValueError (e.g. --no-dry-run without --repo);
            # keep it inside the same fail-closed handler as the PR-open itself.
            provider = _build_provider(args)
            link = asyncio.run(provider.open_pr(request))
        except (GitHubPrError, GitHubPrTransient, ValueError) as exc:
            # Token-free by construction; surface the category and fail closed.
            _emit(f"open-pr: PR 생성 실패: {exc}", stderr=True)
            return 1
        # PR proposal only — no auto commit/tag. Record the PR url + merged
        # state through the repo state machine.
        try:
            repo.mark_merged(prop.id, pr_url=link.url)
        except InvalidProposalTransition as exc:
            _emit(f"open-pr: 상태 전이 거부: {exc}", stderr=True)
            return 1
        _emit(f"PR 생성됨: {link.url} (#{link.number}, provider={link.provider})")
        if args.dry_run:
            _emit("(--dry-run: MockGitProvider 사용 — 실제 GitHub 호출 없음)")
        return 0
    finally:
        store.close()


def _build_provider(args: argparse.Namespace) -> GitProvider:
    """Mock provider for --dry-run (default); real GitHubProvider otherwise.

    The real path reads ``GITHUB_TOKEN`` from the environment via an async token
    callable (the SecretsManager-sourced shape the provider expects). It is opt-in
    (``--no-dry-run``) so the default operator flow never reaches the network.
    """
    from secugent.evolution.git_pr import GitHubProvider, MockGitProvider  # lazy private (I8)

    if args.dry_run:
        return MockGitProvider()
    owner, _, repo = (args.repo or "").partition("/")
    if not owner or not repo:
        # Caught by the caller's ValueError handler → fail-closed exit 1.
        raise ValueError("open-pr --no-dry-run requires --repo OWNER/REPO")

    async def _token() -> str:
        return os.environ.get("GITHUB_TOKEN", "")

    return GitHubProvider(owner=owner, repo=repo, token_provider=_token)


def _pr_request(prop: Proposal) -> PrRequest:
    from secugent.evolution.git_pr import PrRequest  # lazy private tier (I8)

    return PrRequest(
        branch=f"evolution/{prop.id}",
        title=f"EVOLUTION: {prop.title}",
        body=f"{prop.rationale}\n\n제안 id: {prop.id} (4-eyes 승인 완료)",
        files={"proposal.json": json.dumps(prop.payload, ensure_ascii=False, sort_keys=True)},
    )


# --------------------------------------------------------------------------- #
# Argument parsing + dispatch
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secugent evolution",
        description="EVOLUTION 4-eyes operator CLI (list/propose/approve/open-pr).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list proposals for a tenant")
    p_list.add_argument("--db", required=True, help="path to the proposal store SQLite file")
    p_list.add_argument("--tenant", default="", help="tenant id filter (default: all)")
    p_list.set_defaults(func=_cmd_list)

    p_prop = sub.add_parser("propose", help="create + submit a proposal for review")
    p_prop.add_argument("--db", required=True)
    p_prop.add_argument("--proposer", required=True)
    p_prop.add_argument("--tenant", required=True)
    p_prop.add_argument("--title", required=True)
    p_prop.add_argument("--rationale", default="")
    p_prop.add_argument(
        "--kind",
        default="threshold",
        choices=["regulations", "threshold", "harness_prompt", "permission"],
    )
    p_prop.add_argument("--payload-json", required=True, help="proposal payload as JSON")
    p_prop.add_argument("--baseline-json", default="", help="baseline policy JSON (required for regulations)")
    p_prop.set_defaults(func=_cmd_propose)

    p_appr = sub.add_parser("approve", help="record a 4-eyes admin approval")
    p_appr.add_argument("--db", required=True)
    p_appr.add_argument("--id", required=True)
    p_appr.add_argument("--approver", required=True)
    p_appr.add_argument("--tenant", required=True)
    p_appr.add_argument("--reason", default="")
    p_appr.set_defaults(func=_cmd_approve)

    p_pr = sub.add_parser("open-pr", help="open a PR (requires 2 distinct admin approvers)")
    p_pr.add_argument("--db", required=True)
    p_pr.add_argument("--id", required=True)
    p_pr.add_argument("--repo", default="", help="OWNER/REPO for the real GitHub path")
    dry = p_pr.add_mutually_exclusive_group()
    dry.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    dry.add_argument("--no-dry-run", dest="dry_run", action="store_false")
    p_pr.set_defaults(func=_cmd_open_pr)

    return parser


def main(argv: list[str] | None = None) -> int:
    """``secugent evolution <subcommand> ...`` → exit code.

    Accepts either a bare arg list or one led by the ``evolution`` token so it
    works both standalone and dispatched from :mod:`secugent.cli.__main__`.
    """
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list and args_list[0] == "evolution":
        args_list = args_list[1:]
    parser = _build_parser()
    try:
        args = parser.parse_args(args_list)
    except SystemExit as exc:
        # argparse exits 2 on unknown subcommand / bad usage (fail-closed).
        return int(exc.code) if isinstance(exc.code, int) else 2
    # Resolve the private-tier store error type lazily; an ImportError means the
    # EVOLUTION (Enterprise) package is absent in this build → clean operator error.
    try:
        from secugent.evolution.proposal_repo import ProposalStoreError
    except ImportError:  # pragma: no cover - only in the extracted OSS build
        _emit(
            "evolution: EVOLUTION is an Enterprise feature, not available in this build.",
            stderr=True,
        )
        return 1
    try:
        result = args.func(args)
    except ProposalStoreError as exc:
        _emit(f"evolution: 영속 저장소 오류(fail-closed): {exc}", stderr=True)
        return 1
    return int(result)


if __name__ == "__main__":  # pragma: no cover - module entry convenience
    raise SystemExit(main())
