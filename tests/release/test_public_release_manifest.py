# SPDX-License-Identifier: Apache-2.0
"""Public-release manifest gate — deterministic-module test suite.

This module is a DETERMINISTIC gate, so it carries the deterministic-module triple:

* **unit** — each pure function (load_manifest, is_public_path,
  assert_import_closure, scan_forbidden_content) against hand-built inputs,
  including the two red injections (api/main.py -> closure violation; CLAUDE.md
  -> forbidden-content violation) and the placeholder-vs-real-secret split.
* **property (hypothesis)** — for an arbitrary subset of repo files, the public
  judgement equals ``whitelist-match AND NOT blacklist-match``.
* **determinism** — ``public_files`` called 100x on the same tree is byte-identical.
* **scenario regression** — the REAL curated manifest on the REAL repo yields
  ``main() == 0``, ``closure == []``, ``forbidden == []`` (the live repo still
  contains CLAUDE.md / Review/ / docs/specs/, which the manifest excludes).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from scripts.check_public_release import (
    FORBIDDEN_IMPORT_PREFIXES,
    ManifestError,
    ReleaseManifest,
    assert_deny_set_covers_manifest,
    assert_import_closure,
    excluded_top_level_secugent_packages,
    is_public_path,
    load_manifest,
    main,
    public_files,
    scan_forbidden_content,
)

# tests/release/test_*.py -> tests/release -> tests -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "release" / "public_manifest.yaml"

# Public package allowlist passed to assert_import_closure in unit tests; the
# real value is derived from the public set at runtime by main().
_SAMPLE_PUBLIC_PKGS = frozenset({"secugent", "secugent.core", "secugent.orchestrator"})


@pytest.fixture(scope="module")
def manifest() -> ReleaseManifest:
    return load_manifest(MANIFEST_PATH)


# --------------------------------------------------------------------------- #
# load_manifest — parsing + fail-closed on malformed input
# --------------------------------------------------------------------------- #
def test_load_manifest_parses_real_file(manifest: ReleaseManifest) -> None:
    assert manifest.include, "real manifest must declare include globs"
    assert manifest.exclude, "real manifest must declare exclude globs"
    assert "secugent/core/**" in manifest.include
    assert "secugent/enterprise/**" in manifest.exclude


def test_load_manifest_missing_file_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ManifestError):
        load_manifest(tmp_path / "does-not-exist.yaml")


def test_load_manifest_invalid_yaml_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("include: [unterminated\n", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(bad)


def test_load_manifest_non_mapping_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "list.yaml"
    bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(bad)


def test_load_manifest_empty_include_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "empty.yaml"
    bad.write_text("include: []\nexclude:\n  - 'x/**'\n", encoding="utf-8")
    with pytest.raises(ManifestError):
        load_manifest(bad)


def test_load_manifest_wrong_field_type_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "wrong.yaml"
    bad.write_text("include: 'secugent/**'\n", encoding="utf-8")  # str, not list
    with pytest.raises(ManifestError):
        load_manifest(bad)


# --------------------------------------------------------------------------- #
# is_public_path — deny-by-default decision (I4)
# --------------------------------------------------------------------------- #
def test_is_public_path_include_minus_exclude(manifest: ReleaseManifest) -> None:
    assert is_public_path("secugent/core/regulations.py", manifest) is True
    # Excluded mixed-package member (closure risk R3) — exclude wins. sub_agent.py
    # carries real token-budget enforcement (eager secugent.cost import) and stays
    # private; runner.py/errors.py were made import-closed and now SHIP.
    assert is_public_path("secugent/agents/sub_agent.py", manifest) is False
    assert is_public_path("secugent/models/router.py", manifest) is False
    assert is_public_path("secugent/orchestrator/runner.py", manifest) is True
    assert is_public_path("secugent/orchestrator/errors.py", manifest) is True
    # Whole private package.
    assert is_public_path("secugent/enterprise/kms.py", manifest) is False
    # Not in any include glob -> deny-by-default.
    assert is_public_path("secret_notes.txt", manifest) is False


def test_is_public_path_deploy_artifacts_are_private(manifest: ReleaseManifest) -> None:
    # deploy/** artifacts (incl. .env.example) are PRIVATE: they boot the Enterprise
    # secugent.api tier, so the OSS repo ships as library + CLI + SDK with no server.
    assert is_public_path("deploy/.env.example", manifest) is False
    assert is_public_path("deploy/.env", manifest) is False
    assert is_public_path("deploy/Dockerfile", manifest) is False


def test_is_public_path_internal_docs_excluded(manifest: ReleaseManifest) -> None:
    for rel in ("CLAUDE.md", "docs/specs/2026-06-10-x.md", "Review/x.md", "report_1.md"):
        assert is_public_path(rel, manifest) is False, rel


# --------------------------------------------------------------------------- #
# assert_import_closure — AST closure (I2), incl. the RED injection
# --------------------------------------------------------------------------- #
def test_closure_clean_for_core_file() -> None:
    clean = REPO_ROOT / "secugent" / "core" / "regulations.py"
    assert assert_import_closure(_SAMPLE_PUBLIC_PKGS, [clean]) == []


def test_closure_red_injection_api_main_is_violation() -> None:
    """(red) inject secugent/api/main.py -> closure must report a violation.

    Reads an EXCLUDED source file, which is absent in the extracted public repo;
    skip cleanly there (this test ships) so the extract's own ``pytest -q`` does
    not error on a missing file (Invariant I8 — same guard as the Korean-HTML
    test)."""
    leaked = REPO_ROOT / "secugent" / "api" / "main.py"
    if not leaked.is_file():  # pragma: no cover - only in the extracted public repo
        pytest.skip("secugent/api/main.py is excluded from the public set (extract)")
    violations = assert_import_closure(_SAMPLE_PUBLIC_PKGS, [leaked])
    assert violations, "api/main.py imports private tiers and MUST violate closure"
    assert any("secugent/api/main.py imports private tier" in v for v in violations)


def test_closure_sub_agent_is_now_import_closed() -> None:
    """Regression: agents/sub_agent.py was made import-closed — the
    optional secugent.cost token-budget tier is now TYPE_CHECKING / lazy, so its
    top-level import no longer couples the private cost tier (mirrors runner.py /
    errors.py). It must NOT be a private-tier closure violation any more. Whether
    the git-extraction manifest now SHIPS it is a separate manifest decision; this
    only asserts closure."""
    path = REPO_ROOT / "secugent" / "agents" / "sub_agent.py"
    if not path.is_file():  # pragma: no cover - only in the extracted public repo
        pytest.skip("secugent/agents/sub_agent.py not present in this checkout")
    assert assert_import_closure(_SAMPLE_PUBLIC_PKGS, [path]) == []


def test_closure_red_injection_synthetic_private_import_is_violation(tmp_path: Path) -> None:
    """Positive coverage for the closure checker itself: a file that eagerly
    imports a private tier (secugent.cost.accounting) MUST be flagged. Uses a
    synthetic file so the coverage does not depend on any real module staying
    "red" (a prior cleanup closed the last real red, sub_agent.py). Both ``import`` and
    ``from`` forms are exercised."""
    for src in (
        "import secugent.cost.accounting\n",
        "from secugent.cost.accounting import CostLedger\n",
    ):
        red = tmp_path / "red.py"
        red.write_text(src, encoding="utf-8")
        violations = assert_import_closure(_SAMPLE_PUBLIC_PKGS, [red])
        assert any("imports private tier secugent.cost.accounting" in v for v in violations), src


def test_closure_runner_is_now_import_closed() -> None:
    """Regression: runner.py was made import-closed (the optional secugent.cost
    quota tier is TYPE_CHECKING / lazy) so it ships in Core. It must NOT be a
    private-tier closure violation any more — the shipping adapters depend on its
    cost-free ``PlanLike`` at runtime, so a self-contained extract needs it."""
    for rel in ("runner.py", "errors.py"):
        path = REPO_ROOT / "secugent" / "orchestrator" / rel
        assert assert_import_closure(_SAMPLE_PUBLIC_PKGS, [path]) == [], rel


def test_closure_ignores_non_py_files() -> None:
    yaml_file = REPO_ROOT / "config" / "models.yaml"
    assert assert_import_closure(_SAMPLE_PUBLIC_PKGS, [yaml_file]) == []


def test_closure_syntax_error_is_violation(tmp_path: Path) -> None:
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    violations = assert_import_closure(_SAMPLE_PUBLIC_PKGS, [broken])
    assert any("SyntaxError" in v for v in violations)


def test_closure_empty_public_pkgs_is_violation() -> None:
    assert assert_import_closure(frozenset(), []) != []


# --------------------------------------------------------------------------- #
# deny-set ⇔ manifest lock-step (the Critical fail-open the review found)
# --------------------------------------------------------------------------- #
def test_deny_set_covers_every_excluded_secugent_tier(manifest: ReleaseManifest) -> None:
    """FORBIDDEN_IMPORT_PREFIXES MUST cover every top-level ``secugent`` tier the
    manifest wholesale-excludes. The review found desktop/evolution/identity/
    integrations excluded by the manifest but ABSENT from the deny-set, making
    the closure gate fail-open for them. This pins the two in lock-step."""
    excluded = excluded_top_level_secugent_packages(manifest)
    # The four D1-deferred tiers MUST be in the excluded set (sanity on parsing).
    for tier in (
        "secugent.desktop",
        "secugent.evolution",
        "secugent.identity",
        "secugent.integrations",
    ):
        assert tier in excluded, f"{tier} must be a wholesale-excluded tier"
    missing = excluded - set(FORBIDDEN_IMPORT_PREFIXES)
    assert not missing, (
        "deny-set drift: manifest excludes these tiers but FORBIDDEN_IMPORT_PREFIXES "
        f"omits them (closure would be fail-open): {sorted(missing)}"
    )
    assert assert_deny_set_covers_manifest(manifest) == []


def test_deny_set_drift_is_reported_when_a_tier_is_uncovered() -> None:
    """If a manifest excludes a tier the deny-set omits, the drift check reports
    it (the exact regression this whole fix closes). Synthesised manifest:
    excludes secugent.evolution but the deny-set would have to list it — we model
    the gap by excluding a tier name the prefixes intentionally cover, then a tier
    they do NOT cover to prove the asymmetry is detected."""
    drifted = ReleaseManifest(
        include=("secugent/core/**",),
        exclude=("secugent/ghosttier/**", "secugent/evolution/**"),
    )
    violations = assert_deny_set_covers_manifest(drifted)
    # ghosttier is excluded but not in FORBIDDEN_IMPORT_PREFIXES -> reported.
    assert any("secugent.ghosttier" in v for v in violations)
    # evolution IS in the deny-set now, so it must NOT be reported.
    assert not any("secugent.evolution" in v for v in violations)


def test_main_fails_closed_on_deny_set_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """main() must exit non-zero if the live manifest excludes a tier the deny-set
    does not cover — the gate refuses to certify a fail-open configuration."""
    import scripts.check_public_release as mod

    # A tiny fake repo + manifest that excludes a tier absent from the deny-set.
    (tmp_path / "secugent" / "core").mkdir(parents=True)
    (tmp_path / "secugent" / "core" / "ok.py").write_text("x = 1\n", encoding="utf-8")
    man = tmp_path / "m.yaml"
    man.write_text(
        "include:\n  - 'secugent/core/**'\nexclude:\n  - 'secugent/ghosttier/**'\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    assert mod.main([str(man)]) == 1


def test_closure_flags_module_level_desktop_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """(red) A *module-level* import of an excluded tier (the real leak — breaks
    standalone import) MUST still be a closure violation. Guards against the
    precise-detector change going fail-open."""
    import scripts.check_public_release as mod

    pkg = tmp_path / "secugent" / "tools"
    pkg.mkdir(parents=True)
    leak = pkg / "leaky.py"
    leak.write_text("from secugent.desktop.base import VirtualDesktopBackend\n", encoding="utf-8")
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    violations = assert_import_closure(frozenset({"secugent.tools"}), [leak])
    assert any("imports private tier secugent.desktop.base" in v for v in violations)


def test_closure_allows_type_checking_guarded_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An import under ``if TYPE_CHECKING:`` is runtime-erased — it does NOT break
    standalone import and is the sanctioned escape hatch for type-only references.
    It must NOT be a closure violation (this is exactly router.py's annotation)."""
    import scripts.check_public_release as mod

    pkg = tmp_path / "secugent" / "tools"
    pkg.mkdir(parents=True)
    clean = pkg / "typed.py"
    clean.write_text(
        "from __future__ import annotations\n"
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from secugent.desktop.base import VirtualDesktopBackend\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    assert assert_import_closure(frozenset({"secugent.tools"}), [clean]) == []


def test_closure_allows_function_local_lazy_import(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A forbidden import nested in a function body is lazy — it only runs when
    the function is called, never on plain ``import``. Standalone import succeeds,
    so it is not a load-time closure violation (the open-core optional-tier
    pattern, e.g. router.py's _load_desktop_backend_types)."""
    import scripts.check_public_release as mod

    pkg = tmp_path / "secugent" / "tools"
    pkg.mkdir(parents=True)
    clean = pkg / "lazy.py"
    clean.write_text(
        "def get_backend():\n"
        "    from secugent.desktop.stub_backend import StubBackend\n"
        "    return StubBackend()\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    assert assert_import_closure(frozenset({"secugent.tools"}), [clean]) == []


# --------------------------------------------------------------------------- #
# excluded-sibling closure (the Critical fail-open the review found) — a public
# file importing a module that EXISTS but is excluded from the public set would
# ModuleNotFoundError in the extracted repo, yet the old tier-only gate said "OK".
# --------------------------------------------------------------------------- #
def test_closure_flags_module_level_import_of_excluded_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(red) A shipping ``__init__.py`` that load-imports an EXCLUDED sibling
    (present on disk, absent from the public set) must be a closure violation —
    it raises ModuleNotFoundError in the extract even though it is not a private
    *tier*. This is the exact fail-open that certified a non-self-contained set."""
    import scripts.check_public_release as mod

    pkg = tmp_path / "secugent" / "orchestrator"
    pkg.mkdir(parents=True)
    # The excluded sibling exists on disk (but is NOT in the public set).
    (pkg / "runner.py").write_text("x = 1\n", encoding="utf-8")
    init = pkg / "__init__.py"
    init.write_text("from secugent.orchestrator.runner import RunOrchestrator\n", encoding="utf-8")
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    excluded = frozenset({"secugent/orchestrator/runner.py"})
    violations = assert_import_closure(frozenset({"secugent.orchestrator"}), [init], excluded)
    assert any("imports excluded-from-public module secugent.orchestrator.runner" in v for v in violations), (
        violations
    )


def test_closure_ignores_excluded_sibling_under_type_checking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A TYPE_CHECKING / lazy reference to an excluded sibling is runtime-erased
    and does NOT break standalone import — it must NOT be an excluded-sibling
    violation (exactly how dispatcher.py / wiring.py reference the excluded
    sub_agent / runner annotations)."""
    import scripts.check_public_release as mod

    pkg = tmp_path / "secugent" / "agents"
    pkg.mkdir(parents=True)
    (pkg / "sub_agent.py").write_text("x = 1\n", encoding="utf-8")
    clean = pkg / "dispatcher.py"
    clean.write_text(
        "from __future__ import annotations\n"
        "from typing import TYPE_CHECKING\n"
        "if TYPE_CHECKING:\n"
        "    from secugent.agents.sub_agent import SubAgent\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    excluded = frozenset({"secugent/agents/sub_agent.py"})
    assert assert_import_closure(frozenset({"secugent.agents"}), [clean], excluded) == []


def test_closure_excluded_sibling_default_empty_is_noop() -> None:
    """With the default (empty) excluded set, the new check is a no-op — the
    plain tier check still governs (keeps the unit-test call sites unchanged)."""
    init_src = "from secugent.orchestrator.runner import RunOrchestrator\n"
    from scripts.check_public_release import _excluded_sibling_imports_in_source

    assert (
        _excluded_sibling_imports_in_source(
            init_src, package="secugent.orchestrator", excluded_existing=frozenset()
        )
        == []
    )


def test_excluded_existing_files_excludes_public_and_keeps_private(
    manifest: ReleaseManifest,
) -> None:
    """``_excluded_existing_files`` returns repo .py files that exist but are NOT
    public — exactly the import targets that break the extract. sub_agent.py /
    router.py (excluded) must be in it; runner.py / a shipping core file must not."""
    # Extract-time detection of excluded-but-present private .py files. It only
    # applies where the private tier is physically present (the Enterprise source
    # tree); the extracted public repo has no private .py to detect, so skip there.
    if not (REPO_ROOT / "secugent" / "agents" / "sub_agent.py").exists():
        pytest.skip("private tier absent (public repo) — extract-time check N/A")
    from scripts.check_public_release import _excluded_existing_files

    files = public_files(manifest, REPO_ROOT)
    excluded = _excluded_existing_files(manifest, REPO_ROOT, files)
    assert "secugent/agents/sub_agent.py" in excluded
    assert "secugent/models/router.py" in excluded
    assert "secugent/api/main.py" in excluded
    # Now-shipping files must NOT be in the excluded-existing set.
    assert "secugent/orchestrator/runner.py" not in excluded
    assert "secugent/orchestrator/errors.py" not in excluded
    assert "secugent/core/regulations.py" not in excluded


def test_real_router_is_public_and_import_closed() -> None:
    """secugent/tools/router.py ships (the broker imports it) AND is import-closed:
    its desktop references are TYPE_CHECKING / lazy, so the published Core wheel
    imports it without the excluded desktop tier (Invariant I8)."""
    router = REPO_ROOT / "secugent" / "tools" / "router.py"
    assert assert_import_closure(frozenset({"secugent.tools"}), [router]) == []


# --------------------------------------------------------------------------- #
# scan_forbidden_content — strategy docs + secrets (I5), incl. the RED injection
# --------------------------------------------------------------------------- #
def test_content_red_injection_claude_md_is_violation() -> None:
    """(red) inject CLAUDE.md -> scan_forbidden_content must report a violation.

    CLAUDE.md is excluded and absent in the extracted public repo; the scan flags
    it by *basename* (no read needed), so even in the extract this still reports a
    violation against the constructed path. No skip required, but assert on the
    name-based reason that does not depend on the file existing."""
    leaked = REPO_ROOT / "CLAUDE.md"
    violations = scan_forbidden_content([leaked])
    assert any("internal-strategy file CLAUDE.md" in v for v in violations)


def test_content_korean_strategy_html_is_violation(tmp_path: Path) -> None:
    leaked = tmp_path / "SecuGent_시장진단_대시보드.html"
    leaked.write_text("<html></html>", encoding="utf-8")
    # Build a path under the repo root so _rel_posix works; use a real repo file
    # name pattern by checking the Hangul-substring gate directly via a repo path.
    real = REPO_ROOT / "SecuGent_로우리스크_기능우선순위.html"
    if real.exists():
        violations = scan_forbidden_content([real])
        assert any("Korean strategy artifact" in v for v in violations)
    else:  # pragma: no cover - file is normally present in the working tree
        pytest.skip("Korean strategy HTML not present in working tree")


def test_content_env_example_placeholders_not_flagged() -> None:
    """.env.example ships change-me-* placeholders — must NOT be a secret hit.
    deploy/ is private in the OSS distribution, so the file is absent in the
    extracted public repo; this guards the scanner where the file exists."""
    env_example = REPO_ROOT / "deploy" / ".env.example"
    if not env_example.is_file():
        pytest.skip("deploy/.env.example excluded from the public distribution")
    assert scan_forbidden_content([env_example]) == []


def test_content_real_secret_is_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A real AWS key / sk- token in a public text file must be flagged."""
    import scripts.check_public_release as mod

    secret_file = tmp_path / "leak.txt"
    secret_file.write_text(
        "aws_key = AKIA1234567890ABCDEF\napi_key = sk-ABCDEF0123456789abcdef\n",
        encoding="utf-8",
    )
    # Point the module's repo root at tmp so _rel_posix resolves the temp file.
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    violations = scan_forbidden_content([secret_file])
    assert any("secret-like content" in v for v in violations)


def test_content_env_filename_is_flagged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.check_public_release as mod

    env_file = tmp_path / ".env"
    env_file.write_text("X=1\n", encoding="utf-8")
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    violations = scan_forbidden_content([env_file])
    assert any("secret file" in v for v in violations)


def test_content_clean_core_file_not_flagged() -> None:
    clean = REPO_ROOT / "secugent" / "core" / "regulations.py"
    assert scan_forbidden_content([clean]) == []


# --------------------------------------------------------------------------- #
# property (hypothesis): public judgement == whitelist ∧ ¬blacklist
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def repo_rel_paths() -> list[str]:
    """A bounded, deterministic sample of real repo-relative POSIX paths."""
    from scripts.check_public_release import _iter_repo_files

    return _iter_repo_files(REPO_ROOT)


def test_repo_sample_nonempty(repo_rel_paths: list[str]) -> None:
    assert len(repo_rel_paths) > 50, "expected the repo walk to find many files"


@settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_property_public_iff_whitelist_and_not_blacklist(
    data: st.DataObject, manifest: ReleaseManifest, repo_rel_paths: list[str]
) -> None:
    """For an arbitrary subset of repo files, the public judgement equals
    (matches an include glob) AND NOT (matches an exclude glob)."""
    from scripts.check_public_release import _matches_any

    subset = data.draw(st.lists(st.sampled_from(repo_rel_paths), max_size=12, unique=True))
    for rel in subset:
        expected = _matches_any(rel, manifest.include) and not _matches_any(rel, manifest.exclude)
        assert is_public_path(rel, manifest) is expected, rel


@settings(max_examples=100, deadline=None)
@given(
    rel=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="/._-"),
        min_size=1,
        max_size=40,
    )
)
def test_property_synthetic_paths_consistent(rel: str, manifest: ReleaseManifest) -> None:
    """Even for synthetic paths, the decision is exactly include ∧ ¬exclude."""
    from scripts.check_public_release import _matches_any

    expected = _matches_any(rel, manifest.include) and not _matches_any(rel, manifest.exclude)
    assert is_public_path(rel, manifest) is expected


# --------------------------------------------------------------------------- #
# determinism: 100 identical runs (I6)
# --------------------------------------------------------------------------- #
def test_public_files_deterministic_100x(manifest: ReleaseManifest) -> None:
    baseline = public_files(manifest, REPO_ROOT)
    assert baseline, "public set must be non-empty"
    # Sorted invariant.
    rels = [p.as_posix() for p in baseline]
    assert rels == sorted(rels), "public_files output must be sorted"
    for _ in range(100):
        assert public_files(manifest, REPO_ROOT) == baseline


def test_public_files_no_excluded_members(manifest: ReleaseManifest) -> None:
    """Sanity: the curated public set contains none of the known leak files."""
    rels = {
        p.resolve().relative_to(REPO_ROOT.resolve()).as_posix() for p in public_files(manifest, REPO_ROOT)
    }
    for leaked in (
        # sub_agent.py / models/router.py keep an EAGER secugent.cost import
        # (token-budget / cost-ledger enforcement) and stay private.
        "secugent/agents/sub_agent.py",
        "secugent/models/router.py",
        "secugent/api/main.py",
        "secugent/cost/accounting.py",
        "CLAUDE.md",
        "report_1.md",
        # D1-deferred-tier test suites must NOT ship (they import excluded tiers).
        "tests/evolution/test_approval_gate.py",
        "tests/evolution/test_4eyes_required.py",
        "tests/evolution/test_canary_rollback_threshold.py",
        "tests/evolution/test_no_relaxation_invariant.py",
        "tests/unit/test_desktop_factory.py",
        "tests/unit/test_desktop_security.py",
        "tests/unit/test_stub_backend.py",
        # Tests importing the private SUB agent must NOT ship (would
        # ModuleNotFoundError under the extract's pytest -q — Invariant I8).
        "tests/agents/test_sub_agent_envelope.py",
        "tests/orchestrator/test_adapters.py",
        "tests/unit/test_head_agent.py",
        "tests/unit/test_sub_agent.py",
        # Deploy tests exercise the excluded HA/air-gap bundle — must NOT ship.
        "tests/deploy/test_compose_ha.py",
        "tests/deploy/test_airgap_bundle.py",
    ):
        assert leaked not in rels, f"{leaked} must NOT be in the public set"
    # Core files that MUST ship.
    for shipped in (
        "secugent/core/regulations.py",
        "secugent/orchestrator/adapters.py",
        "secugent/agents/dispatcher.py",
        "secugent/models/catalog.py",
        # runner.py / errors.py were made import-closed (optional cost tier is
        # TYPE_CHECKING/lazy) and now SHIP: the public adapters depend on their
        # cost-free symbols (PlanLike, planner/dispatcher errors) at runtime, so
        # the extract needs them to import standalone (I8).
        "secugent/orchestrator/runner.py",
        "secugent/orchestrator/errors.py",
        # tools/router.py SHIPS (the public io/broker imports it); its desktop
        # references are TYPE_CHECKING/lazy so it stays import-closed (I8).
        "secugent/tools/router.py",
    ):
        assert shipped in rels, f"{shipped} must be in the public set"


# --------------------------------------------------------------------------- #
# scenario regression: the real curated manifest on the real repo
# --------------------------------------------------------------------------- #
def _materialize_public_set(manifest: ReleaseManifest, dest: Path) -> int:
    """Copy the curated public file set into ``dest`` (the extracted-repo shape).

    Returns the number of files materialized. Used by the I8 proofs to build the
    exact standalone tree the public OSS repo would ship, with NO private tier
    present, so an eager import of an excluded module fails just like it would in
    the real extract."""
    import shutil

    files = public_files(manifest, REPO_ROOT)
    for src in files:
        rel = src.resolve().relative_to(REPO_ROOT.resolve())
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, out)
    return len(files)


def test_i8_extracted_public_set_imports_standalone(tmp_path: Path) -> None:
    """I8 (self-containment) — the REAL proof, not the gate's self-report. Copy
    public_files() into a clean tree (no secugent.cost / no excluded siblings)
    and import the modules the review reproduced as broken. Each MUST succeed in
    a fresh interpreter (subprocess so the source repo's already-imported
    ``secugent`` cannot mask a ModuleNotFoundError)."""
    import subprocess

    man = load_manifest(MANIFEST_PATH)
    count = _materialize_public_set(man, tmp_path)
    assert count > 100, "expected the public set to be materialized"
    targets = [
        "secugent",
        "secugent.orchestrator",
        "secugent.models",
        "secugent.agents.dispatcher",
        "secugent.orchestrator.adapters",
        "secugent.orchestrator.a2a_adapter",
        "secugent.orchestrator.wiring",
        "secugent.orchestrator.runner",
        "secugent.orchestrator.errors",
        "secugent.sdk",
    ]
    script = "import importlib, sys\n" + "".join(f"importlib.import_module({t!r})\n" for t in targets)
    result = subprocess.run(  # noqa: S603 - sys.executable + a generated import script, no untrusted input
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
    )
    assert result.returncode == 0, "extracted public set is NOT import-closed (I8 broken):\n" + result.stderr


def test_i8_extracted_public_suite_collects_without_errors(tmp_path: Path) -> None:
    """I8 / DoD gate 5 — the extracted public test suite must COLLECT cleanly
    (``pytest --collect-only`` == 0 collection errors). A shipping test importing
    an excluded module would INTERRUPT collection; this asserts the curated set
    has none. Subprocess + PYTHONPATH so the extract's own modules resolve."""
    import subprocess

    man = load_manifest(MANIFEST_PATH)
    _materialize_public_set(man, tmp_path)
    result = subprocess.run(  # noqa: S603 - sys.executable + fixed pytest args, no untrusted input
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
        ],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
    )
    combined = result.stdout + result.stderr
    # pytest exits non-zero on ANY collection error even under --collect-only, so
    # rc==0 is itself the "zero collection errors" proof.
    assert result.returncode == 0, (
        "extracted public suite failed to collect (I8 broken):\n" + combined[-3000:]
    )
    assert "collected" in combined, combined[-2000:]


def test_shipping_tests_do_not_unguardedly_read_excluded_paths(manifest: ReleaseManifest) -> None:
    """Defence-in-depth (Medium #2): a shipping test must not unconditionally read
    a file that is EXCLUDED from the public set — that file is absent in the
    extract, so the read FileNotFoundErrors under the extract's ``pytest -q``
    (Invariant I8) even though collection succeeded.

    Heuristic but deterministic: for every shipping test ``.py``, scan its source
    for a string literal naming an excluded path prefix that is ALSO read
    (``read_text`` / ``read_bytes`` / ``open(``). If found, require a guard token
    (``exists`` / ``is_file`` / ``pytest.skip`` / ``importorskip``) somewhere in
    the file. This is the regression guard for the unguarded enterprise/api/helm/
    airgap reads the review flagged."""
    import re

    public = public_files(manifest, REPO_ROOT)
    public_rel = {p.resolve().relative_to(REPO_ROOT.resolve()).as_posix() for p in public}
    # Excluded path prefixes whose files are absent in the extract.
    excluded_prefixes = (
        "secugent/enterprise/",
        "secugent/api/",
        "secugent/cost/",
        "secugent/evolution/",
        "secugent/identity/",
        "secugent/integrations/",
        "secugent/desktop/",
        "deploy/helm/",
        "deploy/airgap/",
        "deploy/postgres/",
        "deploy/constraints.txt",
        "deploy/docker-compose.dev.yml",
        "ui/",
    )
    read_markers = ("read_text", "read_bytes", "open(")
    guard_markers = ("exists", "is_file", "pytest.skip", "importorskip")
    literal_re = re.compile(r"""["']([A-Za-z0-9_./-]+)["']""")

    offenders: dict[str, list[str]] = {}
    for rel in sorted(public_rel):
        if not (rel.startswith("tests/") and rel.endswith(".py")):
            continue
        src = (REPO_ROOT / rel).read_text(encoding="utf-8")
        if not any(m in src for m in read_markers):
            continue
        if any(g in src for g in guard_markers):
            continue  # the file guards its reads — accept (we cannot pin which).
        hits = [
            lit
            for lit in literal_re.findall(src)
            if any(lit.startswith(pre) or lit == pre.rstrip("/") for pre in excluded_prefixes)
        ]
        if hits:
            offenders[rel] = sorted(set(hits))
    assert not offenders, (
        "shipping tests read EXCLUDED paths without an exists()/skip guard — they "
        f"would FileNotFoundError in the extracted public repo (I8): {offenders}"
    )


def test_scenario_real_repo_closure_empty(manifest: ReleaseManifest) -> None:
    files = public_files(manifest, REPO_ROOT)
    from scripts.check_public_release import _declared_public_packages

    closure = assert_import_closure(_declared_public_packages(files), files)
    assert closure == [], f"real public set must be import-closed, got: {closure}"


def test_scenario_real_repo_forbidden_empty(manifest: ReleaseManifest) -> None:
    files = public_files(manifest, REPO_ROOT)
    forbidden = scan_forbidden_content(files)
    assert forbidden == [], f"real public set must be strategy/secret-free, got: {forbidden}"


def test_scenario_main_exit_zero_on_current_repo() -> None:
    """The whole gate must exit 0 on the current repo (manifest excludes the
    internal docs that still physically exist in the tree)."""
    assert main([str(MANIFEST_PATH)]) == 0


def test_scenario_main_nonzero_on_empty_manifest(tmp_path: Path) -> None:
    bad = tmp_path / "empty.yaml"
    bad.write_text("include: []\n", encoding="utf-8")
    assert main([str(bad)]) == 1


def test_main_rejects_unsupported_repo_root_flag() -> None:
    """main() takes only an optional positional MANIFEST path — there is no
    --repo-root flag. Passing it must fail-closed (treated as a missing manifest),
    which is exactly why the extract script's gate-3 must NOT pass --repo-root.
    Pins the bug the review found (gate 3 always exited 4)."""
    assert main(["--repo-root", "some/extract/dir"]) == 1


def test_extract_script_gate3_invokes_gate_without_repo_root_flag() -> None:
    """Regression for the dead gate-3: the extract script's post-extraction
    re-verification must invoke the in-extract gate with NO --repo-root flag (its
    __file__-derived _REPO_ROOT already resolves to the extracted dir). A bare
    invocation re-scans the extract; --repo-root would always fail (ManifestError)."""
    script = REPO_ROOT / "scripts" / "extract_public_repo.sh"
    text = script.read_text(encoding="utf-8")
    # The dead form must be gone everywhere except in an explanatory comment.
    code_lines = [ln for ln in text.splitlines() if "--repo-root" in ln and not ln.lstrip().startswith("#")]
    assert not code_lines, f"extract script still passes --repo-root in a command: {code_lines}"
    # The correct bare invocation of the in-extract gate must be present.
    assert 'python3 "${GATE_IN_OUT}"' in text


# --------------------------------------------------------------------------- #
# branch coverage: helper edge cases (B-4a 95% gate for a deterministic module)
# --------------------------------------------------------------------------- #
def test_load_manifest_non_string_item_fails_closed(tmp_path: Path) -> None:
    bad = tmp_path / "items.yaml"
    bad.write_text("include:\n  - 'ok/**'\n  - 123\n", encoding="utf-8")  # int item
    with pytest.raises(ManifestError):
        load_manifest(bad)


def test_load_manifest_ignores_blank_globs(tmp_path: Path) -> None:
    good = tmp_path / "blanks.yaml"
    good.write_text("include:\n  - 'secugent/**'\n  - '   '\nexclude: []\n", encoding="utf-8")
    parsed = load_manifest(good)
    assert parsed.include == ("secugent/**",)  # blank stripped out
    assert parsed.exclude == ()


def test_glob_question_mark_matches_single_segment_char() -> None:
    from scripts.check_public_release import _glob_to_regex

    pat = _glob_to_regex("a?.py")
    assert pat.fullmatch("ab.py") is not None
    assert pat.fullmatch("a/.py") is None  # ? must not span '/'
    assert pat.fullmatch("abc.py") is None


def test_glob_double_star_in_middle() -> None:
    from scripts.check_public_release import _glob_to_regex

    pat = _glob_to_regex("a/**/z.py")
    assert pat.fullmatch("a/z.py") is not None  # zero middle segments
    assert pat.fullmatch("a/b/c/z.py") is not None


def test_closure_resolves_relative_import_to_private_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative reach into a private tier (``from ..cost.accounting import X``)
    must resolve to its absolute target and be flagged."""
    import scripts.check_public_release as mod

    pkg = tmp_path / "secugent" / "audit"
    pkg.mkdir(parents=True)
    leak = pkg / "leak.py"
    leak.write_text("from ..cost.accounting import CostLedger\n", encoding="utf-8")
    # Resolve the file's package against tmp_path so _package_of yields
    # 'secugent.audit' and the relative import resolves to secugent.cost.accounting.
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    violations = assert_import_closure(frozenset({"secugent.audit"}), [leak])
    assert any("secugent.cost.accounting" in v for v in violations)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("change-me-token", False),  # placeholder
        ("self._api_key)", False),  # code token (punctuation)
        ("Token[TenantId]", False),  # subscript
        ("password", False),  # bare word, no entropy
        ("abc123def456ghi", True),  # letters + digits
        ("AbCdEf-GhIjKl-MnOp", True),  # letters + separators
    ],
)
def test_looks_like_secret_value(value: str, expected: bool) -> None:
    from scripts.check_public_release import _looks_like_secret_value

    assert _looks_like_secret_value(value) is expected


def test_forbidden_name_reason_variants() -> None:
    from scripts.check_public_release import _forbidden_name_reason

    assert "internal-strategy file" in (_forbidden_name_reason("CLAUDE.md") or "")
    assert "internal-strategy path" in (_forbidden_name_reason("Review/sub/x.md") or "")
    assert "Korean strategy artifact" in (_forbidden_name_reason("dir/SecuGent_로우리스크_x.html") or "")
    assert _forbidden_name_reason("secugent/core/regulations.py") is None


def test_secret_filename_reason_variants() -> None:
    from scripts.check_public_release import _secret_filename_reason

    assert "secret file" in (_secret_filename_reason("deploy/.env") or "")
    assert "key/cert material" in (_secret_filename_reason("certs/server.pem") or "")
    assert "key/cert material" in (_secret_filename_reason("certs/server.key") or "")
    assert _secret_filename_reason("deploy/.env.example") is None


def test_main_nonzero_prints_violations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """main() must print each violation and return nonzero when the public set
    contains a leak (exercises the FAIL print path)."""
    import scripts.check_public_release as mod

    # Build a tiny fake repo whose manifest includes a file that leaks CLAUDE.md.
    (tmp_path / "CLAUDE.md").write_text("internal\n", encoding="utf-8")
    man = tmp_path / "manifest.yaml"
    man.write_text("include:\n  - 'CLAUDE.md'\nexclude: []\n", encoding="utf-8")
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    rc = main([str(man)])
    out = capsys.readouterr().out
    assert rc == 1
    assert "FAIL: public-release gate found violations:" in out
    assert "CLAUDE.md" in out


def test_unreadable_file_in_closure_is_violation() -> None:
    """A .py file that cannot be read is a closure violation (fail-closed)."""
    phantom = REPO_ROOT / "secugent" / "core" / "__does_not_exist__.py"
    violations = assert_import_closure(frozenset({"secugent.core"}), [phantom])
    assert any("unreadable" in v for v in violations)


def test_forbidden_imports_in_source_branches() -> None:
    """Directly exercise the AST detector's sub-branches: bare ``import x``,
    a relative import with no package, and a relative that walks above root."""
    from scripts.check_public_release import _forbidden_imports_in_source, _resolve_relative

    # Bare ``import secugent.enterprise.kms`` (ast.Import branch).
    assert _forbidden_imports_in_source("import secugent.enterprise.kms\n", package="secugent.core") == [
        "secugent.enterprise.kms"
    ]
    # Relative import but no package context -> skipped (cannot resolve).
    assert _forbidden_imports_in_source("from ..cost import x\n", package=None) == []
    # Relative that walks above the top-level package -> resolve returns None.
    assert _resolve_relative(5, "cost.accounting", "secugent.core") is None
    assert _forbidden_imports_in_source("from .....cost import x\n", package="secugent.core") == []


def test_load_manifest_unreadable_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An OSError while reading the manifest is a fail-closed ManifestError."""
    p = tmp_path / "m.yaml"
    p.write_text("include:\n  - 'x/**'\n", encoding="utf-8")

    def boom(*_a: object, **_k: object) -> str:
        raise OSError("disk gone")

    monkeypatch.setattr(Path, "read_text", boom)
    with pytest.raises(ManifestError):
        load_manifest(p)


def test_content_scan_binary_text_suffix_not_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A file with a text suffix but undecodable bytes is skipped, not flagged."""
    import scripts.check_public_release as mod

    f = tmp_path / "weird.txt"
    f.write_bytes(b"\xff\xfe\x00\x80not utf8")
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    assert scan_forbidden_content([f]) == []


def test_content_scan_unreadable_file_is_violation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A text file that raises OSError on read is a fail-closed violation."""
    import scripts.check_public_release as mod

    f = tmp_path / "x.txt"
    f.write_text("ok\n", encoding="utf-8")
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)

    def boom(self: Path, encoding: str = "utf-8") -> str:
        raise OSError("locked")

    monkeypatch.setattr(Path, "read_text", boom)
    violations = scan_forbidden_content([f])
    assert any("unreadable" in v for v in violations)


def test_secret_hits_skips_placeholder_and_code_tokens() -> None:
    """The credential-assignment regex must skip both placeholder values
    (``change-me-*``) and code-shaped right-hand sides (vetting continue)."""
    from scripts.check_public_release import _secret_hits_in_text

    text = (
        'api_key = "change-me-please-1234"\n'  # placeholder -> skip (525)
        'token = "self._value()xyz"\n'  # code punctuation -> vet skip (529)
    )
    assert _secret_hits_in_text(text) == []


def test_declared_public_packages_skips_root_init(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A repo-root ``__init__.py`` resolves to an empty package name and is not
    counted (covers the falsy-``dotted`` branch)."""
    import scripts.check_public_release as mod

    root_init = tmp_path / "__init__.py"
    root_init.write_text("\n", encoding="utf-8")
    pkg_init = tmp_path / "pkg" / "__init__.py"
    pkg_init.parent.mkdir()
    pkg_init.write_text("\n", encoding="utf-8")
    monkeypatch.setattr(mod, "_REPO_ROOT", tmp_path)
    pkgs = mod._declared_public_packages([root_init, pkg_init])
    assert pkgs == frozenset({"pkg"})  # root __init__ contributes no package name
