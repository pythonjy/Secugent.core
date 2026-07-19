# SPDX-License-Identifier: Apache-2.0
"""Open-core boundary enforcement (BDP_01 item 1, invariants I1/I2/I3).

These tests are the *fail-closed CI gate* for the open-core split. The file lives
at ``tests/unit/test_open_core_boundary.py`` (NOT top-level ``tests/``) precisely
so the CI ``pytest tests/unit`` step actually collects and runs it — a top-level
``tests/*.py`` file is silently skipped by that rootarg-scoped collection, which
would leave the boundary gate dead (BDP_01 spec, "Failure behavior").

* **I2 (one-directional dependency)** — every Core-tier module (the
  spec-declared Core paths: ``secugent/core``, ``secugent/audit``,
  ``secugent/steer``, the Core orchestrator adapters
  ``secugent/orchestrator/{adapters,mcp_adapter,a2a_adapter}``,
  ``secugent/regulations/tenant_loader`` and ``secugent/observability/metrics``)
  is AST-parsed; importing any Enterprise-tier package (``secugent.enterprise``,
  ``secugent.compliance``, ``secugent.api``, ``secugent.cost``, or top-level
  ``ui``) is a violation — whether written as an absolute import or a *relative*
  one (``from ..enterprise.kms import X``). Relative imports are resolved to
  their absolute target against the importing file's package before matching, so
  a sibling Enterprise package cannot be reached undetected. The allowed
  direction is Enterprise -> Core, never the reverse. ``secugent.observability``
  is Core (Core records into the metric primitives) and is *not* forbidden.
* **I1 (Core boots standalone)** — ``import secugent`` succeeds and a
  ``MockLLMClient`` can be constructed and the default client booted without
  any Enterprise extra installed (no network, no API key).
* **I3 (SPDX consistency)** — every Core/Enterprise ``.py`` file we touched in
  this item carries the SPDX identifier matching its tier.

The boundary is enforced statically (AST) rather than by importing the modules,
so the gate stays deterministic and does not depend on optional Enterprise
dependencies being importable.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

# tests/unit/test_open_core_boundary.py -> tests/unit -> tests -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
SECUGENT_ROOT = REPO_ROOT / "secugent"

# Directories whose every module forms the Apache-2.0 Core and must never depend
# on any Enterprise-tier layer (one-directional dependency, BDP_01 I2). Kept in
# lock-step with the spec Module->Tier table + docs/OPEN_CORE.md.
#   * ``secugent/core``, ``secugent/audit`` — policy engine + hash-chain/Merkle.
#   * ``secugent/steer/*``                  — STEER mid-run intervention (Core).
# (``secugent/orchestrator`` is NOT a whole-dir Core path: only the three
# protocol adapters below are Core; ``runner.py``/``errors.py`` legitimately wire
# Enterprise ``secugent.cost`` quota enforcement and are NOT Core.)
CORE_SCAN_DIRS = (
    SECUGENT_ROOT / "core",
    SECUGENT_ROOT / "audit",
    SECUGENT_ROOT / "steer",
)

# Individual Core-tier modules that live inside an otherwise mixed-tier package
# (so we cannot scan the whole directory). These are the exact Core paths the
# spec declares: the standards-protocol adapters, the single-tenant regulations
# loader, and the Prometheus metric primitives Core records into.
CORE_SCAN_FILES = (
    SECUGENT_ROOT / "orchestrator" / "adapters.py",
    SECUGENT_ROOT / "orchestrator" / "mcp_adapter.py",
    SECUGENT_ROOT / "orchestrator" / "a2a_adapter.py",
    SECUGENT_ROOT / "regulations" / "tenant_loader.py",
    SECUGENT_ROOT / "observability" / "metrics.py",
)

# Non-Core import prefixes that Core/audit code must never reference at load time
# (BDP_01 invariant I2). Kept in lock-step with ENTERPRISE_PACKAGES below and with
# scripts/check_public_release.py FORBIDDEN_IMPORT_PREFIXES — both must list every
# non-Core (Enterprise + D1-deferred) top-level secugent tier, or a Core->non-Core
# load-time leak passes undetected (fail-open).
#   * ``secugent.enterprise`` — the BSL-1.1 package Enterprise code lives in
#     (multitenant admin, external KMS, console/compliance surfaces).
#   * ``secugent.compliance`` — compliance reporting (future Enterprise item).
#   * ``secugent.api``        — the console/SSO API surface (Enterprise).
#   * ``secugent.cost``       — quota *enforcement* wiring (Enterprise).
#   * ``secugent.desktop|evolution|identity|integrations`` — D1-deferred tiers,
#     excluded from the public Core set, so Core must not load-time depend on them.
#   * ``ui``                  — the console (top-level package outside secugent).
# ``secugent.observability`` is deliberately NOT here: Core records into the
# Prometheus metric primitives; only the dashboards/panels are Enterprise.
FORBIDDEN_IMPORT_PREFIXES = (
    "secugent.enterprise",
    "secugent.compliance",
    "secugent.api",
    "secugent.cost",
    "secugent.desktop",
    "secugent.evolution",
    "secugent.identity",
    "secugent.integrations",
    "ui",
)


def _iter_core_py_files() -> list[Path]:
    files: list[Path] = []
    for base in CORE_SCAN_DIRS:
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            files.append(path)
    for path in CORE_SCAN_FILES:
        if path.is_file():
            files.append(path)
    return files


def _module_prefix_matches(name: str, prefix: str) -> bool:
    """True if ``name`` is exactly ``prefix`` or a sub-module of it."""
    return name == prefix or name.startswith(prefix + ".")


def _package_of(path: Path) -> str:
    """Dotted package that *contains* the module at ``path``.

    A relative import is resolved against the importing module's **package**
    (the package the module lives in), mirroring CPython: for a regular module
    ``secugent/core/foo.py`` the package is ``secugent.core``; for a package
    ``__init__.py`` (``secugent/core/__init__.py``) the package is the package
    itself (``secugent.core``). The result is what
    :func:`importlib.util.resolve_name` expects as ``package``.
    """
    rel = path.resolve().relative_to(REPO_ROOT)
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__.py":
        # A package's __init__ — its package is the package dir itself.
        parts = parts[:-1]
    else:
        # A regular module — its package is the directory it sits in.
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_relative(level: int, module: str, package: str) -> str | None:
    """Resolve a relative ``from`` target to its absolute dotted name.

    Mirrors ``importlib.util.resolve_name(('.' * level) + module, package)`` but
    returns ``None`` (instead of raising) if the relative import walks above the
    top-level package — a malformed import that importlib would reject anyway.
    """
    bits = package.rsplit(".", level - 1)
    if len(bits) < level:
        # Walks past the top-level package — importlib would raise ImportError.
        return None
    base = bits[0]
    return f"{base}.{module}" if module else base


def _is_type_checking_guard(node: ast.If) -> bool:
    """True if ``node`` is an ``if TYPE_CHECKING:`` / ``if typing.TYPE_CHECKING:``
    block. Imports inside it are runtime-erased (type-only) and never execute at
    module import, so they are not a load-time dependency on the tier."""
    test = node.test
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    if isinstance(test, ast.Attribute):
        return test.attr == "TYPE_CHECKING"
    return False


def _forbidden_in_import_node(node: ast.stmt, *, package: str | None) -> list[str]:
    found: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            for prefix in FORBIDDEN_IMPORT_PREFIXES:
                if _module_prefix_matches(alias.name, prefix):
                    found.append(alias.name)
    elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        if node.level and node.level > 0:
            # Relative import: resolve to its absolute target against the
            # importing file's package before matching. A sibling Enterprise
            # package (``from ..enterprise.kms import X`` in secugent/core)
            # resolves to ``secugent.enterprise.kms`` and is caught.
            if package is None:
                return found
            resolved = _resolve_relative(node.level, module, package)
            if resolved is None:
                return found
            module = resolved
        for prefix in FORBIDDEN_IMPORT_PREFIXES:
            if _module_prefix_matches(module, prefix):
                found.append(module)
    return found


def _forbidden_imports_in_source(
    source: str, filename: str = "<test>", *, package: str | None = None
) -> list[str]:
    """Return forbidden import names that EXECUTE at module import (BDP_01 I2).

    Only load-time imports count (the invariant is "Core boots / imports without
    any non-Core tier"). Imports under ``if TYPE_CHECKING:`` (runtime-erased) and
    imports nested in a function/method body (lazy — only run when called) are
    NOT load-time dependencies and are excluded — mirroring the release gate
    (scripts/check_public_release.py) so the two boundary gates stay in
    lock-step. A *module-level* forbidden import is still flagged.

    ``package`` is the dotted package the source module lives in; required to
    resolve relative imports to their absolute target. When ``None`` relative
    imports are skipped — callers scanning real Core files always pass it.
    """
    tree = ast.parse(source, filename=filename)
    violations: list[str] = []

    def scan_top_level(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                violations.extend(_forbidden_in_import_node(node, package=package))
            elif isinstance(node, ast.If):
                if _is_type_checking_guard(node):
                    continue
                scan_top_level(node.body)
                scan_top_level(node.orelse)
            elif isinstance(node, ast.Try):
                scan_top_level(node.body)
                for handler in node.handlers:
                    scan_top_level(handler.body)
                scan_top_level(node.orelse)
                scan_top_level(node.finalbody)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                scan_top_level(node.body)
            # def/async def/class bodies do not run at import -> not descended.

    scan_top_level(tree.body)
    return violations


def _forbidden_imports_in(path: Path) -> list[str]:
    """Return the forbidden import names referenced by the file at ``path``."""
    return _forbidden_imports_in_source(
        path.read_text(encoding="utf-8"), str(path), package=_package_of(path)
    )


def test_core_scan_dirs_exist() -> None:
    """The Core directories we enforce on must actually exist."""
    for base in CORE_SCAN_DIRS:
        assert base.is_dir(), f"expected Core directory missing: {base}"


def test_core_files_discovered() -> None:
    """Sanity: the scan must find a non-trivial number of Core modules."""
    files = _iter_core_py_files()
    assert len(files) >= 10, f"expected to scan many Core modules, found {len(files)}"


def test_scan_covers_every_spec_declared_core_path() -> None:
    """I2 coverage: the boundary scan must include EVERY Core-tier path the spec
    declares — not just core/ + audit/. A Core module under steer/, the
    orchestrator protocol adapters, the single-tenant regulations loader, or the
    observability metric primitives importing Enterprise must be visible to the
    gate (else the 'fail-closed' guarantee is only delivered for two dirs)."""
    scanned = {p.resolve() for p in _iter_core_py_files()}
    required = [
        SECUGENT_ROOT / "steer" / "steer.py",
        SECUGENT_ROOT / "orchestrator" / "adapters.py",
        SECUGENT_ROOT / "orchestrator" / "mcp_adapter.py",
        SECUGENT_ROOT / "orchestrator" / "a2a_adapter.py",
        SECUGENT_ROOT / "regulations" / "tenant_loader.py",
        SECUGENT_ROOT / "observability" / "metrics.py",
    ]
    missing = [str(p.relative_to(REPO_ROOT)) for p in required if p.resolve() not in scanned]
    assert not missing, f"Core-tier paths not covered by the boundary scan: {missing}"


def test_no_core_module_imports_enterprise() -> None:
    """I2: no module under core/ or audit/ imports an Enterprise-tier package."""
    offending: dict[str, list[str]] = {}
    for path in _iter_core_py_files():
        violations = _forbidden_imports_in(path)
        if violations:
            offending[str(path.relative_to(REPO_ROOT))] = violations
    assert not offending, (
        f"Open-core boundary violation (Core/audit must not import Enterprise tiers): {offending}"
    )


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # ``import secugent.enterprise.kms`` — the most important Enterprise pkg.
        ("import secugent.enterprise.kms\n", ["secugent.enterprise.kms"]),
        # ``from secugent.enterprise.tenant_admin import X``.
        (
            "from secugent.enterprise.tenant_admin import TenantAdminService\n",
            ["secugent.enterprise.tenant_admin"],
        ),
        # ``from secugent.cost.accounting import X`` — quota enforcement.
        ("from secugent.cost.accounting import CostLedger\n", ["secugent.cost.accounting"]),
        # ``import secugent.cost``.
        ("import secugent.cost\n", ["secugent.cost"]),
        # Other Enterprise tiers stay caught.
        ("from secugent.compliance import report\n", ["secugent.compliance"]),
        ("from secugent.api.main import create_app\n", ["secugent.api.main"]),
        ("import ui.console\n", ["ui.console"]),
    ],
)
def test_detector_flags_every_enterprise_tier(source: str, expected: list[str]) -> None:
    """The detector must catch EACH forbidden tier — guards against a stale
    FORBIDDEN_IMPORT_PREFIXES set that silently under-enforces I2 (the exact
    false-negative the review found for secugent.enterprise / secugent.cost)."""
    assert _forbidden_imports_in_source(source) == expected


@pytest.mark.parametrize(
    ("source", "package", "expected"),
    [
        # ``from ..enterprise.kms import X`` written in a secugent/core module
        # resolves to secugent.enterprise.kms — a real Core->Enterprise leak that
        # the old blanket relative-import skip let through (fail-open gate).
        (
            "from ..enterprise.kms import AwsKmsProvider\n",
            "secugent.core",
            ["secugent.enterprise.kms"],
        ),
        # Deeper module, deeper relative: secugent/orchestrator/adapters.py doing
        # ``from ...enterprise import x`` (level=3) -> secugent.enterprise.
        (
            "from ...enterprise import kms\n",
            "secugent.orchestrator.adapters",
            ["secugent.enterprise"],
        ),
        # Relative reach into cost-quota enforcement from audit/.
        (
            "from ..cost.accounting import CostLedger\n",
            "secugent.audit",
            ["secugent.cost.accounting"],
        ),
        # Relative within Core (``from ..core import thing`` in audit) is allowed.
        ("from ..core import thing\n", "secugent.audit", []),
        # Single-dot relative (same package) is always Core-local -> allowed.
        ("from . import sibling\n", "secugent.core", []),
        # Relative into observability (Core metric primitives) is allowed.
        ("from ..observability.metrics import APPROVAL_WAIT\n", "secugent.steer", []),
    ],
)
def test_detector_resolves_relative_enterprise_imports(
    source: str, package: str, expected: list[str]
) -> None:
    """A Core module can reach a *sibling* Enterprise package with a relative
    import (``from ..enterprise...``). The detector must resolve the relative
    target against the importing file's package and flag it — the prior blanket
    ``continue`` on every relative import made the fail-closed gate bypassable
    (BDP_01 I2, license boundary). Core-internal relatives must stay allowed."""
    assert _forbidden_imports_in_source(source, package=package) == expected


def test_detector_allows_core_and_observability() -> None:
    """Allowed Core imports (incl. observability and Core-internal relative
    imports) must not false-trigger the gate. Relative imports here resolve to
    Core targets (``secugent.core``) against the importing package, so they are
    legitimately allowed — unlike a relative reach into a sibling Enterprise
    package, which is covered by test_detector_resolves_relative_enterprise_imports."""
    allowed = (
        "from secugent.core.contracts import Event\n"
        "from secugent.audit.merkle import KmsProvider\n"
        "from secugent.observability.metrics import APPROVAL_WAIT\n"
        "from . import sibling\n"
        "from ..core import thing\n"
    )
    assert _forbidden_imports_in_source(allowed, package="secugent.audit") == []


def test_import_secugent_without_enterprise_extra() -> None:
    """I1: plain ``import secugent`` works with no Enterprise extra installed."""
    import secugent

    assert secugent.__version__


def test_mock_llm_client_boots_without_enterprise() -> None:
    """I1: a MockLLMClient can be constructed and the default client booted."""
    from secugent.core.llm_client import MockLLMClient, get_default_client

    client = MockLLMClient(["{}"])
    out = client.generate(model="mock", system="s", messages=[{"role": "user", "content": "hi"}])
    assert out == "{}"

    # Default client resolution must not require any Enterprise dependency and,
    # absent an API key in dev/test, must return a usable mock.
    default = get_default_client()
    assert default is not None


def test_enterprise_guard_raises_actionable_error() -> None:
    """The lazy-import guard must raise a clear, actionable install error."""
    from secugent import EnterpriseFeatureUnavailable, require_enterprise

    with pytest.raises(EnterpriseFeatureUnavailable) as excinfo:
        require_enterprise(
            feature="AWS KMS signing",
            module="boto3",
            extra="enterprise",
        )
    message = str(excinfo.value)
    assert "AWS KMS signing" in message
    assert "pip install" in message
    assert "enterprise" in message


def test_enterprise_extra_is_declared_in_pyproject() -> None:
    """The ``enterprise`` extra the guard's remedy advertises must actually
    resolve: ``pip install 'secugent[enterprise]'`` cannot work unless the extra
    is declared in pyproject. Asserting the substring in the message is not
    enough — this checks the remedy is real."""
    import tomllib

    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    extras = pyproject["project"]["optional-dependencies"]
    assert "enterprise" in extras, "the 'enterprise' optional-dependency extra is missing"


def _pyproject_setuptools_find() -> dict[str, list[str]]:
    """The ``[tool.setuptools.packages.find]`` include/exclude config from
    pyproject — the single source of truth for what the wheel/sdist physically
    ships. Read once here so the discovery replica and the exclude cross-check
    (below) agree on exactly what setuptools will do."""
    import tomllib

    cfg = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    find = cfg["tool"]["setuptools"]["packages"]["find"]
    assert isinstance(find, dict)
    return find


def _discovered_core_packages() -> set[str]:
    """Replicate setuptools ``[tool.setuptools.packages.find]`` discovery from
    pyproject (include/exclude fnmatch globs) without importing setuptools.

    setuptools enumerates every importable package under the project root, keeps
    those matching any ``include`` glob, then drops those matching any
    ``exclude`` glob (``pkg*`` also matches the package itself, not just its
    children). We mirror that exactly so the test asserts what actually ships.
    """
    import fnmatch

    find = _pyproject_setuptools_find()
    include: list[str] = find.get("include", ["*"])
    exclude: list[str] = find.get("exclude", [])

    packages: set[str] = set()
    for init in REPO_ROOT.rglob("__init__.py"):
        if "__pycache__" in init.parts:
            continue
        rel = init.parent.relative_to(REPO_ROOT)
        dotted = ".".join(rel.parts)
        if not dotted:
            continue
        if any(fnmatch.fnmatch(dotted, pat) for pat in include) and not any(
            fnmatch.fnmatch(dotted, pat) for pat in exclude
        ):
            packages.add(dotted)
    return packages


def test_core_wheel_excludes_enterprise_packages() -> None:
    """Compliance (BDP_01 I2, license boundary): NONE of the BSL-1.1/Enterprise
    tiers may be packaged into the Apache-2.0 Core distribution — not just
    ``secugent.enterprise`` but every tier ``docs/OPEN_CORE.md`` classifies as
    ``LicenseRef-SecuGent-Enterprise`` (W8 A4: api/cost/compliance/evolution/
    identity/integrations/desktop/playbooks all shipped into the Core wheel
    before this gate — 55 Enterprise .py files — because the exclude list named
    only ``secugent.enterprise*``). The AST gate only checks import *direction*;
    this checks *shipping* tiers — the other half of I2.

    Single source of truth: the expected Enterprise set is ``ENTERPRISE_PACKAGES``
    (kept in lock-step with ``docs/OPEN_CORE.md`` by
    ``test_tier_sets_match_open_core_doc``), and we also assert the pyproject
    ``exclude`` list covers every one of those tiers. So adding a tier to
    OPEN_CORE without excluding it in ``pyproject.toml`` fails here — no drift."""
    import fnmatch

    discovered = _discovered_core_packages()

    # (1) No discovered (i.e. shipped) Core package may BE, or live under, any
    # Enterprise tier. This is what ``pip install secugent`` actually delivers.
    leaked = sorted(
        pkg for pkg in discovered if any(_module_prefix_matches(pkg, tier) for tier in ENTERPRISE_PACKAGES)
    )
    assert not leaked, (
        "Enterprise-tier packages must be excluded from the Apache-2.0 Core wheel "
        "via [tool.setuptools.packages.find] exclude (align it with the "
        f"docs/OPEN_CORE.md Enterprise tier list), but were discovered: {leaked}"
    )

    # (2) Sanity — discovery must still find the Core package AND the mixed-tier
    # Core packages (orchestrator/agents/models stay Core; their Enterprise-coupled
    # modules rely on lazy import + the git manifest, NOT package-level exclusion).
    # Guards both a broken matcher that vacuously passes by discovering nothing and
    # an over-broad exclude glob that accidentally drops a Core package.
    for core_pkg in (
        "secugent",
        "secugent.core",
        "secugent.audit",
        "secugent.cli",
        "secugent.orchestrator",
        "secugent.agents",
        "secugent.models",
    ):
        assert core_pkg in discovered, (
            f"Core package {core_pkg!r} is missing from wheel discovery — the "
            "exclude glob is either broken (matches nothing) or over-broad "
            "(dropped a Core/mixed tier that must ship)."
        )

    # (3) Cross-check (drift guard): every OPEN_CORE Enterprise tier must be
    # covered by a pyproject exclude glob. Because ``_discovered_core_packages``
    # only surfaces packages that exist on disk, a tier declared in OPEN_CORE but
    # (re)moved could slip past (1); this makes the exclude list itself the
    # asserted contract against ``ENTERPRISE_PACKAGES``.
    exclude = _pyproject_setuptools_find().get("exclude", [])
    uncovered = sorted(
        tier for tier in ENTERPRISE_PACKAGES if not any(fnmatch.fnmatch(tier, pat) for pat in exclude)
    )
    assert not uncovered, (
        "every Enterprise tier in docs/OPEN_CORE.md must have a matching "
        "[tool.setuptools.packages.find] exclude glob (e.g. 'secugent.api*'), "
        f"but these are not excluded and would ship in the Core wheel: {uncovered}"
    )


def test_committed_sources_manifest_omits_enterprise_modules() -> None:
    """If a setuptools SOURCES.txt manifest is committed, it must not list ANY
    Enterprise-tier ``.py`` source — for every tier in ``docs/OPEN_CORE.md``, not
    just ``secugent/enterprise/`` (W8 A4: the last build shipped api/cost/…/
    playbooks sources into the Core sdist while this test only checked
    ``enterprise/`` — a false-green). A listed Enterprise source means the last
    build packaged commercial code into the Apache-2.0 Core distribution. Skips
    cleanly when no manifest is committed."""
    manifest = REPO_ROOT / "secugent.egg-info" / "SOURCES.txt"
    if not manifest.is_file():
        pytest.skip("no committed SOURCES.txt build manifest")
    # secugent.api -> "secugent/api/" ; single source of truth = ENTERPRISE_PACKAGES.
    enterprise_prefixes = tuple(sorted(tier.replace(".", "/") + "/" for tier in ENTERPRISE_PACKAGES))
    listed = [
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip().endswith(".py") and line.strip().startswith(enterprise_prefixes)
    ]
    assert not listed, (
        "SOURCES.txt lists Enterprise-tier modules as shipped in the Apache-2.0 "
        "Core distribution — rebuild after aligning [tool.setuptools.packages.find] "
        f"exclude with docs/OPEN_CORE.md: {listed}"
    )


def test_open_core_doc_and_license_artifacts_exist() -> None:
    """DoD: the dual-license + tier-mapping artifacts the code/docstrings point
    at must exist on disk (no dangling references shipped in the package)."""
    for rel in ("LICENSE", "LICENSE.enterprise", "NOTICE", "docs/OPEN_CORE.md"):
        assert (REPO_ROOT / rel).is_file(), f"missing required artifact: {rel}"


def test_touched_files_have_tier_spdx_header() -> None:
    """I3: files created/modified in this item carry the SPDX id of their tier.

    Several entries (``scripts/apply_spdx.py``, the whole ``secugent/enterprise``
    tier) are EXCLUDED from the public release manifest and are therefore absent
    in the extracted public repo. This test ships, so it must not hard-fail there:
    a missing expected file is skipped (the header it would assert lives only in
    the private/source repo), while every present file is still verified — the
    guarantee that matters in the public Core is the Apache header on the files
    that DO ship (Invariant I8 — the extract's ``pytest -q`` must not error)."""
    apache = "# SPDX-License-Identifier: Apache-2.0"
    enterprise = "# SPDX-License-Identifier: LicenseRef-SecuGent-Enterprise"
    expected_by_path: dict[Path, str] = {
        SECUGENT_ROOT / "__init__.py": apache,
        SECUGENT_ROOT / "audit" / "merkle.py": apache,
        Path(__file__): apache,
        REPO_ROOT / "scripts" / "apply_spdx.py": apache,
        SECUGENT_ROOT / "enterprise" / "__init__.py": enterprise,
        SECUGENT_ROOT / "enterprise" / "kms.py": enterprise,
        SECUGENT_ROOT / "enterprise" / "tenant_admin.py": enterprise,
    }
    checked = 0
    for path, marker in expected_by_path.items():
        if not path.is_file():  # pragma: no cover - only in the extracted public repo
            # Excluded-from-public file, absent in the extract — skip its check.
            continue
        head = path.read_text(encoding="utf-8").splitlines()[:5]
        assert any(line.strip() == marker for line in head), (
            f"missing or wrong SPDX header in {path} (expected {marker!r})"
        )
        checked += 1
    # Guard against a vacuous pass: the always-shipping Apache files must exist
    # and be verified even in the extract (this test file itself is one of them).
    assert checked >= 2, "expected at least the always-public SPDX files to be present"


# ---------------------------------------------------------------------------
# BDP_05 항목 1 — 모듈 티어 확정 (미분류 0 게이트)
# ---------------------------------------------------------------------------

# 공개 Core 패키지 집합 (top-level secugent 하위 패키지 + 최상위 secugent).
# 혼합 패키지(orchestrator/agents/models)는 패키지 자체를 Core로 분류하되,
# 실제 공개 manifest는 파일 수준 정밀도로 Enterprise 연동 파일을 제외한다.
# config.py는 패키지가 아닌 단일 모듈이므로 상수에 포함하지 않는다.
PUBLIC_CORE_PACKAGES: frozenset[str] = frozenset(
    {
        "secugent",
        "secugent.core",
        "secugent.audit",
        "secugent.steer",
        "secugent.observability",
        "secugent.sdk",
        "secugent.cli",
        "secugent.regulations",
        "secugent.tools",
        "secugent.io",
        "secugent.db",
        "secugent.prompts",
        "secugent.deploy",
        # 혼합 패키지: 패키지 자체는 Core, 일부 파일은 manifest exclude
        "secugent.orchestrator",
        "secugent.agents",
        "secugent.models",
    }
)

# 완전 Enterprise 패키지 집합 (공개 불가 — D1 결정 포함).
# D1 결정: evolution/identity/integrations/desktop은 AST clean이나
#           P2 옵셔널·설계 의존·리스크 검토를 이유로 ENTERPRISE 유지.
ENTERPRISE_PACKAGES: frozenset[str] = frozenset(
    {
        "secugent.enterprise",
        "secugent.compliance",
        "secugent.cost",
        "secugent.api",
        "secugent.evolution",  # D1: P2 옵셔널, 공개 시 가치/리스크 검토 필요
        "secugent.identity",  # D1: P2 옵셔널, registry.py가 secugent.api.rbac 설계 의존
        "secugent.integrations",  # D1: P2 옵셔널 외부 커넥터
        "secugent.desktop",  # D1: 데스크톱 자동화 최후수단, §A-1 Non-goal 준용
        # playbooks(06-14 데스크톱 셸 기능)는 router.py가 secugent.api.security,
        # wire.py가 secugent.api.main(AppState)을 import → Enterprise(api) 결합.
        # Core는 Enterprise를 import할 수 없으므로(단방향 의존 I2) Enterprise 티어 확정.
        "secugent.playbooks",
    }
)


def _real_top_level_secugent_packages() -> set[str]:
    """secugent/ 하위의 실제 top-level 패키지 집합을 디스크에서 도출한다.

    ``secugent/tests/`` 는 ``__init__.py`` 없는 빈 디렉터리이므로 Python 패키지가
    아니어서 setuptools 디스커버리 대상이 아니다. 본 함수도 동일 기준으로 제외한다
    (공개 manifest 결정: 내용 없음으로 생략).
    ``__pycache__`` 는 가상 패키지이므로 무시한다.
    """
    packages: set[str] = set()
    for entry in SECUGENT_ROOT.iterdir():
        if not entry.is_dir():
            continue
        if entry.name.startswith("__"):
            continue
        # Python 패키지 성립 기준: __init__.py 존재
        if not (entry / "__init__.py").is_file():
            continue
        packages.add(f"secugent.{entry.name}")
    # 최상위 secugent 자체도 포함 (secugent/__init__.py 존재)
    packages.add("secugent")
    return packages


def test_every_top_level_package_has_a_tier() -> None:
    """I1 (미분류 0): secugent/* 모든 하위 패키지는 정확히 하나의 티어에 속해야 한다.

    두 집합이 서로소이고, 합집합이 디스크의 실제 top-level 패키지 전체를 덮어야 한다.
    신규 패키지가 추가되면 이 테스트가 실패해 티어 지정을 강제한다.
    secugent/tests/은 __init__.py 없어 Python 패키지 미성립이므로 검사 대상 제외.
    """
    # 두 집합이 서로소인지 검증
    overlap = PUBLIC_CORE_PACKAGES & ENTERPRISE_PACKAGES
    assert not overlap, (
        f"PUBLIC_CORE_PACKAGES와 ENTERPRISE_PACKAGES가 겹칩니다(동시 분류 불가): {sorted(overlap)}"
    )

    # 디스크의 실제 패키지 집합
    actual = _real_top_level_secugent_packages()

    # 합집합이 실제 패키지를 전부 커버하는지 검증 (미분류 = fail)
    classified = PUBLIC_CORE_PACKAGES | ENTERPRISE_PACKAGES
    unclassified = actual - classified
    assert not unclassified, (
        "미분류 패키지 발견 — PUBLIC_CORE_PACKAGES 또는 ENTERPRISE_PACKAGES에 추가하세요: "
        f"{sorted(unclassified)}"
    )

    # 선언된 패키지가 모두 디스크에 실제 존재하는지 검증 (환상 등재 = fail)
    phantom = classified - actual
    assert not phantom, (
        f"티어 상수에 등재됐으나 디스크에 존재하지 않는 패키지(오타 또는 삭제 후 미정리): {sorted(phantom)}"
    )


def test_tier_sets_match_open_core_doc() -> None:
    """I3 (드리프트 0): PUBLIC_CORE_PACKAGES와 ENTERPRISE_PACKAGES가
    docs/OPEN_CORE.md의 티어 표와 동기화돼 있어야 한다.

    이 테스트는 OPEN_CORE.md가 최소한 Core 패키지와 Enterprise 패키지 이름을
    언급하고 있는지 확인한다. 문서 누락(드리프트)이 있으면 즉시 실패한다.
    """
    doc_path = REPO_ROOT / "docs" / "OPEN_CORE.md"
    assert doc_path.is_file(), f"docs/OPEN_CORE.md 파일이 없습니다: {doc_path}"
    doc_text = doc_path.read_text(encoding="utf-8")

    # Core 패키지: secugent 최상위 자체와 config.py는 문서에 경로 형태로 표기되므로 제외.
    # 하위 패키지명(점 표기 → 슬래시 경로 또는 점 표기 모두 허용)이 문서에 있어야 한다.
    core_check = PUBLIC_CORE_PACKAGES - {"secugent"}
    missing_core: list[str] = []
    for pkg in sorted(core_check):
        # "secugent.core" -> "secugent/core" or "secugent.core" 중 하나라도 있으면 통과
        slash_form = pkg.replace(".", "/")
        dot_form = pkg
        if slash_form not in doc_text and dot_form not in doc_text:
            missing_core.append(pkg)

    missing_ent: list[str] = []
    for pkg in sorted(ENTERPRISE_PACKAGES):
        slash_form = pkg.replace(".", "/")
        dot_form = pkg
        if slash_form not in doc_text and dot_form not in doc_text:
            missing_ent.append(pkg)

    errors: list[str] = []
    if missing_core:
        errors.append(f"docs/OPEN_CORE.md에 누락된 PUBLIC_CORE 패키지(드리프트): {missing_core}")
    if missing_ent:
        errors.append(f"docs/OPEN_CORE.md에 누락된 ENTERPRISE 패키지(드리프트): {missing_ent}")
    assert not errors, "\n".join(errors)
