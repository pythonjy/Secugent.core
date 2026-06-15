# SPDX-License-Identifier: Apache-2.0
"""Fail-closed public-release gate (BDP_05 item 2).

This is the deterministic CI gate that decides whether the curated public file
set (selected by ``release/public_manifest.yaml``) is safe to ship as the
``secugent-core`` OSS repo. It enforces three invariants, in order, and exits
non-zero if *any* of them is violated (fail-closed — silence is never success):

* **I4 deny-by-default** (:func:`public_files`) — a repo path is public iff it
  matches at least one ``include`` glob AND zero ``exclude`` globs. A new
  *top-level* package/file not named by any include is private by default. NOTE
  the broad recursive includes (``secugent/core/**``, ``docs/security/**``,
  ``tests/**``, ``.github/workflows/**``) are *allow-by-default within their
  subtree*: a new file added under them ships automatically and is caught only by
  the content/closure scanners, so high-sensitivity files under a broad include
  must be excluded explicitly. The result is sorted + deterministic (I6).
* **I2 import-closure** (:func:`assert_import_closure`) — every public ``.py`` is
  AST-parsed (relative imports resolved to absolute); importing a private tier
  (``secugent.enterprise|compliance|cost|api|desktop|evolution|identity|
  integrations`` or top-level ``ui``) is a violation. The deny-set
  (:data:`FORBIDDEN_IMPORT_PREFIXES`) is asserted to cover EVERY top-level
  ``secugent`` tier the manifest wholesale-excludes (so it can never silently
  drift fail-open). A ``SyntaxError`` is itself a violation (never silently skipped).
  Beyond whole tiers, the gate ALSO flags a load-time import that resolves to a
  *file-level excluded sibling* — a module that exists in the working tree but is
  NOT in the public set (e.g. a shipping ``__init__.py`` doing
  ``from secugent.orchestrator.runner import X`` when ``runner.py`` is excluded).
  Such an import compiles fine in the source repo but raises
  ``ModuleNotFoundError`` in the extracted public repo, so it would make the gate
  fail-open on a non-self-contained set (Invariant I8). This is detected by
  resolving the dotted import target to its candidate ``.py`` paths and checking
  them against the set of excluded-but-existing repo files.
* **I5 forbidden-content** (:func:`scan_forbidden_content`) — no internal
  strategy doc (``CLAUDE.md``, ``Review/``, ``docs/specs/``, the Korean strategy
  HTMLs, …) and no real secret (API key / token / password / ``.env``) may
  appear in the public set. Documented placeholders (``change-me-*``) are not
  secrets. Beyond file NAMES, the prose of every shipped public document
  (``.md``/``.txt``/``.rst``/``.yaml`` at the repo root or under
  ``docs/``/``release/``) is scanned for UNAMBIGUOUS internal tokens
  (``Project_Secugent``, ``DEPLOY_PROGRESS``, ``BDP_REFORMED``, ``Review/``,
  ``docs/specs/``): a clean path is not enough — a CHANGELOG/runbook body line can
  still name-drop the private tree (CHG-2). The two boundary-machinery files
  (``release/public_manifest.yaml``, ``release/PUBLIC_RELEASE_RUNBOOK.md``) that
  must name the excluded paths are tightly allowlisted.

CRITICAL: every check operates on the *manifest-selected* public set, NOT the
whole repo. The live repo deliberately still contains CLAUDE.md / Review/ /
docs/specs/ / strategy HTMLs — running this gate on the current repo MUST exit 0
because the manifest EXCLUDES them. A whole-repo scan would always fail; that
would be a bug.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Final

import yaml

# scripts/check_public_release.py -> scripts -> repo root.
_REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
_DEFAULT_MANIFEST: Final[Path] = _REPO_ROOT / "release" / "public_manifest.yaml"

# Directory names never walked when enumerating the working tree: VCS metadata,
# byte-compiled caches, JS deps, and build artifacts. Excluding them keeps
# enumeration deterministic and avoids classifying transient files.
_SKIP_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        "__pycache__",
        "node_modules",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        # Agent-pipeline git worktrees + harness state live under .claude/ — these
        # are NOT repo content (they are full copies of the tree) and must never
        # be enumerated as release candidates. The manifest also excludes
        # ".claude/**", but skipping the directory at walk time is the primary
        # guard (and avoids classifying tens of thousands of copied files).
        ".claude",
    }
)
_SKIP_DIR_SUFFIXES: Final[tuple[str, ...]] = (".egg-info",)

# Private (non-public) import prefixes a public Core module must never reach
# (Invariant I2). This MUST cover every top-level secugent package the manifest
# excludes from the public set — otherwise a public .py importing an excluded
# tier (e.g. ``secugent.desktop`` from tools/router.py) passes the closure gate
# undetected (fail-open). The four D1-deferred tiers (desktop/evolution/identity/
# integrations) are excluded by release/public_manifest.yaml exactly like the
# four always-Enterprise tiers, so they belong here too. Kept in lock-step with
# the boundary gate (tests/unit/test_open_core_boundary.py ENTERPRISE_PACKAGES)
# and asserted equal to the manifest's excluded top-level packages by
# tests/release/test_public_release_manifest.py.
FORBIDDEN_IMPORT_PREFIXES: Final[tuple[str, ...]] = (
    # Always-Enterprise (BSL-1.1) tiers.
    "secugent.enterprise",
    "secugent.compliance",
    "secugent.api",
    "secugent.cost",
    # D1-deferred tiers — source is EXCLUDED from the public set, so a public
    # module importing them would break self-containment (I8) and leak the tier.
    "secugent.desktop",
    "secugent.evolution",
    "secugent.identity",
    "secugent.integrations",
    # The console UI is a top-level package outside ``secugent``.
    "ui",
)

# Internal-strategy / process files that must never ship publicly, matched by
# exact repo-relative POSIX path OR by basename. Defence-in-depth behind the
# manifest `exclude` globs: even if a glob is mistyped, this list still catches
# the canonical leak paths (closure risks R7, R8).
_FORBIDDEN_BASENAMES: Final[frozenset[str]] = frozenset(
    {"CLAUDE.md", "SECURITY_CONTRACT.md", "DEPLOY_PROGRESS.md", "report_1.md"}
)
# Path *prefixes* (repo-relative POSIX) whose entire subtree is internal-only.
_FORBIDDEN_PATH_PREFIXES: Final[tuple[str, ...]] = (
    "Review/",
    "BDP_REFORMED/",
    "docs/specs/",
    ".claude/",
    ".secugent/",
    "data/",
)
# Hangul substrings that mark Korean internal strategy/market artifacts. Checked
# directly against the filename (NOT via fnmatch) so a glob-engine unicode quirk
# cannot let ``*시장진단*.html`` / ``*로우리스크*.html`` leak (closure risk R12).
_FORBIDDEN_HANGUL_SUBSTRINGS: Final[tuple[str, ...]] = ("시장진단", "로우리스크", "전략")

# Internal tokens that must never appear in the PROSE of a shipped public text
# file (CHG-2). Unlike the filename gates above, a manifest that excludes
# ``Review/`` cannot stop a *body* line of CHANGELOG.md / the runbook from
# name-dropping the private source tree — that leaks internal structure even
# though the path itself is clean. Each entry is an UNAMBIGUOUS token that is
# never legitimate inside the body of a public document:
#
# * ``Project_Secugent`` — the private source-repo directory name (no public use);
# * ``DEPLOY_PROGRESS`` / ``BDP_REFORMED`` — internal process/roadmap artifacts;
# * ``Review/`` / ``docs/specs/`` — internal-only path prefixes.
#
# Checked as DIRECT substrings (mirroring :data:`_FORBIDDEN_HANGUL_SUBSTRINGS`),
# NOT as globs, so the gate is deterministic and version-independent. We do NOT
# scan for excluded-tier *module* names (``enterprise``, ``cost`` …): README /
# OPEN_CORE / RELEASE_NOTES / CONTRIBUTING legitimately describe the open-core
# boundary, so a module-name scan would be a false-positive factory. Keeping the
# token list to genuinely-internal markers keeps this gate false-positive-free.
_FORBIDDEN_PROSE_SUBSTRINGS: Final[tuple[str, ...]] = (
    "Project_Secugent",
    "DEPLOY_PROGRESS",
    "BDP_REFORMED",
    "Review/",
    "docs/specs/",
)

# Public text files that legitimately CONTAIN the forbidden prose tokens because
# their whole job is to DEFINE / VERIFY the open-core boundary, where naming the
# excluded paths is unavoidable and correct:
#
# * ``release/public_manifest.yaml`` — its ``exclude:`` list literally names
#   ``Review/**`` / ``docs/specs/**`` / ``DEPLOY_PROGRESS.md`` / ``BDP_REFORMED/**``;
# * ``release/PUBLIC_RELEASE_RUNBOOK.md`` — the extraction runbook documents the
#   ``git log -- <path>`` leak-check commands that grep the *extracted* history for
#   exactly these tokens and assert the output is empty (proving they did NOT leak).
#
# This allowlist is deliberately TIGHT: exactly the two boundary-machinery files,
# matched by exact repo-relative POSIX path. Every other shipped text file is
# scanned with zero tolerance. A new file is NOT covered unless added here.
_PROSE_SCAN_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "release/public_manifest.yaml",
        "release/PUBLIC_RELEASE_RUNBOOK.md",
    }
)

# Repo-relative top-level directories whose shipped text files carry public-facing
# prose worth scanning for internal tokens, plus the repo root itself. Scoped this
# way (docs/release/root) because that is where curated narrative (README,
# CHANGELOG, OPEN_CORE, runbook, release notes, threat model) lives; source-tree
# ``.yaml`` fixtures and test data are out of scope for the PROSE gate.
_PROSE_SCAN_TOP_DIRS: Final[frozenset[str]] = frozenset({"docs", "release"})
# File extensions a public *document* uses (a subset of _TEXT_SUFFIXES). The prose
# gate scans only these; code/config text (``.py``, ``.toml``, ``.sh`` …) is not a
# narrative surface and is covered by the closure/secret gates instead.
_PROSE_SCAN_SUFFIXES: Final[frozenset[str]] = frozenset({".md", ".txt", ".rst", ".yaml"})

# Secret-bearing filenames (a literal ``.env`` is a secret store; ``.env.example``
# is a documented template and is allowed).
_SECRET_FILENAMES: Final[frozenset[str]] = frozenset({".env"})
_SECRET_FILE_SUFFIXES: Final[tuple[str, ...]] = (".pem", ".key", ".pfx", ".p12")

# Substrings that mark a value as a deliberate placeholder, NOT a real secret.
# `.env.example` ships ``change-me-*`` placeholders by design — flagging those
# would make the gate cry wolf and get disabled.
_PLACEHOLDER_MARKERS: Final[tuple[str, ...]] = (
    "change-me",
    "changeme",
    "your-",
    "your_",
    "example",
    "placeholder",
    "<",
    "xxxx",
    "dummy",
    "redacted",
    "${",
)

# Real-secret signatures. Each pattern targets a high-confidence credential shape
# so documented placeholders and ordinary prose do not false-positive. These are
# DETECTION patterns, not secrets themselves (hence the per-line S105/S106 noqa).
_SECRET_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    # AWS access key id.
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),  # noqa: S105
    # Anthropic / OpenAI style API key (sk-...).
    ("provider-api-key", re.compile(r"\bsk-[A-Za-z0-9._-]{16,}\b")),  # noqa: S105
    # GitHub personal access / fine-grained tokens.
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),  # noqa: S105
    # Slack token.
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),  # noqa: S105
    # JSON Web Token (three base64url segments).
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    # PEM private key block.
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    # Generic ``SECRET/TOKEN/PASSWORD/API_KEY = "<opaque literal>"`` assignment.
    # The value MUST be a quoted string literal (single or double quote) — bare
    # right-hand sides like ``token, = ...`` / ``self._api_key)`` / ``Token[X]``
    # are Python code, not credentials, and must NOT trip the gate. The captured
    # value is further vetted by :func:`_looks_like_secret_value` (entropy + not a
    # code token), so only genuinely opaque literals are reported.
    (
        "hardcoded-credential-assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b"
            r"\s*[:=]\s*(['\"])([^'\"\s#]{12,})\1"
        ),
    ),
)
# Files whose own job is to *define* secret-detection patterns. Scanning them for
# secret patterns would self-trip; they carry only regexes + placeholders.
_SECRET_SCAN_SELF_EXEMPT: Final[frozenset[str]] = frozenset(
    {"scripts/check_public_release.py", "tests/release/test_public_release_manifest.py"}
)

_TEXT_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        ".py",
        ".md",
        ".txt",
        ".yaml",
        ".yml",
        ".toml",
        ".cfg",
        ".ini",
        ".json",
        ".env",
        ".example",
        ".sh",
        ".pem",
        ".key",
        "",
    }
)


class ManifestError(ValueError):
    """Raised when the manifest is missing, unreadable, or malformed."""


@dataclass(frozen=True)
class ReleaseManifest:
    """Parsed public-release manifest: include/exclude glob whitelists.

    A repo-relative POSIX path is public iff it matches at least one ``include``
    glob and zero ``exclude`` globs (exclude wins — deny-by-default).
    """

    include: tuple[str, ...]
    exclude: tuple[str, ...]


def _as_glob_list(value: object, field: str) -> tuple[str, ...]:
    """Coerce a manifest field to a tuple of non-empty glob strings.

    Fail-closed: a missing/None field is an empty tuple, but a present field of
    the wrong shape (not a list of strings) is a :class:`ManifestError` rather
    than being silently coerced.
    """
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ManifestError(f"manifest field {field!r} must be a list, got {type(value).__name__}")
    globs: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ManifestError(f"manifest field {field!r} must contain only strings, got {item!r}")
        stripped = item.strip()
        if stripped:
            globs.append(stripped)
    return tuple(globs)


def load_manifest(path: Path) -> ReleaseManifest:
    """Parse a YAML manifest into a :class:`ReleaseManifest`.

    Fail-closed on every malformed input: a missing file, a YAML parse error, a
    non-mapping document, or an ``include`` that selects nothing all raise
    :class:`ManifestError` (the caller turns that into a non-zero exit). We never
    return an empty/defaulted manifest silently, because a manifest that selects
    nothing would make every downstream check vacuously pass.
    """
    if not path.is_file():
        raise ManifestError(f"manifest not found: {path}")
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:  # unreadable file — fail closed.
        raise ManifestError(f"manifest unreadable: {path}: {exc}") from exc
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ManifestError(f"manifest is not valid YAML: {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ManifestError(f"manifest root must be a mapping, got {type(doc).__name__}: {path}")
    include = _as_glob_list(doc.get("include"), "include")
    exclude = _as_glob_list(doc.get("exclude"), "exclude")
    if not include:
        raise ManifestError(f"manifest {path} has no 'include' globs — would select nothing")
    return ReleaseManifest(include=include, exclude=exclude)


def excluded_top_level_secugent_packages(manifest: ReleaseManifest) -> frozenset[str]:
    """Top-level ``secugent.<pkg>`` packages whose *whole subtree* the manifest
    excludes (``secugent/<pkg>/**``).

    These are exactly the tiers no public module may import: their source is not
    shipped, so importing one breaks self-containment (I8) and leaks the tier
    (I2). The release gate asserts :data:`FORBIDDEN_IMPORT_PREFIXES` covers every
    one of them (see :func:`assert_deny_set_covers_manifest`), so the two
    boundary gates can never drift again.
    """
    pkgs: set[str] = set()
    for glob in manifest.exclude:
        parts = glob.split("/")
        # Match the canonical wholesale-exclude shape ``secugent/<pkg>/**`` only;
        # file-level excludes (``secugent/models/router.py``) are NOT whole tiers.
        if len(parts) == 3 and parts[0] == "secugent" and parts[2] == "**" and parts[1]:
            pkgs.add(f"secugent.{parts[1]}")
    return frozenset(pkgs)


def assert_deny_set_covers_manifest(manifest: ReleaseManifest) -> list[str]:
    """Return any excluded top-level ``secugent`` tier missing from the deny-set.

    Empty == the import-closure deny-set (:data:`FORBIDDEN_IMPORT_PREFIXES`) is a
    superset of every wholesale-excluded ``secugent`` tier, so no public module
    can import an excluded tier undetected (closes the fail-open drift the review
    found: desktop/evolution/identity/integrations were excluded but absent from
    the deny-set). A non-empty result is a gate violation (fail-closed).
    """
    forbidden = set(FORBIDDEN_IMPORT_PREFIXES)
    missing = excluded_top_level_secugent_packages(manifest) - forbidden
    return sorted(
        f"manifest excludes tier {pkg} but it is NOT in FORBIDDEN_IMPORT_PREFIXES "
        f"(import-closure would be fail-open for it)"
        for pkg in missing
    )


@lru_cache(maxsize=2048)
def _glob_to_regex(glob: str) -> re.Pattern[str]:
    """Translate a POSIX glob into an anchored regex with deterministic, version-
    independent ``**`` semantics.

    We do NOT use ``PurePosixPath.match`` / ``fnmatch`` because their treatment of
    ``**`` varies across Python versions (3.14's ``PurePath.match`` does not match
    ``secugent/core/**`` against a deeply nested file, and its unicode handling of
    Hangul globs is inconsistent — closure risk R12). This translator fixes the
    semantics ourselves:

    * ``**`` spanning a path boundary (``a/**`` , ``**/b`` , ``a/**/b``) matches
      zero or more whole path segments;
    * a bare ``**`` matches any characters including ``/``;
    * ``*`` matches any run of characters except ``/`` (one segment);
    * ``?`` matches a single non-``/`` character;
    * every other character — including Hangul — is matched literally.
    """
    i = 0
    n = len(glob)
    out: list[str] = []
    while i < n:
        ch = glob[i]
        if ch == "*":
            if i + 1 < n and glob[i + 1] == "*":
                # Consume the '**'.
                j = i + 2
                # '**/' -> zero or more leading segments (incl. none).
                if j < n and glob[j] == "/":
                    out.append(r"(?:[^/]+/)*")
                    i = j + 1
                    continue
                # '/**' at end or '/**/...' was handled by the preceding '/';
                # here a trailing '**' (e.g. 'a/**') -> match the rest, any depth.
                out.append(r".*")
                i = j
                continue
            out.append(r"[^/]*")
            i += 1
            continue
        if ch == "?":
            out.append(r"[^/]")
            i += 1
            continue
        if ch == "/":
            # 'a/**' produced by 'a/' + bare '**': the '/**' should also allow the
            # 'a' directory itself to match nothing extra. Keep literal '/'.
            out.append("/")
            i += 1
            continue
        out.append(re.escape(ch))
        i += 1
    pattern = "".join(out)
    # 'dir/**' must also match 'dir' itself? No — our manifest uses 'dir/**' to mean
    # files strictly under dir, which is what '.*' after '/' yields. Anchor fully.
    return re.compile(rf"^{pattern}$")


def _matches_any(rel_posix: str, globs: tuple[str, ...]) -> bool:
    """True if ``rel_posix`` matches any glob (deterministic ``**`` semantics)."""
    return any(_glob_to_regex(glob).fullmatch(rel_posix) is not None for glob in globs)


def is_public_path(rel_posix: str, manifest: ReleaseManifest) -> bool:
    """Deny-by-default decision for a single repo-relative POSIX path (I4).

    Public iff it matches an ``include`` glob AND no ``exclude`` glob. Exclude
    always wins. This is the pure predicate the property test pins to
    ``whitelist-match AND NOT blacklist-match``.
    """
    if _matches_any(rel_posix, manifest.exclude):
        return False
    return _matches_any(rel_posix, manifest.include)


def _should_skip_dir(name: str) -> bool:
    return name in _SKIP_DIR_NAMES or any(name.endswith(suf) for suf in _SKIP_DIR_SUFFIXES)


def _iter_repo_files(repo_root: Path) -> list[str]:
    """Enumerate every working-tree file as a repo-relative POSIX path.

    Walks deterministically (sorted), skipping VCS/build/cache directories. Files
    are returned as ``str`` POSIX paths so glob matching and downstream output
    are stable across OSes.
    """
    found: list[str] = []
    stack: list[Path] = [repo_root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if not _should_skip_dir(entry.name):
                    stack.append(entry)
                continue
            rel = entry.resolve().relative_to(repo_root).as_posix()
            found.append(rel)
    return found


def public_files(manifest: ReleaseManifest, repo_root: Path) -> list[Path]:
    """Return the public file set: whitelist ∖ blacklist, SORTED + deterministic.

    Invariant I4 (deny-by-default): a file is included only if it matches an
    ``include`` glob and no ``exclude`` glob. Invariant I6 (determinism): the
    output is sorted by repo-relative POSIX path with no set-iteration leakage,
    so 100 calls on the same tree are byte-identical.
    """
    repo_root = repo_root.resolve()
    selected = [rel for rel in _iter_repo_files(repo_root) if is_public_path(rel, manifest)]
    selected.sort()
    return [repo_root / PurePosixPath(rel) for rel in selected]


def _rel_posix(path: Path, repo_root: Path) -> str:
    """Repo-relative POSIX path, or the file's own name if outside the repo.

    The public file set always lives under the repo root, but the checkers also
    accept hand-built paths (tests, ad-hoc audits) that may sit elsewhere (e.g. a
    ``tmp_path`` fixture). Such a path cannot be made repo-relative; rather than
    crash, we fall back to its basename so the violation message is still useful
    and the gate stays robust (it never silently passes).
    """
    resolved = path.resolve()
    try:
        return resolved.relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return resolved.name


def _module_prefix_matches(name: str, prefix: str) -> bool:
    """True if dotted ``name`` is exactly ``prefix`` or a sub-module of it."""
    return name == prefix or name.startswith(prefix + ".")


def _package_of(rel_posix: str) -> str:
    """Dotted package that *contains* the module at ``rel_posix``.

    Mirrors CPython relative-import resolution: a regular module's package is the
    directory it sits in; a package ``__init__.py``'s package is the package dir
    itself. Used to resolve ``from ..x import y`` against the importing module.
    """
    parts = list(PurePosixPath(rel_posix).parts)
    # Drop the filename (regular module) or the __init__.py (package init): both
    # leave the containing package's dotted path.
    parts = parts[:-1]
    return ".".join(parts)


def _resolve_relative(level: int, module: str, package: str) -> str | None:
    """Resolve a relative ``from`` target to its absolute dotted name.

    Returns ``None`` if the relative import walks above the top-level package (a
    malformed import importlib would reject) — the caller treats that as "not a
    forbidden import" since it cannot resolve to a private tier.
    """
    bits = package.rsplit(".", level - 1)
    if len(bits) < level:
        return None
    base = bits[0]
    return f"{base}.{module}" if module else base


def _is_type_checking_guard(node: ast.If) -> bool:
    """True if ``node`` is an ``if TYPE_CHECKING:`` block.

    Matches both ``if TYPE_CHECKING:`` and ``if typing.TYPE_CHECKING:``. Imports
    inside such a block are erased at runtime by the interpreter, so they never
    execute at module import and cannot break standalone import (Invariant I8) —
    they are type-only references, not a runtime dependency on the tier.
    """
    test = node.test
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    if isinstance(test, ast.Attribute):
        return test.attr == "TYPE_CHECKING"
    return False


def _forbidden_in_import_node(node: ast.stmt, *, package: str | None) -> list[str]:
    """Forbidden fully-qualified names referenced by a single import statement."""
    found: list[str] = []
    if isinstance(node, ast.Import):
        for alias in node.names:
            for prefix in FORBIDDEN_IMPORT_PREFIXES:
                if _module_prefix_matches(alias.name, prefix):
                    found.append(alias.name)
    elif isinstance(node, ast.ImportFrom):
        module = node.module or ""
        if node.level and node.level > 0:
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


def _forbidden_imports_in_source(source: str, *, package: str | None) -> list[str]:
    """Forbidden fully-qualified import names that EXECUTE at module import (AST).

    Only imports that actually run when the module is imported count as
    import-closure violations (Invariant I2/I8): a public module importing a
    non-shipped private tier *at load time* breaks standalone ``import`` and
    leaks the tier. Two import forms do NOT execute at load and are therefore not
    closure violations (they are the open-core boundary's sanctioned escape
    hatch for type-only references and optional, lazily-loaded tiers):

    * imports under an ``if TYPE_CHECKING:`` guard — erased at runtime;
    * imports nested inside a function/method body — only run if that function
      is *called*, never on plain ``import`` of the module.

    A *module-level* (top-level, non-TYPE_CHECKING) ``from secugent.desktop import
    X`` IS still a violation — that is the real leak this gate exists to catch.
    Relative imports are resolved against ``package`` before matching. Raises
    :class:`SyntaxError` to the caller (fail-closed — never silently skipped).
    """
    tree = ast.parse(source)
    violations: list[str] = []

    def scan_top_level(body: list[ast.stmt]) -> None:
        """Scan statements that execute at module-import scope.

        Recurses into ``if/else``, ``try/except/finally``, ``with`` bodies (all
        run at import) but treats an ``if TYPE_CHECKING:`` block as runtime-erased
        and does NOT descend into ``def``/``async def``/``class`` bodies (those do
        not run on import — a forbidden import there is a lazy import, not a
        load-time dependency).
        """
        for node in body:
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                violations.extend(_forbidden_in_import_node(node, package=package))
            elif isinstance(node, ast.If):
                if _is_type_checking_guard(node):
                    continue  # runtime-erased: type-only imports are allowed.
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
            # FunctionDef / AsyncFunctionDef / ClassDef: deliberately NOT
            # descended — their bodies do not execute at module import.

    scan_top_level(tree.body)
    return violations


def _module_candidate_files(dotted: str) -> tuple[str, ...]:
    """Repo-relative POSIX paths a dotted module *could* live in.

    ``secugent.orchestrator.runner`` could be either the regular module
    ``secugent/orchestrator/runner.py`` or the package
    ``secugent/orchestrator/runner/__init__.py``. We return both so the
    excluded-sibling check matches whichever shape exists on disk. A leading
    top-level name with no dots (``ui``) yields ``ui.py`` / ``ui/__init__.py``.
    """
    rel = dotted.replace(".", "/")
    return (f"{rel}.py", f"{rel}/__init__.py")


def _excluded_sibling_imports_in_source(
    source: str, *, package: str | None, excluded_existing: frozenset[str]
) -> list[str]:
    """Load-time imports whose target is an excluded-but-existing repo file.

    Mirrors :func:`_forbidden_imports_in_source` (same TYPE_CHECKING/lazy
    exclusions — only imports that EXECUTE at module import count) but instead of
    matching whole private tiers it resolves each load-time import's dotted
    target to its candidate ``.py`` file paths and flags it if any of them is in
    ``excluded_existing`` (a repo file the manifest excludes from the public
    set). Such an import compiles in the source repo yet raises
    ``ModuleNotFoundError`` in the extracted public repo (Invariant I8). Relative
    imports are resolved against ``package`` first. Raises :class:`SyntaxError`
    to the caller (fail-closed)."""
    if not excluded_existing:
        return []
    tree = ast.parse(source)
    violations: list[str] = []

    def _check_target(dotted: str) -> None:
        for candidate in _module_candidate_files(dotted):
            if candidate in excluded_existing:
                violations.append(dotted)
                return

    def scan_top_level(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    _check_target(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level and node.level > 0:
                    if package is None:
                        continue
                    resolved = _resolve_relative(node.level, module, package)
                    if resolved is None:
                        continue
                    module = resolved
                if not module:
                    continue
                # ``from pkg.sub import name`` imports the module ``pkg.sub`` (and
                # possibly ``pkg.sub.name`` if it is a submodule). Check the module
                # itself and each imported name as a potential submodule.
                _check_target(module)
                for alias in node.names:
                    if alias.name != "*":
                        _check_target(f"{module}.{alias.name}")
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

    scan_top_level(tree.body)
    return violations


def assert_import_closure(
    public_pkgs: frozenset[str],
    files: list[Path],
    excluded_existing: frozenset[str] = frozenset(),
) -> list[str]:
    """Return import-closure violations across the public ``.py`` file set (I2).

    For every public ``.py``, AST-parse it (resolving relative imports to
    absolute against the file's package) and flag:

    1. any import of a private TIER (:data:`FORBIDDEN_IMPORT_PREFIXES`); and
    2. any load-time import that resolves to an *excluded-but-existing* repo file
       — a sibling module the manifest excludes from the public set. ``files``
       in an otherwise-public package can ``import secugent.X.Y`` where
       ``secugent/X/Y.py`` exists on disk but is excluded; that compiles in the
       source repo but raises ``ModuleNotFoundError`` in the extracted public
       repo (Invariant I8). ``excluded_existing`` is the set of repo-relative
       POSIX paths the gate enumerated as present-but-not-public; pass it from
       :func:`main` so this second class is detected (it defaults empty so unit
       tests of the tier check keep their old signature).

    ``public_pkgs`` is the set of dotted packages declared public; an import of a
    private tier is a violation regardless. A ``SyntaxError`` or read error is
    itself a violation — we never skip a file we cannot prove clean. Returns a
    sorted list of human-readable violation strings (empty == closed).
    """
    repo_root = _REPO_ROOT
    violations: list[str] = []
    for path in files:
        if path.suffix != ".py":
            continue
        rel = _rel_posix(path, repo_root)
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            violations.append(f"{rel}: unreadable ({exc})")
            continue
        package = _package_of(rel)
        try:
            forbidden = _forbidden_imports_in_source(source, package=package)
            excluded = _excluded_sibling_imports_in_source(
                source, package=package, excluded_existing=excluded_existing
            )
        except SyntaxError as exc:
            violations.append(f"{rel}: SyntaxError ({exc.msg})")
            continue
        for target in forbidden:
            violations.append(f"{rel} imports private tier {target}")
        for target in excluded:
            violations.append(
                f"{rel} imports excluded-from-public module {target} "
                f"(would ModuleNotFoundError in the extracted repo)"
            )
    # public_pkgs is the declared-public allowlist; surface a self-consistency
    # note if a public package somehow re-imports a forbidden tier (already
    # captured above) — referenced here so the parameter is load-bearing.
    if not public_pkgs:
        violations.append("no public packages declared — closure cannot be proven")
    return sorted(violations)


def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


# A credential literal is opaque: a run of credential-alphabet characters with no
# code punctuation. Identifiers / attribute access / calls / subscripts (e.g.
# ``Token[TenantId]``, ``self._api_key)``, ``vault_token,``) are NOT secrets.
_CODE_TOKEN_CHARS: Final[frozenset[str]] = frozenset("()[]{}.,;:<>+*/\\ \t")
_SECRET_VALUE_ALPHABET: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._\-/+=]{12,}$")


def _looks_like_secret_value(value: str) -> bool:
    """True if ``value`` is an opaque, high-entropy credential literal.

    Rejects (returns False for):
    * documented placeholders (``change-me-*`` …);
    * anything containing code punctuation (``(``, ``[``, ``,`` …) — that is a
      Python expression captured by the broad regex, not a credential;
    * a plain word / snake_case identifier with no digits (real keys/tokens mix
      letters and digits or carry separators).
    The high-confidence prefixed patterns (AKIA…, sk-…) bypass this vetting.
    """
    if _is_placeholder(value):
        return False
    if any(ch in _CODE_TOKEN_CHARS for ch in value):
        return False
    if not _SECRET_VALUE_ALPHABET.fullmatch(value):
        return False
    has_digit = any(ch.isdigit() for ch in value)
    has_alpha = any(ch.isalpha() for ch in value)
    has_sep = any(ch in "-_/+=." for ch in value)
    # Require entropy: a credential has digits AND letters, or letters AND a
    # separator run (base64-ish). A bare lowercase word (``password``,
    # ``access_key``) is not opaque enough to be a real leaked secret.
    return has_alpha and (has_digit or has_sep)


def _secret_hits_in_text(text: str) -> list[str]:
    """Return secret-pattern labels found in ``text`` (placeholders excluded)."""
    hits: list[str] = []
    for label, pattern in _SECRET_PATTERNS:
        vet = label == "hardcoded-credential-assignment"
        for match in pattern.finditer(text):
            # The last capturing group (if any) is the credential value; for
            # pattern-only signatures (AKIA…, sk-…) the whole match is the value.
            value = match.group(match.lastindex) if match.lastindex else match.group(0)
            if _is_placeholder(value):
                continue
            # The broad credential-assignment regex needs entropy vetting to
            # avoid flagging ordinary code; prefixed signatures are unambiguous.
            if vet and not _looks_like_secret_value(value):
                continue
            hits.append(label)
            break  # one hit per pattern is enough to fail.
    return hits


def _forbidden_name_reason(rel: str) -> str | None:
    """Internal-strategy reason for ``rel`` by name/path (None if clean)."""
    name = PurePosixPath(rel).name
    if name in _FORBIDDEN_BASENAMES:
        return f"internal-strategy file {rel}"
    for prefix in _FORBIDDEN_PATH_PREFIXES:
        if rel.startswith(prefix):
            return f"internal-strategy path {rel}"
    for token in _FORBIDDEN_HANGUL_SUBSTRINGS:
        if token in name:
            return f"Korean strategy artifact {rel} (matched {token!r})"
    return None


def _secret_filename_reason(rel: str) -> str | None:
    name = PurePosixPath(rel).name
    if name in _SECRET_FILENAMES:
        return f"secret file {rel}"
    if any(name.endswith(suf) for suf in _SECRET_FILE_SUFFIXES):
        return f"key/cert material {rel}"
    return None


def _is_prose_scan_target(rel: str) -> bool:
    """True if ``rel`` is a shipped public *document* the prose gate must scan.

    In scope: ``.md`` / ``.txt`` / ``.rst`` / ``.yaml`` files that live at the repo
    root or under ``docs/`` / ``release/`` (where curated narrative lives), EXCEPT
    the tightly-scoped :data:`_PROSE_SCAN_ALLOWLIST` boundary-machinery files. Out
    of scope: source-tree config/fixtures and code text (covered by the closure /
    secret gates), which are not a public-facing narrative surface.
    """
    if rel in _PROSE_SCAN_ALLOWLIST:
        return False
    suffix = PurePosixPath(rel).suffix.lower()
    if suffix not in _PROSE_SCAN_SUFFIXES:
        return False
    parts = PurePosixPath(rel).parts
    if len(parts) == 1:  # repo-root file (README.md, CHANGELOG.md, …).
        return True
    return parts[0] in _PROSE_SCAN_TOP_DIRS


def _prose_token_reasons(rel: str, text: str) -> list[str]:
    """Forbidden-internal-token violations in the body of a shipped document.

    Direct substring scan (mirroring the deterministic
    :data:`_FORBIDDEN_HANGUL_SUBSTRINGS` filename check — never a glob) of every
    line for each token in :data:`_FORBIDDEN_PROSE_SUBSTRINGS`. Reports the file +
    1-based line for each token hit so the leak is locatable. Fail-closed: any hit
    is a violation (the caller turns a non-empty result into a non-zero exit).
    """
    reasons: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for token in _FORBIDDEN_PROSE_SUBSTRINGS:
            if token in line:
                reasons.append(f"internal token {token!r} in shipped prose {rel}:{line_no}")
    return reasons


def scan_forbidden_content(files: list[Path]) -> list[str]:
    """Return forbidden-content violations in the public file set (I5).

    Three independent gates:

    * **internal-strategy file names** — CLAUDE.md, Review/, docs/specs/, the
      Korean strategy HTMLs, etc., by basename/path/Hangul-substring (so a
      manifest glob mistype cannot let them leak).
    * **internal prose tokens** (CHG-2) — UNAMBIGUOUS internal tokens
      (``Project_Secugent``, ``DEPLOY_PROGRESS``, ``BDP_REFORMED``, ``Review/``,
      ``docs/specs/``) appearing in the BODY of a shipped public document
      (``.md``/``.txt``/``.rst``/``.yaml`` at the repo root or under
      ``docs/``/``release/``). A clean path is not enough — a CHANGELOG/runbook
      line can still name-drop the private tree. The two boundary-machinery files
      that legitimately carry these tokens are tightly allowlisted.
    * **secret content** — ``.env``/key files by name, plus credential regexes
      scanned inside every text file. Documented ``change-me-*`` placeholders are
      NOT secrets.

    A file we cannot read is a violation (fail-closed). Returns a sorted list of
    violation strings (empty == clean).
    """
    repo_root = _REPO_ROOT
    violations: list[str] = []
    for path in files:
        rel = _rel_posix(path, repo_root)
        name_reason = _forbidden_name_reason(rel)
        if name_reason is not None:
            violations.append(name_reason)
        secret_name = _secret_filename_reason(rel)
        if secret_name is not None:
            violations.append(secret_name)

        scan_prose = _is_prose_scan_target(rel)
        scan_secrets = rel not in _SECRET_SCAN_SELF_EXEMPT and (path.suffix.lower() in _TEXT_SUFFIXES)
        if not (scan_prose or scan_secrets):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            violations.append(f"{rel}: unreadable ({exc})")
            continue
        except UnicodeDecodeError:
            # Binary file mislabelled as text — nothing scannable, not a secret.
            continue
        if scan_prose:
            violations.extend(_prose_token_reasons(rel, text))
        if scan_secrets:
            for label in _secret_hits_in_text(text):
                violations.append(f"{rel}: secret-like content ({label})")
    return sorted(violations)


def _declared_public_packages(files: list[Path]) -> frozenset[str]:
    """Dotted packages present in the public set (every dir with an __init__.py)."""
    pkgs: set[str] = set()
    for path in files:
        if path.name != "__init__.py":
            continue
        rel = _rel_posix(path, _REPO_ROOT)
        dotted = _package_of(rel)
        if dotted:
            pkgs.add(dotted)
    return frozenset(pkgs)


def _excluded_existing_files(
    manifest: ReleaseManifest, repo_root: Path, public: list[Path]
) -> frozenset[str]:
    """Repo files that EXIST in the working tree but are NOT in the public set.

    These are exactly the targets a shipping public ``.py`` must never load-time
    import: the file is present in the source repo (so the source compiles) but
    is excluded from the extracted public repo (so the extract raises
    ``ModuleNotFoundError``). Computed as (all enumerated repo files) ∖ (public
    set), restricted to ``.py`` modules since only those can be imported. Used by
    :func:`assert_import_closure` to catch the excluded-sibling fail-open the
    review found (e.g. ``orchestrator/__init__.py`` importing the excluded
    ``orchestrator/runner.py``)."""
    public_rel = {p.resolve().relative_to(repo_root.resolve()).as_posix() for p in public}
    excluded: set[str] = set()
    for rel in _iter_repo_files(repo_root):
        if rel.endswith(".py") and rel not in public_rel:
            excluded.add(rel)
    return frozenset(excluded)


def main(argv: list[str] | None = None) -> int:
    """Run all gates against the public set. >=1 violation -> non-zero (fail-closed).

    ``argv`` may contain a single optional manifest path (defaults to
    ``release/public_manifest.yaml``). Prints a human-readable report and the
    violation list to stdout; returns 0 only when the public set is provably
    safe to ship.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    manifest_path = Path(args[0]) if args else _DEFAULT_MANIFEST

    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        print(f"FAIL: manifest error: {exc}")
        return 1

    # Self-consistency: the import-closure deny-set must cover every excluded
    # top-level secugent tier, or the closure scan is fail-open for the gap.
    deny_drift = assert_deny_set_covers_manifest(manifest)

    files = public_files(manifest, _REPO_ROOT)
    public_pkgs = _declared_public_packages(files)
    excluded_existing = _excluded_existing_files(manifest, _REPO_ROOT, files)
    closure = assert_import_closure(public_pkgs, files, excluded_existing)
    forbidden = scan_forbidden_content(files)

    violations = deny_drift + closure + forbidden
    print(f"public files selected: {len(files)}")
    print(f"deny-set drift violations: {len(deny_drift)}")
    print(f"import-closure violations: {len(closure)}")
    print(f"forbidden-content violations: {len(forbidden)}")
    if violations:
        print("FAIL: public-release gate found violations:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("OK: public set is closed, secret-free, and strategy-doc-free.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
