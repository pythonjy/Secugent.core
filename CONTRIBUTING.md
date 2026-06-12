# Contributing to SecuGent

Thank you for your interest in contributing to SecuGent — an enterprise agent
trust & control plane that provides deterministic safety guarantees for autonomous
agents.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Prerequisites](#prerequisites)
- [Development Setup](#development-setup)
- [Local Gates (Required Before Every PR)](#local-gates-required-before-every-pr)
- [Test Guidelines](#test-guidelines)
- [Pull Request Flow](#pull-request-flow)
- [Commit Style](#commit-style)
- [DCO Sign-off](#dco-sign-off)
- [Open-Core Boundary](#open-core-boundary)
- [Security Vulnerability Disclosure](#security-vulnerability-disclosure)
- [License](#license)

---

## Code of Conduct

This project is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating you agree to abide by its terms.

---

## Prerequisites

- **Python 3.11 or newer** (`python --version`)
- **Git** with commit signing configured (see [DCO Sign-off](#dco-sign-off))
- Optional but recommended: `shellcheck` for shell script contributions

---

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/<your-fork>/secugent.git
cd secugent

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows PowerShell

# 3. Install the package in editable mode with all dev extras
pip install -e ".[dev]"

# 4. Verify the installation
secugent --help
secugent demo
```

The `[dev]` extra installs the full quality toolchain:
`ruff`, `mypy`, `pytest`, `pytest-asyncio`, `pytest-cov`, `hypothesis`, and `pyyaml`.

---

## Local Gates (Required Before Every PR)

Every pull request **must** pass all of the following checks locally before
being pushed. CI runs the same gates and will block the merge if any fail.

```bash
# 1. Lint — zero warnings required
ruff check .

# 2. Format — must be clean (run `ruff format .` to auto-fix)
ruff format --check .

# 3. Type checking — strict mode, zero errors
mypy --strict secugent/

# 4. Tests — full suite with branch coverage
pytest tests/unit tests/release -q --cov=secugent --cov-branch

# 5. Public-release gate — leak-free scan (zero violations required)
python scripts/check_public_release.py
```

All five gates must exit `0` before you open a PR.

### Trust proof (optional but encouraged)

```bash
# Confirm determinism: 100 identical runs must produce the same hash
secugent verify --determinism --fixture tests/cli/fixtures/determinism_seed.json
```

Expected output: `verify: determinism OK - 100 runs identical (digest <hex>)`

A non-zero exit from `secugent verify` is a finding — please report it via
[SECURITY.md](SECURITY.md).

---

## Test Guidelines

SecuGent uses a **test-driven development (TDD)** workflow:

1. **Red** — write a failing test that captures the behaviour described in your
   proposed change.
2. **Green** — write the simplest implementation that makes the test pass.
3. **Refactor** — clean up without changing behaviour; all tests stay green.

### Coverage targets

- **General modules**: 90% branch coverage minimum.
- **Deterministic core modules**
  (`secugent/core/mechanical_oversight.py`, `secugent/core/regulations.py`,
  `secugent/core/approval.py`, `secugent/audit/`):
  **95% branch coverage** is a hard CI gate. These modules must also include:
  - Unit tests
  - Property-based tests (`hypothesis`)
  - A determinism regression test (100 identical inputs → 100 identical outputs)

### Asynchronous code

Use `pytest-asyncio` for async tests. The project is configured with
`asyncio_mode = "auto"` in `pyproject.toml`.

### Test layout

Mirror the source tree under `tests/`:

```
secugent/foo/bar.py  →  tests/foo/test_bar.py
```

---

## Pull Request Flow

1. **Fork** the repository and create a feature branch:

   ```bash
   git switch -c feat/my-feature main
   ```

2. **Develop** using TDD (red → green → refactor).

3. **Run all local gates** (see above). Do not open a PR until all five pass.

4. **Open a PR** against `main`. Use the [PR template](.github/PULL_REQUEST_TEMPLATE.md)
   checklist to confirm your contribution is ready.

5. **Review** — at least one maintainer approval is required before merge.
   Address reviewer feedback in follow-up commits (do not force-push after
   review has started).

6. **Merge** is performed by a maintainer once all CI checks and reviews pass.

---

## Commit Style

We follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<scope>): <short summary>

<optional body — explain WHY, not WHAT>
```

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`.

- First line: 50 characters or fewer.
- Body: 1–3 sentences explaining the motivation. The diff already shows what changed.
- One logical change per commit; do not mix refactoring with feature additions.

---

## DCO Sign-off

SecuGent uses the [Developer Certificate of Origin v1.1](https://developercertificate.org/)
instead of a Contributor License Agreement. Every commit must carry a
`Signed-off-by` trailer:

```bash
git commit -s -m "feat(core): add new invariant check"
```

The `-s` flag appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

By signing off you certify that:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Pull requests that contain commits without a `Signed-off-by` line will not be
merged.

---

## Open-Core Boundary

SecuGent is an **open-core** project:

- **Apache-2.0 core** (`secugent/core/`, `secugent/audit/`, `secugent/steer/`,
  and the other packages listed in `docs/OPEN_CORE.md`) — all contributions are
  welcome and ship in the public release.
- **BSL-1.1 enterprise tier** (`secugent/enterprise/`, `secugent/cost/`,
  `secugent/api/`, `secugent/compliance/`) — not included in the public release.

The boundary is mechanically enforced:

```bash
# Verify that no public source file imports a private package
python scripts/check_public_release.py
```

If your contribution is to a Core package, ensure that no new `import` statement
reaches a private package (`secugent.enterprise`, `secugent.cost`, `secugent.api`,
`secugent.compliance`, `secugent.evolution`, `secugent.identity`,
`secugent.integrations`, `secugent.desktop`, or the top-level `ui` package).

See [docs/OPEN_CORE.md](docs/OPEN_CORE.md) for the complete tier table.

---

## Security Vulnerability Disclosure

**Do not open a public GitHub issue for a security vulnerability.**

Please follow the responsible disclosure process in [SECURITY.md](SECURITY.md).
The short version: use GitHub's private **"Report a vulnerability"** button on
the Security tab, or send email to **security@secugent.example**.

---

## License

By contributing to SecuGent you agree that your contributions to the Core
packages will be licensed under the [Apache License 2.0](LICENSE), and your
contributions to Enterprise packages (if applicable) under the
[Business Source License 1.1](LICENSE.enterprise).

See [docs/OPEN_CORE.md](docs/OPEN_CORE.md) for the full tier boundary description.
