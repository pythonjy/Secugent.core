# SPDX-License-Identifier: Apache-2.0
"""PyYAML 의존성 선언 회귀 가드 (§B-9, §A-2.6 폐쇄망 우선).

``secugent/regulations/tenant_loader.py`` 는 모듈 최상단에서 ``import yaml`` 한다.
이 모듈은 결정적 REGULATIONS 경로(§B-4a)의 일부이며 ``for_tenant`` / ``for_run``
(팩 로딩뿐 아니라 base+override 병합)에서 임포트된다. PyYAML 이 ``pyproject.toml``
``[project].dependencies`` 와 ``requirements.txt`` 에 **고정 선언**되어 있지 않으면,
슬림한 에어갭/폐쇄망 설치(이 제품의 명시적 기본 타깃, §A-2.6)에서 전이 extra 가
잘리면 ``import secugent.regulations.tenant_loader`` 가 ``ModuleNotFoundError`` 로
테넌트 REGULATIONS 로더 전체를 무너뜨린다.

이 테스트는 그 누락(미선언 임포트-타임 의존성)을 fail-closed CI 게이트로 잡는다:

* PyYAML 이 ``[project].dependencies`` 에 런타임 의존성으로 선언되어야 한다.
* PyYAML 이 ``requirements.txt`` 에 고정(pinned lower-bound)되어야 한다 (§B-9).
* mypy 정적 분석을 위해 ``types-PyYAML`` 가 dev extra 에 있어야 한다.

런타임 코드 변경이 아니라 의존성 매니페스트를 직접 검사한다(결정적·네트워크 불필요).
"""

from __future__ import annotations

import tomllib
from pathlib import Path

# tests/regulations/test_pack_deps_declared.py -> tests/regulations -> tests -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]


def _normalize(name: str) -> str:
    """PEP 503-style canonical name (case-insensitive, ``-``/``_``/``.`` folded).

    ``PyYAML`` and ``pyyaml`` (and ``py-yaml``) are the same distribution, so the
    guard must not be defeated by capitalisation or separator drift.
    """
    return "".join(c for c in name.lower() if c.isalnum())


def _requirement_dist_name(spec: str) -> str:
    """Extract the distribution name from a PEP 508 / requirements line.

    Strips an inline comment, environment markers, extras and the version
    specifier, leaving just the project name (e.g. ``"PyYAML>=6.0  # x"`` ->
    ``"PyYAML"``).
    """
    line = spec.split("#", 1)[0].strip()
    line = line.split(";", 1)[0].strip()  # environment marker
    # The name runs until the first of: version op, extras bracket, or whitespace.
    for sep in ("[", "==", ">=", "<=", "~=", "!=", ">", "<", "=", " ", "\t"):
        idx = line.find(sep)
        if idx != -1:
            line = line[:idx]
    return line.strip()


def _pyproject() -> dict[str, object]:
    return tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _runtime_dist_names() -> set[str]:
    cfg = _pyproject()
    project = cfg["project"]
    assert isinstance(project, dict)
    deps = project["dependencies"]
    assert isinstance(deps, list)
    return {_normalize(_requirement_dist_name(str(d))) for d in deps}


def test_pyyaml_is_a_declared_runtime_dependency() -> None:
    """PyYAML must be a first-class ``[project].dependencies`` entry.

    tenant_loader imports it at module top inside the deterministic regulations
    path; relying on a transitive extra (uvicorn[standard]) breaks slim air-gap
    installs (§A-2.6 / §B-9).
    """
    assert "pyyaml" in _runtime_dist_names(), (
        "PyYAML is imported at module top in secugent/regulations/tenant_loader.py "
        "(deterministic §B-4a path, used by for_tenant/for_run) but is NOT declared "
        "in [project].dependencies — a slim air-gapped install would fail at import. "
        "Add 'PyYAML>=6.0' to [project].dependencies (§B-9)."
    )


def test_pyyaml_is_pinned_in_requirements_txt() -> None:
    """§B-9: runtime deps are fixed in BOTH pyproject AND requirements.txt."""
    req = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
    names = {
        _normalize(_requirement_dist_name(line))
        for line in req.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert "pyyaml" in names, (
        "PyYAML must be pinned in requirements.txt alongside pyproject.toml "
        "so air-gapped/closed-network installs are reproducible (§B-9)."
    )


def test_types_pyyaml_in_dev_extra_for_mypy() -> None:
    """mypy strict needs the PyYAML stubs declared in the dev extra.

    Without ``types-PyYAML`` the only reason ``mypy secugent`` stays clean is the
    repo-wide ``ignore_missing_imports = true`` escape hatch; declaring the stubs
    makes the yaml surface actually type-checked instead of silently ``Any``.
    """
    cfg = _pyproject()
    project = cfg["project"]
    assert isinstance(project, dict)
    extras = project["optional-dependencies"]
    assert isinstance(extras, dict)
    dev = extras["dev"]
    assert isinstance(dev, list)
    dev_names = {_normalize(_requirement_dist_name(str(d))) for d in dev}
    assert "typespyyaml" in dev_names, (
        "Add 'types-PyYAML' to the [project.optional-dependencies].dev extra so "
        "mypy type-checks the yaml import surface in tenant_loader.py."
    )
