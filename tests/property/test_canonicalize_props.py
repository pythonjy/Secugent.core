# SPDX-License-Identifier: Apache-2.0
"""EM-01 — Hypothesis property tests for canonicalize_path.

Covers EM-01 §5 tests 12-13:
  - idempotence: canon(canon(x)) == canon(x)
  - isolation: output is always inside a sandbox root (never escapes)
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from secugent.core.sec.canonicalize import AmbiguousEffectError, canonicalize_path

# Segments deliberately include traversal tokens so some inputs escape (→ raise)
# and some stay contained (→ must be idempotent + inside root).
_SEGMENT = st.sampled_from(["a", "b", "sub", "dir", "x.txt", "..", ".", "deep"])
_SEGMENTS = st.lists(_SEGMENT, min_size=0, max_size=6)


@settings(max_examples=80, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(segments=_SEGMENTS)
def test_idempotent_and_contained(tmp_path_factory: pytest.TempPathFactory, segments: list[str]) -> None:
    root = str(tmp_path_factory.mktemp("box"))
    root_canon = canonicalize_path(root, sandbox_roots=[root])
    raw = root + "/" + "/".join(segments) if segments else root
    try:
        once = canonicalize_path(raw, sandbox_roots=[root])
    except AmbiguousEffectError:
        return  # escaping / ambiguous inputs are allowed to fail closed
    # idempotence
    twice = canonicalize_path(once, sandbox_roots=[root])
    assert once == twice
    # isolation — output never escapes the sandbox root
    assert once == root_canon or once.startswith(root_canon.rstrip("/") + "/")


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(segments=_SEGMENTS)
def test_output_is_lowercase_forward_slash(
    tmp_path_factory: pytest.TempPathFactory, segments: list[str]
) -> None:
    root = str(tmp_path_factory.mktemp("box"))
    raw = root + "/" + "/".join(segments) if segments else root
    try:
        out = canonicalize_path(raw, sandbox_roots=[root])
    except AmbiguousEffectError:
        return
    assert "\\" not in out
    assert out == out.lower()
