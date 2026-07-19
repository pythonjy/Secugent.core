# SPDX-License-Identifier: Apache-2.0
"""Audit retention 속성 기반 테스트 (hypothesis).

검증 불변조건:
* I2: retain_days 윈도 안의 sealed day는 어떤 입력에서도 절대 purge 후보에 없다.
* I3: sealed_days에 없는 (unsealed) day는 어떤 입력에서도 절대 purge 후보에 없다.
* 추가: purge_days ∩ retained_sealed_days = ∅, 둘의 합집합 = 고유 sealed days.
* 결정성: 동일 입력 → 동일 plan.
"""

from __future__ import annotations

from datetime import date, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from secugent.audit.retention import plan

_DAYS = st.dates(min_value=date(2000, 1, 1), max_value=date(2100, 12, 31))
_RETAIN = st.integers(min_value=0, max_value=4000)
_NOW = st.dates(min_value=date(2020, 1, 1), max_value=date(2100, 12, 31))


@given(now=_NOW, sealed=st.lists(_DAYS, max_size=40), retain_days=_RETAIN)
@settings(max_examples=300, deadline=None)
def test_within_window_never_purged(now: date, sealed: list[date], retain_days: int) -> None:
    """I2: every purged day is strictly older than retain_days; nothing in the
    window leaks into purge_days."""
    p = plan(now=now, sealed_days=sealed, retain_days=retain_days)
    for day in p.purge_days:
        assert (now - day).days > retain_days
    for day in p.retained_sealed_days:
        assert (now - day).days <= retain_days


@given(now=_NOW, sealed=st.lists(_DAYS, max_size=40), retain_days=_RETAIN)
@settings(max_examples=300, deadline=None)
def test_unsealed_never_purged(now: date, sealed: list[date], retain_days: int) -> None:
    """I3: a day not in sealed_days is never archived/purged (purge_days ⊆ sealed)."""
    sealed_set = set(sealed)
    p = plan(now=now, sealed_days=sealed, retain_days=retain_days)
    assert set(p.purge_days) <= sealed_set
    assert set(p.retained_sealed_days) <= sealed_set


@given(now=_NOW, sealed=st.lists(_DAYS, max_size=40), retain_days=_RETAIN)
@settings(max_examples=300, deadline=None)
def test_partition_is_total_and_disjoint(now: date, sealed: list[date], retain_days: int) -> None:
    """purge_days and retained_sealed_days partition the unique sealed days."""
    p = plan(now=now, sealed_days=sealed, retain_days=retain_days)
    purge = set(p.purge_days)
    retained = set(p.retained_sealed_days)
    assert purge.isdisjoint(retained)
    assert purge | retained == set(sealed)


@given(now=_NOW, sealed=st.lists(_DAYS, max_size=40), retain_days=_RETAIN)
@settings(max_examples=200, deadline=None)
def test_outputs_sorted_and_deduped(now: date, sealed: list[date], retain_days: int) -> None:
    p = plan(now=now, sealed_days=sealed, retain_days=retain_days)
    assert list(p.purge_days) == sorted(set(p.purge_days))
    assert list(p.retained_sealed_days) == sorted(set(p.retained_sealed_days))


@given(now=_NOW, sealed=st.lists(_DAYS, max_size=30), retain_days=_RETAIN)
@settings(max_examples=200, deadline=None)
def test_plan_is_deterministic(now: date, sealed: list[date], retain_days: int) -> None:
    a = plan(now=now, sealed_days=sealed, retain_days=retain_days)
    b = plan(now=now, sealed_days=list(reversed(sealed)), retain_days=retain_days)
    assert a == b


@given(now=_NOW, sealed=st.lists(_DAYS, min_size=1, max_size=30))
@settings(max_examples=150, deadline=None)
def test_retain_zero_purges_all_strictly_past(now: date, sealed: list[date]) -> None:
    """retain_days=0 ⇒ every sealed day strictly before `now` is purged."""
    p = plan(now=now, sealed_days=sealed, retain_days=0)
    for day in set(sealed):
        if day < now:
            assert day in p.purge_days
        else:  # day == now or future (age <= 0)
            assert day in p.retained_sealed_days


@given(
    now=st.dates(min_value=date(2021, 1, 1), max_value=date(2100, 1, 1)),
    age=st.integers(min_value=0, max_value=2000),
    retain_days=_RETAIN,
)
@settings(max_examples=300, deadline=None)
def test_single_day_boundary(now: date, age: int, retain_days: int) -> None:
    """A single sealed day at exactly `age` days old lands in the right bucket."""
    day = now - timedelta(days=age)
    p = plan(now=now, sealed_days=[day], retain_days=retain_days)
    if age > retain_days:
        assert p.purge_days == (day,)
        assert p.retained_sealed_days == ()
    else:
        assert p.purge_days == ()
        assert p.retained_sealed_days == (day,)
