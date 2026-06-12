# SPDX-License-Identifier: Apache-2.0
"""EM-02 — DataLabel lattice, merge, may_egress, mapping (deterministic)."""

from __future__ import annotations

import unicodedata

import pytest

from secugent.core.regulations import DataLabel as RegulationDataLabel
from secugent.core.sec.effects import SinkClass
from secugent.core.sec.labels import (
    DEFAULT_LABEL_MAP,
    DataLabel,
    LabelDecision,
    LabelMappingError,
    may_egress,
    merge,
    resolve_label,
    validate_label_keys,
)

# --------------------------------------------------------------------------- #
# lattice order + merge
# --------------------------------------------------------------------------- #


def test_total_order() -> None:
    assert DataLabel.PUBLIC < DataLabel.INTERNAL_USE < DataLabel.CONFIDENTIAL < DataLabel.SECRET


def test_merge_is_upper_bound() -> None:
    assert merge(DataLabel.PUBLIC, DataLabel.SECRET) is DataLabel.SECRET
    assert merge(DataLabel.INTERNAL_USE, DataLabel.CONFIDENTIAL) is DataLabel.CONFIDENTIAL


def test_merge_identity_public() -> None:
    assert merge(DataLabel.CONFIDENTIAL, DataLabel.PUBLIC) is DataLabel.CONFIDENTIAL


def test_merge_no_args_is_public() -> None:
    assert merge() is DataLabel.PUBLIC


def test_merge_deterministic_100x() -> None:
    outs = {merge(DataLabel.SECRET, DataLabel.PUBLIC, DataLabel.INTERNAL_USE) for _ in range(100)}
    assert outs == {DataLabel.SECRET}


# --------------------------------------------------------------------------- #
# may_egress (test 2)
# --------------------------------------------------------------------------- #


def test_confidential_to_external_denied() -> None:
    d = may_egress(DataLabel.CONFIDENTIAL, SinkClass.EXTERNAL, max_external=DataLabel.INTERNAL_USE)
    assert d.allow is False
    assert d.reason == "label_exceeds_external_sink"
    assert d.label is DataLabel.CONFIDENTIAL
    assert d.sink_class is SinkClass.EXTERNAL


def test_internal_use_to_external_allowed() -> None:
    d = may_egress(DataLabel.INTERNAL_USE, SinkClass.EXTERNAL, max_external=DataLabel.INTERNAL_USE)
    assert d.allow is True
    assert d.reason == "label_within_external_max"


def test_label_equals_max_external_allowed() -> None:
    # max_external is the INCLUSIVE ceiling — a label equal to it may egress.
    d = may_egress(DataLabel.SECRET, SinkClass.EXTERNAL, max_external=DataLabel.SECRET)
    assert d.allow is True
    assert d.reason == "label_within_external_max"


def test_secret_to_internal_sink_allowed() -> None:
    d = may_egress(DataLabel.SECRET, SinkClass.INTERNAL, max_external=DataLabel.PUBLIC)
    assert d.allow is True
    assert d.reason == "sink_not_external"


def test_local_sandbox_sink_allowed_regardless() -> None:
    d = may_egress(DataLabel.SECRET, SinkClass.LOCAL_SANDBOX, max_external=DataLabel.PUBLIC)
    assert d.allow is True
    assert d.reason == "sink_not_external"


def test_may_egress_deterministic_100x() -> None:
    outs = {
        may_egress(DataLabel.SECRET, SinkClass.EXTERNAL, max_external=DataLabel.CONFIDENTIAL).allow
        for _ in range(100)
    }
    assert outs == {False}


def test_label_decision_is_frozen() -> None:
    import dataclasses

    d = LabelDecision(allow=True, reason="x", label=DataLabel.PUBLIC, sink_class=SinkClass.INTERNAL)
    with pytest.raises(dataclasses.FrozenInstanceError):
        d.allow = False  # type: ignore[misc]


def test_merge_rejects_out_of_lattice_int() -> None:
    # Defense-in-depth: an int outside the lattice must never flow through.
    with pytest.raises(ValueError):
        merge(99, DataLabel.PUBLIC)  # type: ignore[arg-type]


def test_may_egress_rejects_out_of_lattice_int() -> None:
    with pytest.raises(ValueError):
        may_egress(99, SinkClass.EXTERNAL, max_external=DataLabel.PUBLIC)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# REGULATIONS key ↔ lattice mapping
# --------------------------------------------------------------------------- #


def test_resolve_label_known_keys() -> None:
    assert resolve_label("공개") is DataLabel.PUBLIC
    assert resolve_label("대외비") is DataLabel.CONFIDENTIAL
    assert resolve_label("SECRET") is DataLabel.SECRET  # case-insensitive
    assert resolve_label("internal_use") is DataLabel.INTERNAL_USE


def test_default_map_exact_tiers() -> None:
    # Pin EVERY key's exact tier so a one-character typo in DEFAULT_LABEL_MAP
    # (a silent "downgrade-by-mapping") can't ship green.
    expected = {
        "public": DataLabel.PUBLIC,
        "internal": DataLabel.INTERNAL_USE,
        "internal_use": DataLabel.INTERNAL_USE,
        "confidential": DataLabel.CONFIDENTIAL,
        "secret": DataLabel.SECRET,
        "공개": DataLabel.PUBLIC,
        "대내": DataLabel.INTERNAL_USE,
        "내부": DataLabel.INTERNAL_USE,
        "대외비": DataLabel.CONFIDENTIAL,
        "기밀": DataLabel.SECRET,
    }
    for key, tier in expected.items():
        assert resolve_label(key) is tier


def test_resolve_label_nfd_normalized() -> None:
    # NFD-decomposed Korean must resolve identically to the NFC map key.
    nfd = unicodedata.normalize("NFD", "기밀")
    assert nfd != "기밀"  # genuinely decomposed
    assert resolve_label(nfd) is DataLabel.SECRET


def test_resolve_label_unknown_raises() -> None:
    with pytest.raises(LabelMappingError):
        resolve_label("최고기밀-미정의")


def test_validate_label_keys_accepts_known() -> None:
    validate_label_keys(["public", "대외비", "secret"])  # no raise


def test_validate_label_keys_rejects_unknown() -> None:
    with pytest.raises(LabelMappingError):
        validate_label_keys(["public", "made-up-tier"])


def test_default_map_covers_four_tiers() -> None:
    assert set(DEFAULT_LABEL_MAP.values()) == set(DataLabel)


# --------------------------------------------------------------------------- #
# namespace collision guard (invariant 6)
# --------------------------------------------------------------------------- #


def test_lattice_is_not_regulation_datalabel() -> None:
    # The egress lattice and the oversight classification model are distinct,
    # complementary types — never the same object.
    assert DataLabel is not RegulationDataLabel
    assert not issubclass(DataLabel, RegulationDataLabel)
