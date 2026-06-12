# SPDX-License-Identifier: Apache-2.0
"""EM-01 — Effect model unit tests (deterministic).

Covers EM-01 §5 tests 6-8 + field validation + fingerprint determinism.
"""

from __future__ import annotations

import dataclasses

import pytest

from secugent.core.sec.effects import Effect, EffectKind, SinkClass


def _file_effect(**kw: object) -> Effect:
    base: dict[str, object] = dict(
        kind=EffectKind.FILE_WRITE,
        target="c:/sandbox/out.txt",
        sink_class=SinkClass.LOCAL_SANDBOX,
    )
    base.update(kw)
    return Effect(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# enum surface
# --------------------------------------------------------------------------- #


def test_effect_kind_values() -> None:
    assert EffectKind.FILE_READ == "file_read"
    assert EffectKind.NET_SEND == "net_send"
    assert EffectKind.CONNECTOR_ACTION == "connector_action"


def test_sink_class_values() -> None:
    assert SinkClass.EXTERNAL == "external"
    assert SinkClass.LOCAL_SANDBOX == "local_sandbox"


# --------------------------------------------------------------------------- #
# canonical-target enforcement (test 6)
# --------------------------------------------------------------------------- #


def test_raw_windows_path_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.FILE_WRITE, target="C:\\Users\\..\\x", sink_class=SinkClass.LOCAL_SANDBOX)


def test_uppercase_path_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.FILE_READ, target="c:/Sandbox/File", sink_class=SinkClass.LOCAL_SANDBOX)


def test_dotdot_path_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.FILE_READ, target="c:/a/../b", sink_class=SinkClass.LOCAL_SANDBOX)


def test_canonical_path_accepted() -> None:
    eff = _file_effect()
    assert eff.target == "c:/sandbox/out.txt"


def test_net_target_requires_scheme() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.NET_SEND, target="example.com/x", sink_class=SinkClass.EXTERNAL)


def test_net_target_uppercase_host_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.NET_SEND, target="https://Example.com/x", sink_class=SinkClass.EXTERNAL)


def test_net_canonical_accepted() -> None:
    eff = Effect(kind=EffectKind.NET_SEND, target="https://example.com/Path", sink_class=SinkClass.EXTERNAL)
    assert eff.target == "https://example.com/Path"  # path case preserved


def test_connector_target_lenient() -> None:
    eff = Effect(
        kind=EffectKind.CONNECTOR_ACTION,
        target="C-General",  # channel id, case preserved
        sink_class=SinkClass.EXTERNAL,
        action="slack.post_message",
    )
    assert eff.action == "slack.post_message"


def test_empty_target_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.FILE_READ, target="", sink_class=SinkClass.LOCAL_SANDBOX)


def test_surrounding_whitespace_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.FILE_READ, target=" c:/a ", sink_class=SinkClass.LOCAL_SANDBOX)


def test_negative_byte_estimate_rejected() -> None:
    with pytest.raises(ValueError):
        _file_effect(byte_estimate=-1)


def test_nul_in_target_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.CONNECTOR_ACTION, target="a\x00b", sink_class=SinkClass.EXTERNAL)


def test_env_var_path_target_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.FILE_READ, target="c:/%userprofile%/x", sink_class=SinkClass.LOCAL_SANDBOX)


def test_short_name_path_target_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.FILE_READ, target="c:/progra~1/x", sink_class=SinkClass.LOCAL_SANDBOX)


def test_bad_meta_pair_rejected() -> None:
    with pytest.raises(ValueError):
        _file_effect(meta=(("only-one",),))  # type: ignore[arg-type]


def test_non_str_meta_value_rejected() -> None:
    with pytest.raises(ValueError):
        _file_effect(meta=(("k", 1),))  # type: ignore[arg-type]


def test_bool_byte_estimate_rejected() -> None:
    # bool is an int subclass — True would serialize as `true`, corrupting the
    # fingerprint vs an equivalent `1`.
    with pytest.raises(ValueError):
        _file_effect(byte_estimate=True)


def test_net_dotdot_target_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.NET_SEND, target="https://example.com/../x", sink_class=SinkClass.EXTERNAL)


def test_net_empty_authority_rejected() -> None:
    with pytest.raises(ValueError):
        Effect(kind=EffectKind.NET_SEND, target="https://", sink_class=SinkClass.EXTERNAL)


# --------------------------------------------------------------------------- #
# immutability (test 8)
# --------------------------------------------------------------------------- #


def test_effect_is_frozen() -> None:
    eff = _file_effect()
    with pytest.raises(dataclasses.FrozenInstanceError):
        eff.target = "c:/sandbox/other.txt"  # type: ignore[misc]


# --------------------------------------------------------------------------- #
# fingerprint (test 7)
# --------------------------------------------------------------------------- #


def test_fingerprint_deterministic_100x() -> None:
    eff = _file_effect(byte_estimate=10, meta=(("a", "1"), ("b", "2")))
    fps = {eff.fingerprint() for _ in range(100)}
    assert len(fps) == 1
    assert len(next(iter(fps))) == 64  # sha256 hex


def test_fingerprint_meta_order_independent() -> None:
    e1 = _file_effect(meta=(("b", "2"), ("a", "1")))
    e2 = _file_effect(meta=(("a", "1"), ("b", "2")))
    assert e1.meta == e2.meta  # normalised (sorted) on construction
    assert e1.fingerprint() == e2.fingerprint()


def test_fingerprint_differs_on_field_change() -> None:
    a = _file_effect(byte_estimate=1)
    b = _file_effect(byte_estimate=2)
    assert a.fingerprint() != b.fingerprint()


def test_fingerprint_includes_label_when_set() -> None:
    from secugent.core.sec.labels import DataLabel

    unlabelled = _file_effect()
    labelled = _file_effect(label=DataLabel.SECRET)
    # the optional EM-02 label participates in the fingerprint when present...
    assert unlabelled.fingerprint() != labelled.fingerprint()
    # ...and is deterministic
    assert labelled.fingerprint() == _file_effect(label=DataLabel.SECRET).fingerprint()
    # label=PUBLIC is a distinct state from label=None (must not collide)
    assert _file_effect(label=DataLabel.PUBLIC).fingerprint() != unlabelled.fingerprint()


def test_fingerprint_golden_value() -> None:
    # Hard-coded hash proves the canonical serialization is stable across Python
    # versions / hash seeds (not just within one process).
    eff = Effect(
        kind=EffectKind.FILE_WRITE,
        target="c:/sandbox/out.txt",
        sink_class=SinkClass.LOCAL_SANDBOX,
        byte_estimate=10,
        meta=(("a", "1"), ("b", "2")),
    )
    assert eff.fingerprint() == "a37e61bf48b086b7a238d7cf84a08f9de2a07092cc8127b3512b47fe2d5447b5"
