# SPDX-License-Identifier: Apache-2.0
"""EM-01 — canonicalize_{path,url,command} unit tests (deterministic).

Covers EM-01 §5 tests 1-5 + fail-closed edges. Filesystem-touching tests use
``tmp_path``; symlink tests skip where the OS forbids symlink creation.
"""

from __future__ import annotations

import os
import subprocess
import unicodedata
from pathlib import Path

import pytest

from secugent.core.sec.canonicalize import (
    AmbiguousEffectError,
    _strip_windows_trailing,
    canonicalize_command,
    canonicalize_path,
    canonicalize_url,
)

# --------------------------------------------------------------------------- #
# canonicalize_path — fail-closed rejections
# --------------------------------------------------------------------------- #


def test_empty_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path("", sandbox_roots=[str(tmp_path)])


def test_nul_byte_rejected(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(str(tmp_path / "a\x00b"), sandbox_roots=[str(tmp_path)])


def test_env_var_expansion_rejected(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(str(tmp_path / "%USERPROFILE%" / "x"), sandbox_roots=[str(tmp_path)])


def test_short_name_rejected(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(str(tmp_path / "PROGRA~1" / "x"), sandbox_roots=[str(tmp_path)])


def test_relative_path_rejected(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path("relative/dir/file.txt", sandbox_roots=[str(tmp_path)])


def test_empty_sandbox_roots_rejected(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(str(tmp_path / "a.txt"), sandbox_roots=[])


def test_non_absolute_sandbox_root_rejected(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(str(tmp_path / "a.txt"), sandbox_roots=["relative_root"])


def test_empty_string_sandbox_root_rejected(tmp_path: Path) -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(str(tmp_path / "a.txt"), sandbox_roots=[""])


# --------------------------------------------------------------------------- #
# canonicalize_path — escape detection (test 1)
# --------------------------------------------------------------------------- #


def test_dotdot_escape_raises(tmp_path: Path) -> None:
    box = tmp_path / "box"
    box.mkdir()
    escaping = str(box / ".." / "secret.txt")  # resolves to tmp_path/secret.txt
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(escaping, sandbox_roots=[str(box)])


def test_symlink_escape_raises(tmp_path: Path) -> None:
    box = tmp_path / "box"
    box.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = box / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):  # Windows w/o privilege, etc.
        pytest.skip("symlink creation not permitted on this platform")
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(str(link / "x.txt"), sandbox_roots=[str(box)])


# --------------------------------------------------------------------------- #
# canonicalize_path — happy path + normalization
# --------------------------------------------------------------------------- #


def test_within_sandbox_lowercased_forward_slash(tmp_path: Path) -> None:
    root = str(tmp_path)
    target = str(tmp_path / "Sub" / "File.TXT")
    out = canonicalize_path(target, sandbox_roots=[root])
    assert "\\" not in out
    assert out == out.lower()
    root_canon = canonicalize_path(root, sandbox_roots=[root])
    assert out == root_canon or out.startswith(root_canon.rstrip("/") + "/")


def test_unicode_nfc_convergence(tmp_path: Path) -> None:
    root = str(tmp_path)
    nfd = "é.txt"  # decomposed é
    nfc = unicodedata.normalize("NFC", nfd)  # composed é
    assert nfd != nfc
    out_nfd = canonicalize_path(str(tmp_path) + "/" + nfd, sandbox_roots=[root])
    out_nfc = canonicalize_path(str(tmp_path) + "/" + nfc, sandbox_roots=[root])
    assert out_nfd == out_nfc


def test_determinism_100x(tmp_path: Path) -> None:
    root = str(tmp_path)
    target = str(tmp_path / "deep" / "a.txt")
    outs = {canonicalize_path(target, sandbox_roots=[root]) for _ in range(100)}
    assert len(outs) == 1


# --------------------------------------------------------------------------- #
# Windows path aliasing (NTFS trailing dots/spaces) + junction escape
# --------------------------------------------------------------------------- #


@pytest.mark.skipif(os.name != "nt", reason="NTFS trailing dot/space semantics")
def test_windows_trailing_dot_space_aliasing(tmp_path: Path) -> None:
    # On NTFS 'a.txt', 'a.txt.', 'a.txt...' and 'a.txt ' are the SAME file —
    # they must canonicalize identically or policy/fingerprint matching is bypassed.
    root = str(tmp_path)
    base = canonicalize_path(root + "/a.txt", sandbox_roots=[root])
    dot = canonicalize_path(root + "/a.txt.", sandbox_roots=[root])
    dots = canonicalize_path(root + "/a.txt...", sandbox_roots=[root])
    space = canonicalize_path(root + "/a.txt ", sandbox_roots=[root])
    assert base == dot == dots == space


@pytest.mark.skipif(os.name != "nt", reason="NTFS trailing dot/space semantics")
def test_windows_dots_only_component_rejected(tmp_path: Path) -> None:
    root = str(tmp_path)
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(root + "/.../x", sandbox_roots=[root])


def test_strip_windows_trailing_helper() -> None:
    # Tested directly: real Windows realpath mangles dots-only names before the
    # helper sees them, so this OS-independent unit test pins the helper's logic.
    assert _strip_windows_trailing("c:/box/a.txt.") == "c:/box/a.txt"
    assert _strip_windows_trailing("c:/box/a.txt   ") == "c:/box/a.txt"
    assert _strip_windows_trailing("c:/box/keep") == "c:/box/keep"  # drive + empties preserved
    with pytest.raises(AmbiguousEffectError):
        _strip_windows_trailing("c:/box/.../x")  # dots-only component


@pytest.mark.skipif(os.name != "nt", reason="NTFS junction (mklink /J needs no admin)")
def test_windows_junction_escape_raises(tmp_path: Path) -> None:
    box = tmp_path / "box"
    box.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    junction = box / "j"
    comspec = os.environ.get("COMSPEC", r"C:\Windows\System32\cmd.exe")
    proc = subprocess.run(  # noqa: S603 - fixed test command, no untrusted input
        [comspec, "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"mklink /J unavailable: {proc.stderr.strip()}")
    # realpath resolves the junction to 'outside', which escapes the box.
    with pytest.raises(AmbiguousEffectError):
        canonicalize_path(str(junction / "x.txt"), sandbox_roots=[str(box)])


# --------------------------------------------------------------------------- #
# canonicalize_url (test 3)
# --------------------------------------------------------------------------- #


def test_url_scheme_host_lowercased() -> None:
    origin, _ = canonicalize_url("HTTP://Example.COM/Path")
    assert origin == "http://example.com"


def test_url_default_port_omitted() -> None:
    assert canonicalize_url("https://example.com:443/x")[0] == "https://example.com"
    assert canonicalize_url("http://example.com:80/x")[0] == "http://example.com"


def test_url_nondefault_port_kept() -> None:
    assert canonicalize_url("http://example.com:8080/x")[0] == "http://example.com:8080"


def test_url_punycode_idn_same_key() -> None:
    o_unicode, _ = canonicalize_url("http://bücher.example/")
    o_puny, _ = canonicalize_url("http://xn--bcher-kva.example/")
    assert o_unicode == o_puny


def test_url_percent_unreserved_decoded_hex_uppercased() -> None:
    _, path = canonicalize_url("http://example.com/%41%2fb")
    # %41 -> 'A' (unreserved decoded); %2f -> %2F (reserved, hex uppercased, NOT decoded)
    assert path == "/A%2Fb"


def test_url_missing_scheme_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_url("example.com/path")


def test_url_missing_host_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_url("file:///etc/passwd")


def test_url_empty_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_url("   ")


def test_url_nul_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_url("http://example.com/\x00")


def test_url_invalid_port_rejected() -> None:
    # .port raises ValueError for an out-of-range port → fail-closed.
    with pytest.raises(AmbiguousEffectError):
        canonicalize_url("http://example.com:99999/x")


def test_url_idna_refused_host_falls_back() -> None:
    # A DNS label > 63 chars makes the IDNA codec raise; we fall back to the
    # lower-cased host verbatim rather than crashing (host stays the egress key).
    long_label = "a" * 100
    origin, _ = canonicalize_url(f"http://{long_label}.LOCAL/x")
    assert origin == f"http://{long_label}.local"


def test_url_ipv6_bracketed_and_roundtrippable() -> None:
    origin, _ = canonicalize_url("http://[::1]:8080/x")
    assert origin == "http://[::1]:8080"
    # the produced origin must itself re-canonicalize without raising (idempotent)
    again, _ = canonicalize_url(origin + "/x")
    assert again == origin


def test_url_ipv6_default_port_dropped() -> None:
    assert canonicalize_url("https://[2001:db8::1]:443/x")[0] == "https://[2001:db8::1]"


def test_url_host_trailing_dot_stripped() -> None:
    # FQDN-absolute form must match the bare host (aligns with normalize_domain).
    assert canonicalize_url("http://example.com./x")[0] == "http://example.com"


def test_url_empty_label_host_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_url("http://example..com/x")


def test_url_host_only_dots_rejected() -> None:
    # host '.' collapses to empty after the trailing-dot strip → fail closed
    with pytest.raises(AmbiguousEffectError):
        canonicalize_url("http://./x")


def test_url_path_dot_segments_resolved() -> None:
    assert canonicalize_url("http://example.com/a/../b")[1] == "/b"
    assert canonicalize_url("http://example.com/a/./b")[1] == "/a/b"  # '.' segment dropped
    # decoded %2e%2e must not survive as a traversal
    assert canonicalize_url("http://example.com/%2e%2e/x")[1] == "/x"


# --------------------------------------------------------------------------- #
# canonicalize_command (test 4)
# --------------------------------------------------------------------------- #


def test_command_single_string_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_command("ls -la")  # type: ignore[arg-type]


def test_command_argv_passthrough() -> None:
    assert canonicalize_command(["ls", "-la"]) == ["ls", "-la"]


def test_command_nfc_normalized() -> None:
    assert canonicalize_command(["é"]) == [unicodedata.normalize("NFC", "é")]


def test_command_nul_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_command(["ls", "a\x00b"])


def test_command_empty_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_command([])


def test_command_non_str_element_rejected() -> None:
    with pytest.raises(AmbiguousEffectError):
        canonicalize_command(["ls", 7])  # type: ignore[list-item]
