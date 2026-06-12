# SPDX-License-Identifier: Apache-2.0
"""Deterministic effect-target canonicalization (EM-01).

Reduces a file path / URL / command to a canonical form, **failing closed**
(:class:`AmbiguousEffectError`) on any input that cannot be unambiguously and
deterministically normalized. This is invariant **I-E** of the EM series
(SECURITY_CONTRACT §11): normalization failure ⇒ block.

Relationship to :mod:`secugent.core.mechanical_oversight` (intended divergence):
``normalize_path`` there resolves ``..`` *lexically* and silently anchors at the
root (glob-matching, no filesystem access). :func:`canonicalize_path` here is for
**sandbox isolation** — it resolves symlinks and ``..`` against the real
filesystem (``os.path.realpath``) and *raises* when the result escapes
``sandbox_roots``. The refusal tokens (NUL, ``%VAR%``/``${VAR}``, 8.3 short
names) are kept identical so the two layers agree on what is non-normalizable.

Purity: no mutation, no network. ``realpath`` performs read-only filesystem path
resolution (required to detect symlink escapes); outputs are deterministic for a
given input + filesystem state, and inputs must be absolute (no ``cwd``
dependence).
"""

from __future__ import annotations

import os
import re
import string
import unicodedata
from urllib.parse import urlsplit

__all__ = [
    "AmbiguousEffectError",
    "canonicalize_path",
    "canonicalize_url",
    "canonicalize_command",
]


class AmbiguousEffectError(Exception):
    """Raised when an effect target cannot be canonicalized (fail-closed)."""


# 8.3 short-name token like FOO~1, BAR~12 — non-deterministic, refused.
_SHORT_NAME_RE = re.compile(r"~\d")
# Lower-cased Windows drive letter component, e.g. ``c:``.
_DRIVE_RE = re.compile(r"[a-z]:")
# `%VAR%` or `$VAR`/`${VAR}` environment-variable expansion — non-deterministic.
_ENV_VAR_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")

# Default ports that are dropped from a canonical origin.
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}

# RFC 3986 unreserved set — percent-encodings of these are decoded.
_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")
_PCT_RE = re.compile(r"%([0-9A-Fa-f]{2})")


# --------------------------------------------------------------------------- #
# Path
# --------------------------------------------------------------------------- #


def canonicalize_path(raw: str, *, sandbox_roots: list[str]) -> str:
    """Canonicalize ``raw`` to a forward-slash, lower-case absolute path that is
    guaranteed to live inside one of ``sandbox_roots``.

    Raises :class:`AmbiguousEffectError` on: empty/NUL/env-var/8.3 input, a
    non-absolute target or root, an empty ``sandbox_roots`` (nothing allowed),
    or a target whose real path (after ``..``/symlink resolution) escapes every
    root.
    """
    if not isinstance(raw, str) or not raw:
        raise AmbiguousEffectError("path must be a non-empty string")
    if not sandbox_roots:
        raise AmbiguousEffectError("no sandbox roots configured (deny-by-default)")

    nfc = unicodedata.normalize("NFC", raw)
    if "\x00" in nfc:
        raise AmbiguousEffectError("path contains NUL byte")
    if _ENV_VAR_RE.search(nfc):
        raise AmbiguousEffectError("path contains environment-variable expansion")
    if _SHORT_NAME_RE.search(nfc):
        raise AmbiguousEffectError("path contains 8.3 short-name token (e.g., FOO~1)")
    if not os.path.isabs(nfc):
        raise AmbiguousEffectError("path must be absolute (relative paths are ambiguous)")

    resolved = _realpath_norm(nfc)
    root_norms = _canonical_roots(sandbox_roots)
    for root in root_norms:
        if resolved == root or resolved.startswith(root.rstrip("/") + "/"):
            return resolved
    raise AmbiguousEffectError("path escapes all sandbox roots")


def _canonical_roots(sandbox_roots: list[str]) -> list[str]:
    roots: list[str] = []
    for root in sandbox_roots:
        if not isinstance(root, str) or not root:
            raise AmbiguousEffectError("sandbox root must be a non-empty string")
        nfc = unicodedata.normalize("NFC", root)
        if not os.path.isabs(nfc):
            raise AmbiguousEffectError(f"sandbox root must be absolute: {root!r}")
        roots.append(_realpath_norm(nfc))
    return roots


def _realpath_norm(path: str) -> str:
    """``os.path.realpath`` then unify to forward-slash, lower-case.

    On Windows, trailing dots/spaces on each component are stripped because NTFS
    ignores them (``a.txt`` and ``a.txt.`` are the *same* file): without this,
    one on-disk file would have several distinct canonical forms, defeating
    policy/fingerprint matching. A component that is *only* dots/spaces is
    ambiguous and fails closed.
    """
    try:
        resolved = os.path.realpath(path)
    except OSError as exc:  # pragma: no cover - platform dependent
        raise AmbiguousEffectError(f"path resolution failed: {exc}") from exc
    norm = resolved.replace("\\", "/").lower()
    if os.name == "nt":
        norm = _strip_windows_trailing(norm)
    return norm


def _strip_windows_trailing(norm: str) -> str:
    """Strip trailing dots/spaces from each path component (NTFS semantics)."""
    segments = norm.split("/")
    out: list[str] = []
    for index, segment in enumerate(segments):
        # Preserve empties (UNC ``//`` / root ``/``) and a drive letter (``c:``).
        if segment == "" or (index == 0 and _DRIVE_RE.fullmatch(segment)):
            out.append(segment)
            continue
        stripped = segment.rstrip(" .")
        if stripped == "":
            raise AmbiguousEffectError(f"ambiguous path component (dots/spaces only): {segment!r}")
        out.append(stripped)
    return "/".join(out)


# --------------------------------------------------------------------------- #
# URL
# --------------------------------------------------------------------------- #


def canonicalize_url(raw: str) -> tuple[str, str]:
    """Return ``(origin, path)`` where ``origin = 'scheme://host[:port]'``.

    Scheme and host are lower-cased; IDN hosts become punycode; default ports
    are dropped; the path's percent-encoding is normalized (unreserved decoded,
    reserved hex upper-cased). ``host`` is the egress decision key.

    Raises :class:`AmbiguousEffectError` when the scheme or host is missing or
    the URL cannot be parsed.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise AmbiguousEffectError("url must be a non-empty string")
    nfc = unicodedata.normalize("NFC", raw.strip())
    if "\x00" in nfc:
        raise AmbiguousEffectError("url contains NUL byte")
    # urlsplit and the .hostname / .port accessors all raise ValueError on
    # malformed authorities (bad IPv6 brackets, out-of-range ports): catch here.
    try:
        parts = urlsplit(nfc)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise AmbiguousEffectError(f"invalid URL: {exc}") from exc

    if not scheme:
        raise AmbiguousEffectError("url has no scheme")
    if not host:
        raise AmbiguousEffectError("url has no host")

    if ":" in host:
        # IPv6 literal — idna can't encode it; keep it bracketed so the origin
        # stays unambiguous (host vs port) and round-trippable.
        host_repr = f"[{host.lower()}]"
    else:
        host = host.rstrip(".")  # FQDN-absolute 'example.com.' == 'example.com'
        if not host:
            raise AmbiguousEffectError("url has empty host")
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except (UnicodeError, UnicodeDecodeError):
            # Already-ASCII hosts (incl. punycode) that idna refuses: keep verbatim.
            ascii_host = host.lower()
        if ascii_host.startswith(".") or ".." in ascii_host:
            raise AmbiguousEffectError(f"url host has an empty label: {ascii_host!r}")
        host_repr = ascii_host

    origin = f"{scheme}://{host_repr}"
    if port is not None and _DEFAULT_PORTS.get(scheme) != port:
        origin = f"{origin}:{port}"

    return origin, _remove_dot_segments(_normalize_percent(parts.path))


def _normalize_percent(value: str) -> str:
    """RFC 3986 percent-encoding normalization: decode unreserved octets, and
    upper-case the hex of everything else (do NOT decode reserved chars)."""

    def repl(match: re.Match[str]) -> str:
        hexpair = match.group(1)
        char = chr(int(hexpair, 16))
        if char in _UNRESERVED:
            return char
        return "%" + hexpair.upper()

    return _PCT_RE.sub(repl, value)


def _remove_dot_segments(path: str) -> str:
    """Resolve ``.`` / ``..`` segments in a URL path (RFC 3986 §5.2.4).

    ``..`` never escapes the root (clamps), so a decoded ``%2e%2e`` cannot become
    a traversal in the canonical path. Empty segments (``//``) are preserved.
    """
    if "." not in path:
        return path
    out: list[str] = []
    for segment in path.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if out and out[-1] != "":  # pop a real segment; clamp at root
                out.pop()
            continue
        out.append(segment)
    return "/".join(out)


# --------------------------------------------------------------------------- #
# Command
# --------------------------------------------------------------------------- #


def canonicalize_command(argv: list[str]) -> list[str]:
    """Canonicalize an argv list. A single string is refused (list only).

    Each argument is NFC-normalized; case is preserved (commands are
    case-sensitive). Raises :class:`AmbiguousEffectError` on a non-list input, an
    empty argv, a non-string element, or a NUL byte.
    """
    if not isinstance(argv, list):
        raise AmbiguousEffectError("command must be a list of arguments (argv), not a string")
    if not argv:
        raise AmbiguousEffectError("command argv must be non-empty")
    out: list[str] = []
    for arg in argv:
        if not isinstance(arg, str):
            raise AmbiguousEffectError("every argv element must be a string")
        if "\x00" in arg:
            raise AmbiguousEffectError("argv element contains NUL byte")
        out.append(unicodedata.normalize("NFC", arg))
    return out
