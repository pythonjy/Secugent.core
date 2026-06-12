# SPDX-License-Identifier: Apache-2.0
"""Snapshot + rollback for REVERSIBLE file effects (EM-09).

The honest scope: only genuinely reversible effects (sandbox file writes) can be
rolled back this way. Irreversible effects are caught pre-commit by staging
(``io.staging``); compensatable effects are handled by issuing a compensating
action (``steer.precommit.compensate``).
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["FileSnapshotStore"]


class FileSnapshotStore:
    """Captures a file's bytes before a reversible write so it can be restored."""

    def __init__(self) -> None:
        self._snapshots: dict[str, bytes | None] = {}

    def capture(self, path: str) -> bytes | None:
        """Snapshot ``path`` (None = file did not exist) and return its content."""
        target = Path(path)
        content = target.read_bytes() if target.is_file() else None
        self._snapshots[str(target)] = content
        return content

    def rollback(self, path: str) -> None:
        """Restore ``path`` to its snapshot. Raises if no snapshot was captured."""
        key = str(Path(path))
        if key not in self._snapshots:
            raise KeyError(f"no snapshot captured for {path!r}")
        content = self._snapshots[key]
        target = Path(path)
        if content is None:
            # Did not exist at snapshot time → remove the file the effect created.
            if target.exists():
                target.unlink()
        else:
            target.write_bytes(content)
