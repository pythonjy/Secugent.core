# SPDX-License-Identifier: Apache-2.0
"""SecuGent command-line interface (Core, Apache-2.0).

Ships the read-only ``secugent verify`` subcommand and the
:mod:`secugent.cli.__main__` dispatcher with ``run``/``demo``. The
public verification API lives in :mod:`secugent.cli.verify` and re-uses the
existing audit crypto (``hash_chain``/``merkle``) — it adds no new primitives.
"""

from __future__ import annotations

from secugent.cli.verify import (
    ChainReport,
    DeterminismReport,
    VerifyInputError,
    verify_audit_chain,
    verify_determinism,
)

__all__ = [
    "ChainReport",
    "DeterminismReport",
    "VerifyInputError",
    "verify_audit_chain",
    "verify_determinism",
]
