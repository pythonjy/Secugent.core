# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON serialization (shared by compiler + signer).

The compiler's ``doc_hash`` and the signer's signed bytes MUST be derived from
the *same* canonical form, so both go through this single function (the same
JCS-style scheme used by the audit hash chain).
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["canonical_json"]


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, compact separators, UTF-8 preserved."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
