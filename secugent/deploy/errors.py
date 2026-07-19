# SPDX-License-Identifier: Apache-2.0
"""Domain exceptions for the air-gap deploy package.

A single :class:`AirgapError` root so callers (``bundle.sh`` driver, install
verifier, CI) can ``except AirgapError`` and fail closed on any reproducibility /
integrity violation without catching unrelated ``RuntimeError``s.
"""

from __future__ import annotations

__all__ = [
    "AirgapError",
    "BundleIntegrityError",
    "ConstraintsError",
]


class AirgapError(Exception):
    """Base for all air-gap bundle / reproducibility failures."""


class BundleIntegrityError(AirgapError):
    """Bundle contents do not match the manifest — install must be refused (I3)."""


class ConstraintsError(AirgapError):
    """A constraints line is not an exact pin — reproducibility broken (I2)."""
