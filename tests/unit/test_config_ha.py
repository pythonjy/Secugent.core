# SPDX-License-Identifier: Apache-2.0
"""W1 supporting edit B — OrchestratorConfig HA fields.

The lease-wiring lane (G-C8) reads ``ha_enabled`` / ``ha_backend`` off
``OrchestratorConfig`` via ``getattr`` so it does not hard-depend on fields a
sibling lane is still adding. This test pins the fields' existence + safe
defaults (HA off, single-node) so the wiring stops needing ``# type: ignore``.
"""

from __future__ import annotations

from secugent.config import OrchestratorConfig


def test_ha_defaults_off_single_node() -> None:
    cfg = OrchestratorConfig()
    assert cfg.ha_enabled is False
    assert cfg.ha_backend == "memory"


def test_ha_fields_are_settable() -> None:
    cfg = OrchestratorConfig(ha_enabled=True, ha_backend="pg")
    assert cfg.ha_enabled is True
    assert cfg.ha_backend == "pg"


def test_existing_run_state_fields_unchanged() -> None:
    cfg = OrchestratorConfig()
    # F8/F13: the default is now None (UNCONFIGURED) so the boot path can tell an
    # operator's explicit "memory" apart from the default and fail fast in prod.
    assert cfg.run_state_backend is None
    assert cfg.run_state_db_path == "data/run_state.db"
    assert cfg.auto_approve is False
    assert cfg.fail_fast is True
