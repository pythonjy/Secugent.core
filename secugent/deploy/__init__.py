# SPDX-License-Identifier: Apache-2.0
"""Air-gap / on-prem deployment hardening (BDP_04 항목 13).

Pure, infra-free logic that backs the deploy artifacts:

* :mod:`secugent.deploy.airgap` — bundle manifest/checksum generation,
  tamper-detection, constraints (exact-pin) reproducibility validation, and the
  single-writer HA arbiter that rides on the existing
  :class:`secugent.orchestrator.lease.LeaseManager`.

Importing this package pulls in **no** optional dependency (boto3/hvac/cosign):
those are install-time / shell-time tooling, not Python runtime imports
(CLAUDE.md §A — framework/model neutral, closed-network first).
"""
