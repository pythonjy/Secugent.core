# SPDX-License-Identifier: Apache-2.0
"""Probabilistic (LLM-backed) modules, isolated from the deterministic core.

Modules here are scored against golden datasets with
F1/Precision/Recall gates and a Korean eval set — never trusted without
verification, and never on the enforcement path (their output must pass a
deterministic sign/verify gate).
"""
