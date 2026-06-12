# SPDX-License-Identifier: Apache-2.0
"""IO layer (``secugent.io``) — external-effect mediation, isolated from core.

All external side-effects route through the Egress Broker (``io.broker``); the
workload container stays ``network=none`` and the broker is the only egress path
(SECURITY_CONTRACT §11 I-A). See ``docs/specs/2026-06-02-em-05-egress-broker.md``.
"""
