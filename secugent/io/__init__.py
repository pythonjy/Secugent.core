# SPDX-License-Identifier: Apache-2.0
"""IO layer (``secugent.io``) — external-effect mediation, isolated from core.

All external side-effects route through the Egress Broker (``io.broker``); the
workload container stays ``network=none`` and the broker is the only egress path.
"""
