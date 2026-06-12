# SPDX-License-Identifier: Apache-2.0
"""PHASE 12 — audit integrity primitives."""

from secugent.audit.export import EDiscoveryExporter
from secugent.audit.hash_chain import (
    AuditChainBrokenError,
    ChainedEventRecord,
    ChainedEventStore,
)
from secugent.audit.merkle import (
    KmsProvider,
    LocalHmacKmsProvider,
    MerkleSigner,
    SignedMerkleRoot,
)

__all__ = [
    "AuditChainBrokenError",
    "ChainedEventRecord",
    "ChainedEventStore",
    "EDiscoveryExporter",
    "KmsProvider",
    "LocalHmacKmsProvider",
    "MerkleSigner",
    "SignedMerkleRoot",
]
