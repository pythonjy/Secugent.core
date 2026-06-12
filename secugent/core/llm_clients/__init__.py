# SPDX-License-Identifier: Apache-2.0
"""Registry for domestic/sovereign :class:`LLMClient` adapters.

Maps a domestic model selector (``exaone`` | ``hyperclova`` | ``ax`` | ``solar``)
to its concrete adapter class. This module holds **no control decision logic**
— it is a pure name→constructor dispatch so ``secugent.core`` can obtain a
sovereign client through the :class:`LLMClient` abstraction without importing
any concrete adapter directly (§A-2.3 model-neutral core, isolation invariant).

The supported selectors are exposed as :data:`DomesticModel` (a ``Literal``) so
settings can make an unsupported model unrepresentable at the type level.
"""

from __future__ import annotations

from typing import Any, Final, Literal, get_args

from secugent.core.llm_client import LLMClient, LLMError

from ._base import BaseDomesticLLMClient
from .ax import AxLLMClient
from .exaone import ExaoneLLMClient
from .hyperclova import HyperClovaLLMClient
from .solar import SolarLLMClient

__all__ = [
    "DomesticModel",
    "DOMESTIC_MODELS",
    "build_domestic_client",
    "ExaoneLLMClient",
    "HyperClovaLLMClient",
    "AxLLMClient",
    "SolarLLMClient",
]

DomesticModel = Literal["exaone", "hyperclova", "ax", "solar"]

#: Selector → concrete adapter class. The only place names bind to classes.
#: Typed as ``BaseDomesticLLMClient`` (not the bare ``LLMClient`` ABC) so the
#: shared ``endpoint=`` constructor keyword is statically known here.
_REGISTRY: Final[dict[str, type[BaseDomesticLLMClient]]] = {
    "exaone": ExaoneLLMClient,
    "hyperclova": HyperClovaLLMClient,
    "ax": AxLLMClient,
    "solar": SolarLLMClient,
}

#: Tuple of supported selectors (kept in sync with the ``Literal`` at runtime).
DOMESTIC_MODELS: Final[tuple[str, ...]] = get_args(DomesticModel)


def build_domestic_client(model: str, *, endpoint: str, **kwargs: Any) -> LLMClient:
    """Construct the concrete domestic client for ``model``.

    ``model`` must be one of :data:`DOMESTIC_MODELS`. An unsupported/unknown
    name raises :class:`LLMError` (fail-closed; never returns a permissive
    default). Extra keyword args (``api_key``, ``model_id``, ``timeout``,
    ``transport``, ``max_attempts``) pass through to the adapter constructor;
    ``model_id`` binds the sovereign model the endpoint serves so ``generate``
    does not forward a caller's cloud (Claude) model id to it.
    """
    client_cls = _REGISTRY.get(model)
    if client_cls is None:
        supported = ", ".join(sorted(_REGISTRY))
        raise LLMError(f"unsupported domestic model {model!r}; supported: {supported}")
    return client_cls(endpoint=endpoint, **kwargs)
