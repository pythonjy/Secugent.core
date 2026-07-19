# SPDX-License-Identifier: Apache-2.0
"""DA-H1 / DA-M1 / DA-M3 / DA-M6 — deploy-artifact env contract regression guard.

W5-a shipped the OIDC/session + REGULATIONS + Alembic-migrate config across the
three operator-facing artifact families (``.env.example``, ``docker-compose.yml``,
the Helm chart). The boot path reads these env vars by *exact* name
(``secugent/api/main.py`` · ``oidc_login.py`` · ``session.py``); if an artifact
silently drops one, production fails closed at boot with a confusing error or —
worse — an operator believes auth/MFA/policy is configured when it is not.

These are STRING-PRESENCE / structural checks on the artifact files (no Docker or
Helm runtime needed), pinning that:

* every required OIDC/session + regulations env key is documented in
  ``deploy/.env.example`` and *forwarded* into the ``secugent-api`` container by
  ``docker-compose.yml`` (compose ``.env`` only feeds ``${}`` interpolation — an
  unlisted var never reaches the container);
* the Helm ConfigMap declares the non-secret OIDC vars + regulations path +
  ``SECUGENT_OIDC_REQUIRE_MFA``, the Secret declares the two auth secret keys, and
  ``values.yaml`` exposes the matching knobs;
* the required-prod secrets are fail-closed (``${VAR:?...}`` in compose), and the
  recommended secure default ``SECUGENT_OIDC_REQUIRE_MFA`` resolves to ``true``;
* the gated Alembic migration step exists in BOTH compose (``secugent-migrate``)
  and Helm (a pre-install/pre-upgrade hook Job).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

_DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
_ENV_EXAMPLE = _DEPLOY / ".env.example"
_COMPOSE = _DEPLOY / "docker-compose.yml"
_HELM = _DEPLOY / "helm"
_CONFIGMAP = _HELM / "templates" / "configmap.yaml"
_SECRET = _HELM / "templates" / "secret.yaml"
_VALUES = _HELM / "values.yaml"
_MIGRATE_JOB = _HELM / "templates" / "migrate-job.yaml"

# --- The auth/policy env contract the app reads by exact name -----------------

# Required in production (compose enforces with ${VAR:?...}). Secrets must come
# from a secret store, never the ConfigMap.
_REQUIRED_PROD_VARS = (
    "SECUGENT_OIDC_ISSUER",
    "SECUGENT_OIDC_CLIENT_ID",
    "SECUGENT_OIDC_CLIENT_SECRET",
    "SECUGENT_SESSION_SECRET",
)

# Optional / recommended OIDC knobs (app applies a default when unset).
_OPTIONAL_OIDC_VARS = (
    "SECUGENT_OIDC_ALGORITHM",
    "SECUGENT_OIDC_JWKS_URL",
    "SECUGENT_OIDC_JWKS_FILE",
    "SECUGENT_OIDC_GROUP_MAP",
    "SECUGENT_OIDC_REQUIRE_MFA",
)

# REGULATIONS policy path (DA-M1) — prod refuses an allow-all engine without it.
_REGULATIONS_VAR = "SECUGENT_REGULATIONS_PATH"

# The full set every artifact must DECLARE/forward.
_ALL_CONTRACT_VARS = (*_REQUIRED_PROD_VARS, *_OPTIONAL_OIDC_VARS, _REGULATIONS_VAR)

# The two secret-store-only keys (ConfigMap must NOT carry them).
_SECRET_ONLY_VARS = ("SECUGENT_OIDC_CLIENT_SECRET", "SECUGENT_SESSION_SECRET")

# Non-secret vars the Helm ConfigMap renders (everything except the secrets).
_CONFIGMAP_VARS = tuple(v for v in _ALL_CONTRACT_VARS if v not in _SECRET_ONLY_VARS)


# --- helpers ------------------------------------------------------------------


def _load_compose() -> dict[str, Any]:
    doc = yaml.safe_load(_COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), "docker-compose.yml root must be a mapping"
    return doc


def _api_environment() -> dict[str, str]:
    """Return the ``secugent-api`` service ``environment:`` as a key->value dict."""
    api = _load_compose()["services"]["secugent-api"]
    env = api.get("environment", {})
    if isinstance(env, dict):
        return {str(k): str(v) for k, v in env.items()}
    # list form: "KEY=value" entries
    out: dict[str, str] = {}
    for entry in env:
        key, _, value = str(entry).partition("=")
        out[key] = value
    return out


# --- .env.example -------------------------------------------------------------


@pytest.mark.parametrize("var", _ALL_CONTRACT_VARS)
def test_env_example_documents_var(var: str) -> None:
    text = _ENV_EXAMPLE.read_text(encoding="utf-8")
    assert re.search(rf"^#?{re.escape(var)}=", text, re.MULTILINE), (
        f"{var} not documented in deploy/.env.example (active or commented line)"
    )


# --- docker-compose forwarding ------------------------------------------------


@pytest.mark.parametrize("var", _ALL_CONTRACT_VARS)
def test_compose_forwards_var(var: str) -> None:
    """compose ``.env`` only feeds ``${}`` interpolation — each contract var must
    be listed explicitly in the api ``environment:`` or it never reaches the app."""
    env = _api_environment()
    assert var in env, f"{var} not forwarded to secugent-api in docker-compose.yml"


@pytest.mark.parametrize("var", _REQUIRED_PROD_VARS)
def test_compose_required_vars_fail_closed(var: str) -> None:
    """Required prod vars must use ``${VAR:?...}`` so an unset value aborts boot."""
    value = _api_environment()[var]
    assert value.startswith("${") and ":?" in value, (
        f"{var} must be a fail-closed required reference (${{{var}:?...}}); got {value!r}"
    )


def test_compose_require_mfa_defaults_true() -> None:
    """Recommended secure default: MFA on unless the operator opts out (§A-2)."""
    value = _api_environment()["SECUGENT_OIDC_REQUIRE_MFA"]
    assert value == "${SECUGENT_OIDC_REQUIRE_MFA:-true}", (
        f"SECUGENT_OIDC_REQUIRE_MFA must default to true; got {value!r}"
    )


def test_compose_regulations_points_at_in_image_default() -> None:
    value = _api_environment()[_REGULATIONS_VAR]
    assert "/app/regulations_examples/default.json" in value, (
        f"{_REGULATIONS_VAR} must default to the in-image default.json; got {value!r}"
    )


# --- Alembic migrate step (DA-M6) --------------------------------------------


def test_compose_has_gated_migrate_service() -> None:
    """A gated one-shot ``secugent-migrate`` runs ``alembic upgrade head`` and is
    behind the ``pg-migrate`` profile so the default boot is unaffected."""
    svc = _load_compose()["services"].get("secugent-migrate")
    assert svc is not None, "secugent-migrate service missing from docker-compose.yml"
    assert "pg-migrate" in svc.get("profiles", []), (
        "secugent-migrate must be gated behind the 'pg-migrate' profile"
    )
    command = (
        " ".join(str(p) for p in svc["command"]) if isinstance(svc["command"], list) else str(svc["command"])
    )
    assert "alembic" in command and "upgrade" in command and "head" in command


def test_compose_api_depends_on_migrate_not_required() -> None:
    """api waits for migrate ONLY when the profile is on (``required: false``), so
    the single-command boot promise holds with the profile off."""
    api = _load_compose()["services"]["secugent-api"]
    dep = api["depends_on"]["secugent-migrate"]
    assert dep["condition"] == "service_completed_successfully"
    assert dep["required"] is False


# --- Helm ConfigMap / Secret / values -----------------------------------------


@pytest.mark.parametrize("var", _CONFIGMAP_VARS)
def test_helm_configmap_declares_nonsecret_var(var: str) -> None:
    text = _CONFIGMAP.read_text(encoding="utf-8")
    assert var in text, f"{var} not declared in helm configmap.yaml"


@pytest.mark.parametrize("var", _SECRET_ONLY_VARS)
def test_helm_configmap_excludes_secret_var(var: str) -> None:
    """The two auth secrets must NOT be RENDERED as ConfigMap data keys (a comment
    may *name* them to explain they live in the Secret — that is allowed)."""
    text = _CONFIGMAP.read_text(encoding="utf-8")
    assert not re.search(rf"^\s*{re.escape(var)}:", text, re.MULTILINE), (
        f"{var} is a secret and must not be a ConfigMap data key"
    )


@pytest.mark.parametrize("var", _SECRET_ONLY_VARS)
def test_helm_secret_declares_secret_var(var: str) -> None:
    text = _SECRET.read_text(encoding="utf-8")
    assert var in text, f"{var} not declared in helm secret.yaml"


@pytest.mark.parametrize(
    "token",
    (
        "oidc:",
        "issuer:",
        "clientId:",
        "requireMfa:",
        "jwksFile:",
        "existingSecret:",
        "regulations:",
        "path:",
        "OIDC_CLIENT_SECRET:",
        "SESSION_SECRET:",
    ),
)
def test_helm_values_exposes_knob(token: str) -> None:
    text = _VALUES.read_text(encoding="utf-8")
    assert token in text, f"helm values.yaml missing knob {token!r}"


def test_helm_values_require_mfa_default_true() -> None:
    """The chart default for MFA must be true (overridable, but secure by default)."""
    values = yaml.safe_load(_VALUES.read_text(encoding="utf-8"))
    assert values["oidc"]["requireMfa"] is True


def test_helm_has_gated_migration_job() -> None:
    """A pre-install/pre-upgrade hook Job runs ``alembic upgrade head``, gated on
    ``postgresql.enabled`` so it renders nothing on the default install."""
    text = _MIGRATE_JOB.read_text(encoding="utf-8")
    assert "kind: Job" in text
    assert "alembic" in text and "upgrade" in text and "head" in text
    assert "pre-install,pre-upgrade" in text
    assert ".Values.postgresql.enabled" in text, "migration Job must be gated on postgresql.enabled"
