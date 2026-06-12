# SecuGent API image — single-command on-prem deployment.
#
# Pinned base for reproducible, air-gap-friendly builds. No external SaaS
# dependency at runtime: the container only needs Postgres + Vault reachable
# on the compose network.
#
# IMAGE SIGNING (BDP_04 항목 13): images are signed OUT-OF-BAND with cosign after
# build (`cosign sign --key cosign.key secugent/api:<ver>`), and the air-gap
# bundle ships a cosign signature over MANIFEST.sha256 (deploy/airgap/bundle.sh
# --sign). Air-gap installers verify provenance before `docker load`
# (deploy/airgap/README.md §2). Signing is a build-host step, not a layer here.
FROM python:3.11-slim

# curl is required by the HEALTHCHECK below (and is handy for debugging).
# Pin nothing weakly: clean the apt lists so no stale index is baked in.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/*

# Keep Python lean and deterministic inside the container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copy build metadata first so the dependency install layer caches across
# source-only changes. README.md is required because pyproject reads it as the
# long description. (requirements.txt is intentionally NOT copied/installed: the
# image installs from pyproject extras below.) deploy/constraints.txt is copied
# alongside so the install is pinned to exact versions for a reproducible,
# air-gappable image (BDP_04 항목 13 / invariant I2).
COPY pyproject.toml README.md ./
COPY deploy/constraints.txt ./constraints.txt

# Copy the package and its runtime fixtures/scripts.
COPY secugent/ ./secugent/
COPY regulations_examples/ ./regulations_examples/
COPY scripts/ ./scripts/

# Install the package WITH the pg + vault + obs extras so hvac, sqlalchemy and
# asyncpg (Postgres event store + Vault secrets backend) AND the observability
# runtime (opentelemetry + prometheus_client) are present. The obs extra is
# mandatory: create_app() calls init_tracing() and serves /metrics at boot, so
# without it the container crashes before /healthz can pass and the whole stack
# (ui/prometheus/grafana depend on this service) comes up dead.
#
# REPRODUCIBILITY (BDP_04 항목 13 / invariant I2): `-c constraints.txt` pins every
# resolved dependency to an EXACT version (deploy/constraints.txt, validated by
# secugent.deploy.airgap.parse_constraints to contain only `name==version` pins).
# pyproject's `>=` lower bounds still apply, but the constraints file forces the
# upper resolution to a fixed point so two builds resolve identically — required
# for air-gap byte-reproducibility. Regenerate constraints.txt (pip freeze) when
# bumping deps and record the reason in CHANGELOG (§B-9).
RUN pip install --no-cache-dir -c constraints.txt ".[pg,vault,obs]"

# Run as an unprivileged user. The durable event-store dir (/app/data, the
# SQLite append-only audit log + hash chain) and the logs dir are created and
# owned by appuser so the non-root process can write them. A named volume
# mounted at /app/data inherits THIS ownership; without the chown the volume
# mountpoint would be root-owned and the process would hit EACCES (C-1/C-2).
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /app/logs/events /app/data \
    && chown -R appuser:appuser /app/logs /app/data

USER appuser

EXPOSE 8000

# Fail closed if the API stops serving: the orchestrator restart policy in
# compose recycles unhealthy containers.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://localhost:8000/healthz || exit 1

# CLI reachability (BDP Phase 1 item 3): the `secugent` console script is
# installed by `pip install` above (pyproject `[project.scripts]`), so the
# key-less demo and the read-only verify proofs are reachable WITHOUT changing
# the default server boot. We deliberately set NO ENTRYPOINT so the CMD can be
# overridden positionally:
#
#   docker run --rm <img>                 # default: the uvicorn API server
#   docker run --rm <img> secugent demo   # key-less demo (override CMD)
#   docker run --rm <img> secugent verify --chain --tenant <t> --store <p>
#
# Keeping the server as the default CMD preserves the compose/HEALTHCHECK
# contract (ui/prometheus/grafana depend on the API), while the CLI stays one
# `docker run` argument away.
#
# main.py exposes a `create_app` factory (no module-level `app`), so boot it via
# uvicorn's --factory flag. This is the import-string-correct equivalent of
# `secugent.api.main:app` for a factory entrypoint.
CMD ["uvicorn", "secugent.api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
