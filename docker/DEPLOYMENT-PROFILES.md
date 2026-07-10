# Docker Deployment Profiles

This directory contains bounded Docker Compose profiles for local and
single-node container deployment validation. They improve ARC-40/41/42 coverage
for container posture, but they are not production attestation evidence.

## Profiles

### `single-node`

Starts one `chancela-server` container from the existing server image:

```sh
docker compose -f docker/docker-compose.yml --profile single-node up --build
```

The service uses:

- non-root UID/GID `65532:65532`
- read-only root filesystem
- all Linux capabilities dropped
- `no-new-privileges:true`
- `/tmp` as tmpfs scratch
- a persistent named volume mounted at `/var/lib/chancela`
- a container healthcheck against `GET /health`

The host port defaults to `127.0.0.1:8080`. Override it with
`CHANCELA_HOST_PORT`, for example:

```sh
CHANCELA_HOST_PORT=18080 docker compose -f docker/docker-compose.yml --profile single-node up
```

The existing Docker smoke scripts can validate this profile without rebuilding
an image:

```sh
scripts/docker-smoke.sh --compose-profile chancela-server:local
```

```powershell
scripts\docker-smoke.ps1 -Image chancela-server:local -ComposeProfile
```

### `validation-worker`

Starts the `server` service plus a bounded `validation-worker` sidecar that
reuses the same server image:

```sh
docker compose -f docker/docker-compose.yml --profile validation-worker up --build
```

The sidecar has the same non-root, read-only, capability-dropped posture as the
server. It binds only inside the Compose network on port `8081`, has its own
persistent named volume, and exposes a healthcheck against its internal
`/health` endpoint.

Current limitation: this is a deployment-profile placeholder for isolation and
health validation. It is not a dedicated asynchronous worker, validation queue,
or production sidecar implementation because the repository does not currently
ship a separate worker image or worker entrypoint.

## Image Signing And Attestation

These profiles do not sign, attest, notarize, push, or verify images. They only
build or run local Docker images. Do not describe images produced by these
commands as signed or attested unless a separate signing and provenance pipeline
has been configured and its evidence is available.

## HA And Multi-Node Limits

These profiles are single-host profiles. They do not provide:

- high availability
- distributed locking
- database failover
- rolling updates
- registry promotion controls
- runtime admission policy enforcement

Use them as local smoke and bounded deployment coverage, not as a complete
production deployment architecture.
