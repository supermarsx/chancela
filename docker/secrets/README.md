# Docker secrets (postgres profile)

> Also documented on the site: [Configuration → Secrets](https://supermarsx.github.io/chancela/configuration/#secrets-postgres-profile).

**This directory is optional for the normal Compose profile.** It keeps API,
Postgres, signing-key, and restricted-projector credentials in named volumes
populated by `secrets-init`, so a fresh clone needs nothing here. The hardened
Compose file uses these host-backed secret files directly.

```sh
CHANCELA_PROJECTOR_DEDICATED_DATABASE=true \
  docker compose --profile postgres up -d
```

Set that acknowledgement only for a PostgreSQL **database dedicated to
Chancela**. The restricted projector initializer revokes database-global
`PUBLIC` `CONNECT`, `CREATE`, and `TEMPORARY`, plus public-schema `CREATE` and
routine `EXECUTE`; a shared application database is therefore unsupported.

Files placed here are **adopted** instead: `secrets-init` copies them into the
volume, as long as the volume does not already hold that secret. That is the
escape hatch for operators who manage their own values, and the migration path
for an installation created before the volume existed — leave the files where
they are and the running database keeps its password. Once a value is in the
volume the volume wins and a differing file here is ignored.

The real files are **gitignored** (see `.gitignore` here) — only the `*.example`
templates are committed. Never commit a real secret.

To generate host-side values with cryptographically random content:

```sh
sh docker/preflight-secrets.sh --generate
```

Before generating a missing owner password, the preflight discovers Compose
volumes through `com.docker.compose.project` /
`com.docker.compose.volume` labels (including custom project names) and probes
the volume for a real, nonempty `PG_VERSION`. Check-only mode likewise reports
stack-managed secrets only after probing the exact five regular, nonempty
files; mere volume existence is never treated as evidence.

Generation — here or in `secrets-init` — is strictly **create-if-absent**.
Each value is prepared privately and published with an atomic, no-clobber hard
link; a file that appears concurrently is accepted only when its exact value
matches. Empty files, symbolic links, CR/LF bytes, and `CHANGE_ME` in any letter
case are rejected before any missing value is persisted.
An uncatchable `SIGKILL` can leave a private `.chancela-*.publish.*` staging
directory, but never a partial destination file. Later runs use a fresh
`mktemp` directory and safely ignore that debris; after confirming no
initializer is active, the stale directory may be removed manually.
`postgres_password`/`database_url` and
`search_database_password`/`search_database_url` are produced as two independent
pairs, so each URL matches its password and the projector never inherits the API
owner credential. Host files have no trailing newline and mode `0600` (not
honoured on a Windows checkout). Each split named-volume directory is `0755`
and each secret file is root-owned `0444`: the read bit intentionally supports
the different non-root UIDs of the few declared consumers. Isolation comes
from attaching each per-secret volume only to those consumers, never from a
misleading owner-only mode. Every consumer mount is read-only.

Or supply your own by copying the templates and filling them in:

```sh
cp docker/secrets/postgres_password.example docker/secrets/postgres_password
cp docker/secrets/database_url.example      docker/secrets/database_url
cp docker/secrets/credential_key.example    docker/secrets/credential_key
cp docker/secrets/search_database_password.example docker/secrets/search_database_password
cp docker/secrets/search_database_url.example      docker/secrets/search_database_url
```

| Secret file         | Consumed as                        | Notes |
| ------------------- | ---------------------------------- | ----- |
| `postgres_password` | `POSTGRES_PASSWORD_FILE` (postgres) | At least 32 URI-unreserved characters (`A-Z a-z 0-9 . _ ~ -`). Read **only** when Postgres initialises `chancela-pgdata`; after that the password lives in the database and this file must keep matching it. |
| `database_url`      | `DATABASE_URL_FILE` (chancela app)  | Exact local-Compose libpq URL **including** the same password. References `postgres:5432` and requires `sslmode=verify-full`. |
| `credential_key`    | `CHANCELA_CREDENTIAL_KEY_FILE` (chancela app) | Provider-credential store root key. **Required** on Postgres (no SQLCipher `DerivedFromDbKey`). Any high-entropy value; generate with `openssl rand -base64 48`. Changing it makes already-stored credentials undecryptable. |
| `search_database_password` | role initializer only | Independent password with the same 32-character URI-unreserved minimum for the fixed `chancela_search_projector` PostgreSQL role. |
| `search_database_url` | `CHANCELA_SEARCH_DATABASE_URL_FILE` (projector) | Exact local-Compose URL containing the independent projector password. This restricted role has exact column-level corpus `SELECT` and derived-search DML grants, excluding retained PDF/import bytes and API/schema-owner access. |

The password inside `database_url` **must match** `postgres_password`, otherwise
the API cannot authenticate to Postgres. The password inside
`search_database_url` must separately match `search_database_password`.

The exact URL checks are intentionally scoped to these local Compose files:

```text
postgres://<role>:<password>@postgres:5432/<database>?sslmode=verify-full
```

External PostgreSQL hosts need an independently managed deployment and URL
validation path; do not weaken these local helpers to accept arbitrary hosts or
TLS modes.

The template uses `sslmode=verify-full`. The compose profile's isolated
`postgres-tls-init` service creates or renews a private CA and a certificate
whose SAN covers `postgres` and `localhost`. The CA is mounted read-only into
the app; no CA private key is exposed to the app container. Insecure
`disable`/`prefer`/`require` modes are rejected by the backend.

Prefer the repository generator, which emits 48 URL-safe password characters
from 36 random bytes and derives both exact URLs:

```sh
sh docker/preflight-secrets.sh --generate
```
