# Docker secrets (postgres profile)

> Also documented on the site: [Configuration → Secrets](https://supermarsx.github.io/chancela/configuration/#secrets-postgres-profile).

**This directory is optional.** The `postgres` compose profile keeps its three
secrets in the `chancela-secrets` named volume, populated by the `secrets-init`
service before anything that reads them starts, so a fresh clone needs nothing
here:

```sh
docker compose -f docker/docker-compose.yml --profile postgres up -d
```

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

Generation — here or in `secrets-init` — is strictly **create-if-absent**: an
existing secret is never rewritten, rotated or overwritten, because all three
are write-once (see the table below). `postgres_password` and `database_url` are
always produced together from the same value, so the pair cannot drift. Host
files are written with no trailing newline and mode `0600` (not honoured on a
Windows checkout); inside the volume each secret is `0400` and owned by the one
uid that reads it (`70` for `postgres_password`, `65532` for the other two).

Or supply your own by copying the templates and filling them in:

```sh
cp docker/secrets/postgres_password.example docker/secrets/postgres_password
cp docker/secrets/database_url.example      docker/secrets/database_url
cp docker/secrets/credential_key.example    docker/secrets/credential_key
```

| Secret file         | Consumed as                        | Notes |
| ------------------- | ---------------------------------- | ----- |
| `postgres_password` | `POSTGRES_PASSWORD_FILE` (postgres) | Long random password. Read **only** when Postgres initialises `chancela-pgdata`; after that the password lives in the database and this file must keep matching it. |
| `database_url`      | `DATABASE_URL_FILE` (chancela app)  | Full libpq URL **including** the same password. References the local `postgres` service by name. |
| `credential_key`    | `CHANCELA_CREDENTIAL_KEY_FILE` (chancela app) | Provider-credential store root key. **Required** on Postgres (no SQLCipher `DerivedFromDbKey`). Any high-entropy value; generate with `openssl rand -base64 48`. Changing it makes already-stored credentials undecryptable. |

The password inside `database_url` **must match** `postgres_password`, otherwise
the app cannot authenticate to Postgres.

The template uses `sslmode=verify-full`. The compose profile's isolated
`postgres-tls-init` service creates or renews a private CA and a certificate
whose SAN covers `postgres` and `localhost`. The CA is mounted read-only into
the app; no CA private key is exposed to the app container. Insecure
`disable`/`prefer`/`require` modes are rejected by the backend.

Generate strong values, for example:

```sh
openssl rand -base64 32 > docker/secrets/postgres_password   # then paste into database_url too
openssl rand -base64 48 > docker/secrets/credential_key
```
