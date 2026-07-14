# Docker secrets (postgres profile)

The `postgres` compose profile (`docker/docker-compose.yml`) reads three
file-based docker secrets from this directory. The real files are **gitignored**
(see `.gitignore` here) — only the `*.example` templates are committed. Never
commit a real secret.

Create the real secrets by copying the templates and filling them in:

```sh
cp docker/secrets/postgres_password.example docker/secrets/postgres_password
cp docker/secrets/database_url.example      docker/secrets/database_url
cp docker/secrets/credential_key.example    docker/secrets/credential_key
```

| Secret file         | Consumed as                        | Notes |
| ------------------- | ---------------------------------- | ----- |
| `postgres_password` | `POSTGRES_PASSWORD_FILE` (postgres) | Long random password. |
| `database_url`      | `DATABASE_URL_FILE` (chancela app)  | Full libpq URL **including** the same password. References the local `postgres` service by name. |
| `credential_key`    | `CHANCELA_CREDENTIAL_KEY_FILE` (chancela app) | Provider-credential store root key. **Required** on Postgres (no SQLCipher `DerivedFromDbKey`). Any high-entropy value; generate with `openssl rand -base64 48`. |

The password inside `database_url` **must match** `postgres_password`, otherwise
the app cannot authenticate to Postgres.

The template uses `sslmode=disable` because this compose lane connects to the
local Compose network with the current `NoTls` backend. Remote Postgres with
`sslmode=verify-full` needs a future TLS connector before it is supported.

Generate strong values, for example:

```sh
openssl rand -base64 32 > docker/secrets/postgres_password   # then paste into database_url too
openssl rand -base64 48 > docker/secrets/credential_key
```
