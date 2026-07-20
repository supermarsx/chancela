# Connector secret mount

Place development-only connector secret files in this directory, or set
`CHANCELA_CONNECTOR_SECRETS_HOST_DIR` to a protected host directory. Files are
mounted read-only at `/run/chancela-connector-secrets`; only `.gitignore` and
this README are tracked.

Production deployments should use an external secret manager or protected
Docker secret files and must restrict host permissions to the service account.
