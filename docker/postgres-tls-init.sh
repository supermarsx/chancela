#!/bin/sh
set -eu

tls_dir="${POSTGRES_TLS_DIR:-/tls}"
renew_before_seconds="${POSTGRES_TLS_RENEW_BEFORE_SECONDS:-2592000}"
server_uid="${POSTGRES_TLS_SERVER_UID:-70}"
server_gid="${POSTGRES_TLS_SERVER_GID:-70}"

mkdir -p "$tls_dir"

if [ -s "$tls_dir/ca.crt" ] \
  && [ -s "$tls_dir/server.crt" ] \
  && [ -s "$tls_dir/server.key" ] \
  && openssl x509 -in "$tls_dir/server.crt" -noout -checkend "$renew_before_seconds" >/dev/null 2>&1 \
  && openssl pkey -in "$tls_dir/server.key" -check >/dev/null 2>&1 \
  && openssl verify -CAfile "$tls_dir/ca.crt" "$tls_dir/server.crt" >/dev/null 2>&1; then
  echo "PostgreSQL TLS material is valid beyond the renewal window."
else
  work_dir="$(mktemp -d)"
  trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
  umask 077

  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -keyout "$work_dir/ca.key" \
    -out "$work_dir/ca.crt" \
    -subj "/CN=Chancela Compose PostgreSQL Root" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

  cat >"$work_dir/server.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
req_extensions = server_ext

[dn]
CN = postgres

[server_ext]
subjectAltName = DNS:postgres,DNS:localhost,IP:127.0.0.1
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF

  openssl req -new -newkey rsa:3072 -sha256 -nodes \
    -keyout "$work_dir/server.key" \
    -out "$work_dir/server.csr" \
    -config "$work_dir/server.cnf"
  openssl x509 -req -sha256 -days 397 \
    -in "$work_dir/server.csr" \
    -CA "$work_dir/ca.crt" \
    -CAkey "$work_dir/ca.key" \
    -CAcreateserial \
    -out "$work_dir/server.crt" \
    -extfile "$work_dir/server.cnf" \
    -extensions server_ext
  openssl verify -CAfile "$work_dir/ca.crt" "$work_dir/server.crt"

  cp "$work_dir/ca.crt" "$tls_dir/ca.crt.new"
  cp "$work_dir/server.crt" "$tls_dir/server.crt.new"
  cp "$work_dir/server.key" "$tls_dir/server.key.new"
  chmod 0644 "$tls_dir/ca.crt.new" "$tls_dir/server.crt.new"
  chmod 0600 "$tls_dir/server.key.new"
  chown "$server_uid:$server_gid" \
    "$tls_dir/ca.crt.new" "$tls_dir/server.crt.new" "$tls_dir/server.key.new"
  mv -f "$tls_dir/ca.crt.new" "$tls_dir/ca.crt"
  mv -f "$tls_dir/server.crt.new" "$tls_dir/server.crt"
  mv -f "$tls_dir/server.key.new" "$tls_dir/server.key"
  echo "Generated a new private CA and verify-full server certificate for PostgreSQL."
fi

chmod 0755 "$tls_dir"
chmod 0644 "$tls_dir/ca.crt" "$tls_dir/server.crt"
chmod 0600 "$tls_dir/server.key"
chown "$server_uid:$server_gid" \
  "$tls_dir/ca.crt" "$tls_dir/server.crt" "$tls_dir/server.key"
