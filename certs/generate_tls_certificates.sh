#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# generate_tls_certificates.sh
# - Generates ECDSA (prime256v1) CA, server and client certificates suitable
#   for use with ECDHE-ECDSA cipher suites and strict mTLS.
# - Respects MODE (DEV | PROD | BENCH) and uses HOST/PORT from Makefile logic.
# - Writes files into ./certs/ (script must be executed from repo root or will
#   create certs/ under current dir).
###############################################################################

CERT_DIR="certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

MODE="${1:-}"

if [[ -z "$MODE" ]]; then
    echo "Usage: $0 DEV | PROD | BENCH"
    exit 1
fi

case "$MODE" in
    DEV)
        HOST="localhost"
        PORT="8443"
        DAYS=30
        ;;
    PROD)
        HOST="secure.lab.linux"
        PORT="443"
        DAYS=730
        ;;
    BENCH)
        HOST="127.0.0.1"
        PORT="443"
        DAYS=730
        ;;
    *)
        echo "ERROR: Mode must be DEV, PROD, or BENCH"
        exit 1
        ;;
esac

echo "Generating certificates for $MODE"
echo "Host: $HOST"
echo "Port: $PORT"
echo

# Cleanup old files (idempotent)
rm -f server-key.pem server-cert.pem server.csr \
      ca-key.pem ca-cert.pem ca-crl.pem ca-cert.srl \
      client-key.pem client-cert.pem client.csr \
      ca-index.txt ca-serial ca-crlnumber

OPENSSL=$(command -v openssl)
if [[ -z "$OPENSSL" ]]; then
    echo "ERROR: openssl CLI not found in PATH"
    exit 2
fi

# Temporary files cleanup on exit
TMP_TO_CLEAN=()
cleanup() {
  for f in "${TMP_TO_CLEAN[@]}"; do
    [[ -f "$f" ]] && rm -f "$f"
  done
}
trap cleanup EXIT

# ============================================================
# CA (ECDSA, prime256v1) — create CA key and CA certificate with CA extensions
# ============================================================
echo "[1] Creating CA key"
$OPENSSL ecparam -name prime256v1 -genkey -out ca-key.pem >/dev/null
chmod 600 ca-key.pem

CA_CFG=$(mktemp)
TMP_TO_CLEAN+=("$CA_CFG")

cat > "$CA_CFG" <<EOF
[ req ]
distinguished_name = dn
x509_extensions = ca_ext
prompt = no

[ dn ]
CN = Test-CA

[ ca_ext ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

echo "[2] Creating CA certificate"
$OPENSSL req -x509 -new -key ca-key.pem -sha256 \
    -days "$DAYS" -config "$CA_CFG" -out ca-cert.pem

# ============================================================
# Server certificate (ECDSA)
# ============================================================
echo "[3] Creating server key"
$OPENSSL ecparam -name prime256v1 -genkey -out server-key.pem >/dev/null
chmod 600 server-key.pem

TMP_CFG=$(mktemp)
TMP_TO_CLEAN+=("$TMP_CFG")

cat > "$TMP_CFG" <<EOF
[ req ]
prompt = no
distinguished_name = dn
req_extensions = ext

[ dn ]
CN = ${HOST}:${PORT}

[ ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @san

[ san ]
DNS.1 = ${HOST}
EOF

# include IP SAN for DEV only (keeps PROD/BENCH strictly matching Makefile host)
if [[ "$MODE" = "DEV" ]]; then
  printf "IP.1 = 127.0.0.1\n" >> "$TMP_CFG"
fi

echo "[4] Creating server CSR"
$OPENSSL req -new -key server-key.pem -out server.csr -config "$TMP_CFG"

echo "Signing server certificate"
$OPENSSL x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out server-cert.pem -days "$DAYS" -sha256 \
    -extfile "$TMP_CFG" -extensions ext

rm -f server.csr

# ============================================================
# CLIENT CERTIFICATE (required for mTLS)
# ============================================================
echo "[5] Creating client key"
$OPENSSL ecparam -name prime256v1 -genkey -out client-key.pem >/dev/null
chmod 600 client-key.pem

CLIENT_CFG=$(mktemp)
TMP_TO_CLEAN+=("$CLIENT_CFG")

cat > "$CLIENT_CFG" <<EOF
[ req ]
prompt = no
distinguished_name = dn
req_extensions = ext

[ dn ]
CN = client.${HOST}

[ ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyAgreement
extendedKeyUsage = clientAuth
subjectAltName = @san

[ san ]
DNS.1 = client.${HOST}
EOF

# include IP SAN for DEV only
if [[ "$MODE" = "DEV" ]]; then
  printf "IP.1 = 127.0.0.1\n" >> "$CLIENT_CFG"
fi

echo "[6] Creating client CSR"
$OPENSSL req -new -key client-key.pem -out client.csr -config "$CLIENT_CFG"

echo "Signing client certificate"
$OPENSSL x509 -req -in client.csr -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out client-cert.pem -days "$DAYS" -sha256 \
    -extfile "$CLIENT_CFG" -extensions ext

rm -f client.csr

# ============================================================
# CRL
# ============================================================
echo "Preparing CA database"
: > ca-index.txt
echo 01 > ca-serial
echo 01 > ca-crlnumber

echo "Generating CRL"
$OPENSSL ca -gencrl -keyfile ca-key.pem -cert ca-cert.pem \
    -out ca-crl.pem -crldays 30 -config <(
cat <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
database = ca-index.txt
new_certs_dir = .
serial = ca-serial
crlnumber = ca-crlnumber
certificate = ca-cert.pem
private_key = ca-key.pem
default_md = sha256
policy = policy_any

[ policy_any ]
commonName = supplied
EOF
)

# ============================================================
# Basic validations
# ============================================================
# Ensure files exist and certificate CN matches expected value for server
if [[ ! -f server-cert.pem || ! -f server-key.pem || ! -f ca-cert.pem || ! -f client-cert.pem || ! -f client-key.pem || ! -f ca-crl.pem ]]; then
  echo "ERROR: One or more expected PEM files missing"
  ls -1
  exit 3
fi

server_cn=$($OPENSSL x509 -in server-cert.pem -noout -subject | sed -E 's/.*CN *= *([^,\/]+).*/\1/')
if [[ "$server_cn" != "${HOST}:${PORT}" ]]; then
  echo "ERROR: server CN mismatch: found='$server_cn' expected='${HOST}:${PORT}'"
  exit 4
fi

# Quick cert inspection (non-fatal) — prints issuer for human confirmation
echo
echo "Certificates generated:"
echo "  server-key.pem"
echo "  server-cert.pem (CN=$server_cn)"
echo "  client-key.pem"
echo "  client-cert.pem"
echo "  ca-cert.pem"
echo "  ca-crl.pem"
echo "Done."

exit 0
