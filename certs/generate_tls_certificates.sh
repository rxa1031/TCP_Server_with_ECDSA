#!/usr/bin/env bash
set -euo pipefail

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

# Cleanup
rm -f server-key.pem server-cert.pem server.csr \
      ca-key.pem ca-cert.pem ca-crl.pem \
      ca-cert.srl ca-index.txt ca-serial ca-crlnumber

OPENSSL=$(command -v openssl)

# ---------------------------------------------------------
# CA
# ---------------------------------------------------------
echo "[1] Creating CA key"
$OPENSSL genrsa -out ca-key.pem 4096 >/dev/null

echo "[2] Creating CA certificate"
$OPENSSL req -x509 -new -nodes \
    -key ca-key.pem \
    -sha256 -days "$DAYS" \
    -subj "/CN=Test-CA" \
    -out ca-cert.pem

# ---------------------------------------------------------
# Server cert
# ---------------------------------------------------------
echo "[3] Creating server key"
$OPENSSL genrsa -out server-key.pem 4096 >/dev/null

TMP_CFG=$(mktemp)

cat > "$TMP_CFG" <<EOF
[ req ]
prompt = no
distinguished_name = dn
req_extensions = ext

[ dn ]
CN = ${HOST}:${PORT}

[ ext ]
subjectAltName = @san

[ san ]
DNS.1 = ${HOST}
EOF

echo "[4] Creating server CSR"
$OPENSSL req -new \
    -key server-key.pem \
    -out server.csr \
    -config "$TMP_CFG"

echo "Signing server certificate"
$OPENSSL x509 -req \
    -in server.csr \
    -CA ca-cert.pem \
    -CAkey ca-key.pem \
    -CAcreateserial \
    -out server-cert.pem \
    -days "$DAYS" \
    -sha256 \
    -extfile "$TMP_CFG" \
    -extensions ext

rm -f "$TMP_CFG" server.csr ca-cert.srl

# ---------------------------------------------------------
# CRL
# ---------------------------------------------------------
echo "Preparing CA database"
echo -n > ca-index.txt
echo 01 > ca-serial
echo 01 > ca-crlnumber

echo "Generating CRL"
$OPENSSL ca -gencrl \
    -keyfile ca-key.pem -cert ca-cert.pem \
    -out ca-crl.pem \
    -crldays 30 \
    -config <(
        cat <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
database = ca-index.txt
new_certs_dir     = .
serial = ca-serial
crlnumber = ca-crlnumber
certificate       = ca-cert.pem
private_key       = ca-key.pem
default_md        = sha256
EOF
    )

echo
echo "Certificates generated:"
echo "  server-key.pem"
echo "  server-cert.pem"
echo "  ca-cert.pem"
echo "  ca-crl.pem"
echo
