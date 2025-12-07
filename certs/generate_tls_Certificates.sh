#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Usage / Help
# =============================================================================
show_help() {
    echo ""
    echo "Usage: $0 [MODE]"
    echo ""
    echo "MODE options:"
    echo "  DEV     - Host: localhost  | Port: 8443"
    echo "  BENCH   - Host: 127.0.0.1  | Port: 443"
    echo "  PROD    - Host: secure.lab.linux | Port: 443"
    echo ""
    echo "Examples:"
    echo "  $0              (default: DEV)"
    echo "  $0 DEV"
    echo "  $0 BENCH"
    echo "  $0 PROD"
    echo "  $0 --help"
    echo ""
}

# Recognize help flags
if [[ "${1:-}" =~ ^(--help|-h)$ ]]; then
    show_help
    exit 0
fi

MODE="${1:-DEV}"   # Default MODE = DEV if not provided

# =============================================================================
# Host + Port Selection
# =============================================================================
case "$MODE" in
    PROD)
        HOST="secure.lab.linux"
        PORT="443"
        ;;
    BENCH)
        HOST="127.0.0.1"
        PORT="443"
        ;;
    DEV|*)
        HOST="localhost"
        PORT="8443"
        MODE="DEV"  # Normalize in case of invalid input
        ;;
esac

echo "MODE      = $MODE"
echo "HOSTNAME  = $HOST"
echo "TLS PORT  = $PORT"

# Always generate into script directory
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
echo "Using certificate directory: $SCRIPT_DIR"


# =============================================================================
# Root CA (ECDSA)
# =============================================================================
echo "==> Generating Root CA key"
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem

openssl req -x509 -new \
    -key ca-key.pem \
    -sha256 -days 1825 \
    -subj "/CN=Security-Authority-Root-CA" \
    -out ca-cert.pem


# =============================================================================
# Server certificate
# =============================================================================
echo "==> Generating Server key"
openssl ecparam -name prime256v1 -genkey -noout -out server-key.pem

cat > server-san.ext <<EOF
subjectAltName=DNS:${HOST},IP:127.0.0.1
extendedKeyUsage = serverAuth
keyUsage = digitalSignature, keyEncipherment, keyAgreement
EOF

echo "==> Server CSR"
openssl req -new \
    -key server-key.pem \
    -out server.csr \
    -subj "/CN=${HOST}"

echo "==> Signing Server certificate"
openssl x509 -req -in server.csr \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -sha256 -days 825 \
    -extfile server-san.ext \
    -out server-cert.pem

rm -f server.csr server-san.ext


# =============================================================================
# Client certificate
# =============================================================================
echo "==> Generating Client key"
openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem

cat > client-san.ext <<EOF
subjectAltName=DNS:client.${HOST},IP:127.0.0.1
extendedKeyUsage = clientAuth
keyUsage = digitalSignature, keyAgreement
EOF

echo "==> Client CSR"
openssl req -new \
    -key client-key.pem \
    -out client.csr \
    -subj "/CN=client.${HOST}"

echo "==> Signing Client certificate"
openssl x509 -req -in client.csr \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -sha256 -days 825 \
    -extfile client-san.ext \
    -out client-cert.pem

rm -f client.csr client-san.ext


# =============================================================================
# CRL (for hardened modes)
# =============================================================================
[[ -f index.txt ]] || touch index.txt
echo "01" > serial

cat > openssl-ca.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = .
database          = index.txt
new_certs_dir     = .
certificate       = ca-cert.pem
private_key       = ca-key.pem
serial            = serial
default_md        = sha256
policy            = policy_any

[ policy_any ]
commonName        = supplied
EOF

openssl ca -config openssl-ca.cnf -batch -gencrl \
    -out ca-crl.pem \
    -crldays 30

# =============================================================================

echo "=== CERTIFICATES GENERATED SUCCESSFULLY ==="
echo "MODE       : ${MODE}"
echo "HOSTNAME   : ${HOST}"
echo "TLS PORT   : ${PORT}"
echo "-------------------------------------------"
ls -1 *.pem
