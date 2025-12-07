#!/usr/bin/env bash
#
# Generates all certificate/key/CRL artifacts required by TCP_Server.c
# Based strictly on build-policy docs inside server source file.
#

#!/usr/bin/env bash
set -euo pipefail

# Always operate inside the script directory (certs/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "Using cert directory: $SCRIPT_DIR"

# ---------------------------------------------------------------------------
# Root CA (highly sensitive — NEVER ship private key)
# ---------------------------------------------------------------------------

if [[ ! -f ca-key.pem ]]; then
    echo "==> Generating Root CA key"
    openssl genpkey -algorithm RSA \
        -pkeyopt rsa_keygen_bits:4096 \
        -out ca-key.pem
    chmod 600 ca-key.pem
else
    echo "--> Root CA key already exists (skipping)"
fi

if [[ ! -f ca-cert.pem ]]; then
    echo "==> Generating Root CA certificate"
    openssl req -x509 -new -nodes \
        -key ca-key.pem \
        -sha256 -days 1825 \
        -subj "/CN=Security-Authority-Root-CA" \
        -out ca-cert.pem
else
    echo "--> Root CA certificate already exists (skipping)"
fi

# ---------------------------------------------------------------------------
# Server certificate — ALWAYS required
# ---------------------------------------------------------------------------

echo "==> Generating Server key"
openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out server-key.pem

cat > server-san.ext <<EOF
subjectAltName=DNS:secure.lab.linux,IP:127.0.0.1
EOF

echo "==> Generating Server CSR"
openssl req -new \
    -key server-key.pem \
    -out server.csr \
    -subj "/CN=secure.lab.linux"

echo "==> Signing Server certificate"
openssl x509 -req -in server.csr \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -sha256 -days 825 \
    -extfile server-san.ext \
    -out server-cert.pem

rm -f server.csr server-san.ext

# ---------------------------------------------------------------------------
# Client certificate — required only when mTLS enabled (default in PROD/BENCH)
# ---------------------------------------------------------------------------

echo "==> Generating Client key"
openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out client-key.pem

echo "==> Generating Client CSR"
openssl req -new \
    -key client-key.pem \
    -out client.csr \
    -subj "/CN=Secure-Client"

echo "==> Signing Client certificate"
openssl x509 -req -in client.csr \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
    -sha256 -days 825 \
    -out client-cert.pem

rm -f client.csr

# ---------------------------------------------------------------------------
# CRL — required in SECURITY_LEVEL >= 2 builds (PROD/BENCH)
# ---------------------------------------------------------------------------

echo "==> Preparing CRL DB"
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

echo "==> Generating CRL"
openssl ca -config openssl-ca.cnf -batch -gencrl \
    -out ca-crl.pem \
    -crldays 30


echo
echo "================ DONE ================"
echo "Generated artifacts:"
ls -1 *.pem *.srl 2>/dev/null || true
echo
echo "CA KEY IS SENSITIVE — MOVE OFF MACHINE FOR REAL PROD!"
