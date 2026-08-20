#!/usr/bin/env bash
# Generates a self-signed dev certificate so the storage nodes and metadata
# service can serve over TLS locally. Not for production use - a real
# deployment would use certs from a trusted CA (or an internal one) with
# proper rotation.
set -euo pipefail

CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$CERT_DIR/dev-key.pem" \
  -out "$CERT_DIR/dev-cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "wrote $CERT_DIR/dev-cert.pem and $CERT_DIR/dev-key.pem"
echo "run a service with, e.g.:"
echo "  uvicorn metadata_service.app:app --ssl-keyfile $CERT_DIR/dev-key.pem --ssl-certfile $CERT_DIR/dev-cert.pem"
