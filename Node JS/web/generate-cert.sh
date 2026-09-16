#!/bin/sh
# Runs automatically on container start (nginx's official image executes every
# executable *.sh in /docker-entrypoint.d/ before starting nginx). Generates a
# self-signed cert for the client-facing TLS listener on first boot.
#
# Training-only: a real deployment terminates TLS at a load balancer or edge
# proxy with a CA-issued cert (e.g. via ACME/Let's Encrypt), not one minted at
# container startup with no external validation.
set -e

CERT_DIR=/certs
CERT_FILE="$CERT_DIR/cert.pem"
KEY_FILE="$CERT_DIR/key.pem"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  mkdir -p "$CERT_DIR"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost"
fi
