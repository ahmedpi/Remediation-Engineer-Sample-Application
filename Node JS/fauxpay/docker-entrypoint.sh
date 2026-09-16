#!/bin/sh
# Generates a self-signed cert for FauxPay's TLS listener on first boot, into a
# volume shared with the services that must trust it (nginx's /fauxpay/ relay
# and the api service's outbound client). Training-only: a real processor
# terminates TLS with a CA-issued cert, and we'd never generate one at
# container startup.
set -e

CERT_DIR="${FAUXPAY_TLS_DIR:-/certs}"
CERT_FILE="${FAUXPAY_TLS_CERT:-$CERT_DIR/cert.pem}"
KEY_FILE="${FAUXPAY_TLS_KEY:-$CERT_DIR/key.pem}"

if [ ! -f "$CERT_FILE" ] || [ ! -f "$KEY_FILE" ]; then
  mkdir -p "$CERT_DIR"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days 365 \
    -subj "/CN=fauxpay" \
    -addext "subjectAltName=DNS:fauxpay"
fi

exec "$@"
