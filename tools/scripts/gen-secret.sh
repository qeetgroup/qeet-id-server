#!/usr/bin/env bash
# Generate a random base64-encoded secret value.
# Usage: ./gen-secret.sh [bytes]   (default: 32 bytes)
set -euo pipefail

BYTES="${1:-32}"
openssl rand -base64 "$BYTES"
