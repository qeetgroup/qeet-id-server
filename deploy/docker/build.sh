#!/usr/bin/env bash
# Build both qeet-id Docker images from the repo root.
# Usage: ./deploy/docker/build.sh <tag>
# Example: ./deploy/docker/build.sh dev
#          ./deploy/docker/build.sh v1.2.3

set -euo pipefail

TAG=${1:?Usage: $0 <tag>}
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "Building qeet-id:${TAG} from ${REPO_ROOT}"
docker build \
  --file "${REPO_ROOT}/Dockerfile" \
  --tag "ghcr.io/qeetgroup/qeet-id:${TAG}" \
  --build-arg VERSION="${TAG}" \
  --build-arg COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo none)" \
  --build-arg DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "${REPO_ROOT}"

echo "Building qeet-id-migrate:${TAG} from ${REPO_ROOT}"
docker build \
  --file "${REPO_ROOT}/Dockerfile.migrate" \
  --tag "ghcr.io/qeetgroup/qeet-id-migrate:${TAG}" \
  "${REPO_ROOT}"

echo ""
echo "Built:"
echo "  ghcr.io/qeetgroup/qeet-id:${TAG}"
echo "  ghcr.io/qeetgroup/qeet-id-migrate:${TAG}"
