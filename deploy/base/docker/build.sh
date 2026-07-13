#!/usr/bin/env bash
# Build both qeet-id Docker images. The build context is the repo ROOT (the Go
# module + platform/database/migrations are needed at build time); the
# Dockerfiles live under deploy/base/docker/.
# Usage: ./deploy/base/docker/build.sh <tag>
# Example: ./deploy/base/docker/build.sh dev
#          ./deploy/base/docker/build.sh v1.2.3

set -euo pipefail

TAG=${1:?Usage: $0 <tag>}
# script is at deploy/base/docker/ → repo root is three levels up.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
DOCKERDIR="${REPO_ROOT}/deploy/base/docker"

echo "Building qeet-id:${TAG} from ${REPO_ROOT}"
docker build \
  --file "${DOCKERDIR}/Dockerfile" \
  --tag "ghcr.io/qeetgroup/qeet-id:${TAG}" \
  --build-arg VERSION="${TAG}" \
  --build-arg COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo none)" \
  --build-arg DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "${REPO_ROOT}"

echo "Building qeet-id-migrate:${TAG} from ${REPO_ROOT}"
docker build \
  --file "${DOCKERDIR}/Dockerfile.migrate" \
  --tag "ghcr.io/qeetgroup/qeet-id-migrate:${TAG}" \
  "${REPO_ROOT}"

echo ""
echo "Built:"
echo "  ghcr.io/qeetgroup/qeet-id:${TAG}"
echo "  ghcr.io/qeetgroup/qeet-id-migrate:${TAG}"
