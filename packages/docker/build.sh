#!/usr/bin/env bash
# Build the Argus Docker image from any directory.
# Usage: ./packages/docker/build.sh [extra docker build args...]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${ARGUS_IMAGE:-argus-scan}"
PLATFORM="${ARGUS_PLATFORM:-linux/arm64}"

cd "$ROOT"

echo "Building ${IMAGE} from ${ROOT} (platform: ${PLATFORM})"

docker build \
  --platform "${PLATFORM}" \
  -f packages/docker/Dockerfile \
  -t "${IMAGE}" \
  "$@" \
  .

echo "Done. Test with: docker run --rm ${IMAGE} tools"
