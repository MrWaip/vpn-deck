#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="vpn-deck-builder:local"

docker build -f "$SCRIPT_DIR/Dockerfile" -t "$IMAGE" "$SCRIPT_DIR/.."
docker run --rm -v "./bin:/out" "$IMAGE" sh -c "cp /binaries/amneziawg-go /binaries/awg /binaries/sing-box /out/"

echo "==> Binaries extracted to ./bin/"
ls -lh ./bin/
