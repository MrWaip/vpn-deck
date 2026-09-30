image := "ghcr.io/mrwaip/vpn-deck-builder"
tag := "latest"

# Show available recipes
default:
    @just --list

# Install JS dependencies
install:
    pnpm install

# Run unit tests (no binaries required)
test:
    PYTHONPATH=py_modules python3 test_unit.py
    PYTHONPATH=py_modules python3 test_simple.py
    python3 test_vpn_uri.py
    python3 test_network_watch.py

# Run smoke tests inside a Steam Deck OS container (holo-base)
test-smoke:
    bash infra/test-smoke.sh

# Build the builder Docker image
build-image:
    docker build -t {{ image }}:{{ tag }} -f infra/Dockerfile .

# Push the builder image to GHCR
push-image: build-image
    docker push {{ image }}:{{ tag }}

# Extract AmneziaWG binaries from Docker image to ./binaries/
build-binaries:
    bash infra/extract-binaries.sh

# Build plugin zip (copies binaries to bin/, packs via Decky CLI)
build-plugin:
    bash infra/build-plugin.sh

# Release (bump version, build, publish GitHub release)
release bump="patch":
    pnpm release:{{ bump }}
