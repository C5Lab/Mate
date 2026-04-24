#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IDF_DOCKER_IMAGE:-espressif/idf:release-v6.0}"
USE_DOCKER="${USE_DOCKER:-1}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
APP_DIR="${REPO_ROOT}"
CACHE_DIR="${IDF_CACHE_DIR:-${REPO_ROOT}/.espressif}"
BOARD="${BOARD:-xiao-c6}"
IDF_TARGET="${IDF_TARGET:-esp32c6}"
SDKCONFIG_DEFAULTS="${SDKCONFIG_DEFAULTS:-sdkconfig.defaults;sdkconfig.defaults.esp32c6}"
BUILD_DIR="${BUILD_DIR:-build-${BOARD}}"

usage() {
  cat <<'EOF'
Usage: container_build.sh [--no-docker]

Builds Mate firmware for a specific board using esp-idf release-v6.0.
Set BOARD, IDF_TARGET, SDKCONFIG_DEFAULTS, BUILD_DIR env vars before calling.

Options:
  --no-docker   Run idf.py directly (for GitHub Actions container job or host with esp-idf installed)
EOF
}

normalize_sdkconfig() {
  local cfg="${APP_DIR}/sdkconfig"
  local cfg_old="${APP_DIR}/sdkconfig.old"

  for f in "$cfg" "$cfg_old"; do
    [ -f "$f" ] || continue
    sed -i 's/\r$//' "$f"
  done
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-docker)
      USE_DOCKER=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

build_native() {
  cd "$APP_DIR"
  # Remove root sdkconfig so idf.py regenerates it from sdkconfig.defaults for the correct target
  rm -f sdkconfig sdkconfig.old
  normalize_sdkconfig
  export IDF_TARGET
  export SDKCONFIG_DEFAULTS
  if [ -f /opt/esp/idf/export.sh ]; then
    # shellcheck disable=SC1091
    . /opt/esp/idf/export.sh >/dev/null 2>&1
  fi
  idf.py set-target "${IDF_TARGET}"
  idf.py -B "${BUILD_DIR}" build
}

if [[ "$USE_DOCKER" == "0" || "$USE_DOCKER" == "false" ]]; then
  build_native
  exit 0
fi

mkdir -p "$CACHE_DIR"
normalize_sdkconfig

docker run --rm \
  --workdir /project \
  --env IDF_TARGET="${IDF_TARGET}" \
  --env SDKCONFIG_DEFAULTS="${SDKCONFIG_DEFAULTS}" \
  --env BUILD_DIR="${BUILD_DIR}" \
  --volume "${APP_DIR}:/project" \
  --volume "${CACHE_DIR}:/root/.espressif" \
  "$IMAGE" \
  bash -c '. /opt/esp/idf/export.sh >/dev/null 2>&1; rm -f sdkconfig sdkconfig.old; idf.py set-target "${IDF_TARGET}"; idf.py -B "${BUILD_DIR}" build'
