#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 && $# -ne 4 ]]; then
  echo "usage: scripts/validate-bitwarden-importer.sh BITWARDEN_CLIENTS_DIR BITWARDEN_JSON [--passkeys-only-count N]" >&2
  exit 2
fi

bitwarden_dir=$1
bitwarden_json=$2
expected_commit=2be53da5b7ec6f7608f2fc28a6f63d70d89ec53f
bridge_mode=fixture
expected_count=1

if [[ $# -eq 4 ]]; then
  if [[ $3 != --passkeys-only-count || ! $4 =~ ^[1-9][0-9]*$ ]]; then
    echo "usage: scripts/validate-bitwarden-importer.sh BITWARDEN_CLIENTS_DIR BITWARDEN_JSON [--passkeys-only-count N]" >&2
    exit 2
  fi
  bridge_mode=passkeys_only
  expected_count=$4
fi

if [[ $(git -C "$bitwarden_dir" rev-parse HEAD) != "$expected_commit" ]]; then
  echo "validation requires the pinned Bitwarden clients commit" >&2
  exit 1
fi

if [[ ! -f "$bitwarden_dir/node_modules/jest/bin/jest.js" ]]; then
  echo "install the pinned Bitwarden development dependencies first" >&2
  exit 1
fi

temporary_test="$bitwarden_dir/libs/importer/src/importers/bitwarden/bitwarden-json-importer.bridge.spec.ts"
if [[ -e "$temporary_test" ]]; then
  echo "temporary Bitwarden test path already exists" >&2
  exit 1
fi

cleanup() {
  rm -f -- "$temporary_test"
}
trap cleanup EXIT
cp "$(dirname "$0")/../tests/bitwarden-json-importer.bridge.spec.ts" "$temporary_test"

if BITWARDEN_BRIDGE_JSON=$(realpath "$bitwarden_json") \
  BITWARDEN_BRIDGE_MODE=$bridge_mode \
  BITWARDEN_BRIDGE_EXPECTED_COUNT=$expected_count \
  node "$bitwarden_dir/node_modules/jest/bin/jest.js" \
    --config "$bitwarden_dir/libs/importer/jest.config.js" \
    "$temporary_test" \
    --runInBand >/dev/null 2>&1; then
  echo "pinned Bitwarden importer bridge passed"
else
  echo "pinned Bitwarden importer bridge failed without displaying vault contents" >&2
  exit 1
fi
