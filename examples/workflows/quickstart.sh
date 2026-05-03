#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-coinbase/<IN_SCOPE_REPO_1>}"
REPO_PATH="${2:-.}"
CONFIG="${3:-openclaw.localstub.yaml}"

python3 -m openclaw \
  --config "${CONFIG}" \
  --target "${TARGET}" \
  --repo-path "${REPO_PATH}" \
  --print-json
