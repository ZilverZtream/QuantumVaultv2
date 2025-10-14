#!/bin/bash
set -euo pipefail

# TSK062_FUSE_Filesystem_Integration_Linux smoke test for FUSE mount lifecycle

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
BIN_DIR="${ROOT_DIR}/build/bin"
CLI="${BIN_DIR}/qv"

if [[ ! -x "${CLI}" ]]; then
  echo "qv binary not found at ${CLI}. Build the project first." >&2
  exit 1
fi

TMP_CONTAINER="/tmp/test.qv"
TMP_MOUNT="/tmp/test_mount"
rm -f "${TMP_CONTAINER}"
mkdir -p "${TMP_MOUNT}"

# Create volume
"${CLI}" create "${TMP_CONTAINER}" <<'PASS'
password123
password123
PASS

# Launch mount in background
"${CLI}" mount "${TMP_CONTAINER}" "${TMP_MOUNT}" >/tmp/qv_mount.log 2>&1 &
MOUNT_PID=$!

sleep 2

echo "Hello World" > "${TMP_MOUNT}/test.txt"
if ! grep -q "Hello World" "${TMP_MOUNT}/test.txt"; then
  echo "Failed to verify file contents" >&2
  kill "${MOUNT_PID}" || true
  wait "${MOUNT_PID}" || true
  exit 1
fi

mkdir -p "${TMP_MOUNT}/subdir"
echo "Nested" > "${TMP_MOUNT}/subdir/file.txt"
ls -la "${TMP_MOUNT}" >/dev/null

kill "${MOUNT_PID}" || true
wait "${MOUNT_PID}" || true

echo "FUSE mount test passed!"
