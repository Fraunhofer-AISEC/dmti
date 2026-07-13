#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

DYNAMORIO_ROOT="/src/dynamorio"
DYNAMORIO_BUILD="${DYNAMORIO_ROOT}/build_aarch64"
TOOLCHAIN_FILE="${DYNAMORIO_ROOT}/make/toolchain-aarch64.cmake"
QEMU_AARCH64="/src/qemu/build/qemu-aarch64"

mkdir -p "${BUILD_DIR}"

cd "${BUILD_DIR}"
export CXXFLAGS="-isystem /usr/local/include"

cmake -G Ninja \
  -DDynamoRIO_DIR="${DYNAMORIO_BUILD}/cmake" \
  -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
  ..

ninja dmti

cd "${REPO_ROOT}"

echo "Execute clients native with:"
echo "  ${DYNAMORIO_BUILD}/bin64/drrun -c ${BUILD_DIR}/bin/libdmti.so <IN_FILE_NAME> -- <TARGET>"
echo "Executing in qemu-user"
echo "  ${QEMU_AARCH64} -L /usr/aarch64-linux-gnu ${DYNAMORIO_BUILD}/bin64/drrun -xarch_root /usr/aarch64-linux-gnu -c ${BUILD_DIR}/bin/libdmti.so <IN_FILE_NAME> -- <TARGET>"