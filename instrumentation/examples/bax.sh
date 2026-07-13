#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../build"
BUILD_OUT="${BUILD_DIR}/targets"
TARGETS_DIR="${SCRIPT_DIR}/targets"
OUTPUT_DIR="${SCRIPT_DIR}/outputs"

TARGETS="${SCRIPT_DIR}/target_names.conf"
if [ ! -f "$TARGETS" ]; then
    echo "ERROR: ${TARGETS} does not exist!"
    exit 1
fi

RESULT_FILE="${SCRIPT_DIR}/bax_result.out"

DYNAMORIO_DIR="/src/dynamorio/build_aarch64"
QEMU_AARCH64="/src/qemu/build/qemu-aarch64"

GHIDRA_ROOT="/opt/ghidra_10.3.2_PUBLIC"
GHIDRA_HEADLESS="${GHIDRA_ROOT}/support/analyzeHeadless"
METAMEM_PATH="${GHIDRA_ROOT}/Ghidra/Processors/JVM/ghidra_scripts/MetaMem.java"
REPAIR_SCRIPT="${GHIDRA_ROOT}/Ghidra/Features/Base/ghidra_scripts/RepairFuncDefinitionUsageScript.java"
CREATE_STRUCT_SCRIPT="${GHIDRA_ROOT}/Ghidra/Features/Decompiler/ghidra_scripts/CreateStructure.java"
FIX_ARRAY_SCRIPT="${GHIDRA_ROOT}/Ghidra/Features/Base/ghidra_scripts/FixArrayStructReferencesScript.java"

mkdir -p "$OUTPUT_DIR"
mkdir -p "$BUILD_OUT"

run_and_log() {
    local description="$1"
    local log_file="$2"
    shift 2

    echo "INFO ${description}: $*"
    echo "INFO ${description}: $*" >> "$log_file"

    "$@" 2>&1 | tee -a "$log_file"
    local rc=${PIPESTATUS[0]}

    echo "INFO ${description} result: retval=${rc}"
    echo "INFO ${description} result: retval=${rc}" >> "$log_file"

    return $rc
}

start=$(date +%s)
"${SCRIPT_DIR}/../build.sh" &> "${OUTPUT_DIR}/dmti_build.out"
build_rc=$?
end=$(date +%s)

if [ $build_rc -ne 0 ]; then
    echo "ERROR: DMTI build failed. See ${OUTPUT_DIR}/dmti_build.out"
    exit 1
fi

echo "Build time: $((end - start)) seconds"

TIME_NOW=$(date +"%x %T")
echo "Tests (${TIME_NOW}):" > "$RESULT_FILE"

start=$(date +%s)

while read -r name || [ -n "$name" ]; do
    [ -z "$name" ] && continue
    case "$name" in
        \#*) continue ;;
    esac

    TARGET="${BUILD_OUT}/${name}"
    TARGET_SRC="${TARGETS_DIR}/${name}.c"
    TARGET_META="${BUILD_OUT}/${name}.json"
    LOG_FILE="${OUTPUT_DIR}/${name}.out"

    if [ ! -f "$TARGET_SRC" ]; then
        echo "ERROR: ${TARGET_SRC} does not exist." | tee -a "$RESULT_FILE"
        continue
    fi

    : > "$LOG_FILE"
    echo "=== ${name} ==="
    echo "  ${name}" >> "$RESULT_FILE"

    if [ ! -f "$TARGET" ]; then
        run_and_log "build" "$LOG_FILE" \
            aarch64-linux-gnu-g++ -O0 -march=armv8.5-a+memtag "$TARGET_SRC" -o "$TARGET"
        compile_rc=$?
        if [ $compile_rc -ne 0 ]; then
            echo "    build        -> ✘ ERROR" | tee -a "$RESULT_FILE"
            echo "    normal       -> ✘ SKIPPED" | tee -a "$RESULT_FILE"
            echo "    instrumented -> ✘ SKIPPED" | tee -a "$RESULT_FILE"
            continue
        else
            echo "    build        -> ✔ OK" | tee -a "$RESULT_FILE"
        fi
    else
        echo "INFO build: skipped, target already exists: ${TARGET}" | tee -a "$LOG_FILE"
    fi

    run_and_log "normal execution" "$LOG_FILE" \
        "${QEMU_AARCH64}" -L /usr/aarch64-linux-gnu "$TARGET"
    normal_rc=$?
    if [ $normal_rc -eq 0 ]; then
        echo "    normal       -> ✔ OK" | tee -a "$RESULT_FILE"
    else
        echo "    normal       -> ✘ ERROR (retval=${normal_rc})" | tee -a "$RESULT_FILE"
    fi

    if [ ! -f "$TARGET_META" ]; then
        if [ -x "$GHIDRA_HEADLESS" ] && [ -f "$METAMEM_PATH" ]; then
            run_and_log "analysis" "$LOG_FILE" \
                "${GHIDRA_HEADLESS}" \
                "${TARGETS_DIR}" \
                BMST \
                -overwrite \
                -readOnly \
                -postScript "${REPAIR_SCRIPT}" \
                -postScript "${CREATE_STRUCT_SCRIPT}" \
                -postScript "${FIX_ARRAY_SCRIPT}" \
                -postScript "${METAMEM_PATH}" \
                -import "${TARGET}"
            ghidra_rc=$?
            if [ $ghidra_rc -ne 0 ]; then
                echo "    analysis     -> ✘ ERROR (retval=${ghidra_rc})" | tee -a "$RESULT_FILE"
                echo "    instrumented -> ✘ ERROR (ghidra analysis failed: retval=${ghidra_rc})" | tee -a "$RESULT_FILE"
                continue
            else
                echo "    analysis     -> ✔ OK" | tee -a "$RESULT_FILE"
            fi
        else
            echo "INFO analysis: ${TARGET_META} does not exist and Ghidra is not available in this container." | tee -a "$LOG_FILE"
            echo "    analysis     -> ✘ ERROR (Ghidra unavailable)" | tee -a "$RESULT_FILE"
            echo "    instrumented -> ✘ ERROR (missing ${TARGET_META}; Ghidra unavailable)" | tee -a "$RESULT_FILE"
            continue
        fi
    else
        echo "INFO analysis: skipped, metadata already exists: ${TARGET_META}" | tee -a "$LOG_FILE"
    fi

    run_and_log "instrumentation" "$LOG_FILE" \
        "${QEMU_AARCH64}" -L /usr/aarch64-linux-gnu \
        "${DYNAMORIO_DIR}/bin64/drrun" \
        -xarch_root /usr/aarch64-linux-gnu \
        -c "${BUILD_DIR}/bin/libdmti.so" "${TARGET_META}" \
        -- "$TARGET"
    inst_rc=$?

    if [ $inst_rc -eq 139 ]; then
        echo "    instrumented -> ✔ OK (SIGSEGV)" | tee -a "$RESULT_FILE"
    elif [ $inst_rc -eq 1 ]; then
        echo "    instrumented -> ✔ OK" | tee -a "$RESULT_FILE"
    elif [ $inst_rc -eq 134 ]; then
        echo "    instrumented -> ✔ OK (SIGABRT due to scudo)" | tee -a "$RESULT_FILE"
    elif [ $inst_rc -eq 255 ]; then
        echo "    instrumented -> ✔ OK (tool returned 255)" | tee -a "$RESULT_FILE"
    else
        echo "    instrumented -> ✘ ERROR (retval=${inst_rc})" | tee -a "$RESULT_FILE"
    fi

done < "$TARGETS"

end=$(date +%s)
echo "Execution time: $((end - start)) seconds" | tee -a "$RESULT_FILE"
echo "Wrote results to ${RESULT_FILE}"