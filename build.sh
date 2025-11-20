#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ASTATION_ROOT_DEFAULT="$(cd "${ROOT_DIR}/../Astation" 2>/dev/null && pwd || true)"
if [[ -z "${ASTATION_ROOT_DEFAULT}" ]]; then
    echo "❌ Could not locate Astation project at ../Astation." >&2
    echo "   Set ASTATION_ROOT environment variable to the Astation repository path." >&2
    exit 1
fi
ASTATION_ROOT="${ASTATION_ROOT:-${ASTATION_ROOT_DEFAULT}}"
if [[ ! -d "${ASTATION_ROOT}" ]]; then
    echo "❌ ASTATION_ROOT directory does not exist: ${ASTATION_ROOT}" >&2
    exit 1
fi
DOWNLOAD_DIR="${ROOT_DIR}/.downloads"
ASTATION_THIRD_PARTY_DIR="${ASTATION_ROOT}/third_party"
ATEM_THIRD_PARTY_DIR="${ROOT_DIR}/native/third_party"
AGORA_RTC_MAC_URL="https://download.agora.io/sdk/release/Agora_Native_SDK_for_Mac_v4.6.0_FULL.zip"
AGORA_RTM_MAC_URL="https://download.agora.io/rtm2/release/Agora_RTM_OC_SDK_v2.2.4.zip"
AGORA_RTM_LINUX_URL="https://download.agora.io/rtm2/release/Agora_RTM_C%2B%2B_SDK_for_Linux_v2.2.4.zip"
ASTATION_RTC_MAC_DIR="${ASTATION_THIRD_PARTY_DIR}/agora/rtc_mac"
ASTATION_RTM_MAC_DIR="${ASTATION_THIRD_PARTY_DIR}/agora/rtm_mac"
ATEM_RTM_LINUX_DIR="${ATEM_THIRD_PARTY_DIR}/agora/rtm_linux"

usage() {
    cat <<'EOF'
Usage: ./build.sh <command>

Available commands:
  deps     Install prerequisites, download Agora SDKs, and arrange directory structure
  build    Compile a target product for a specific OS after dependencies are prepared
           Usage: ./build.sh build <product> <os>
             • product: astation | atem
             • os: mac (for astation) | linux (for atem)
  run      Kill existing Astation/Atem processes, launch Astation (if available), then launch Atem
  help     Show this message

Environment:
  ASTATION_ROOT  Override path to the Astation project (defaults to ../Astation relative to this script)
EOF
}

require_command() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "❌ Required command '${cmd}' not found on PATH." >&2
        exit 1
    fi
}

install_dependencies() {
    echo "🔍 Checking required tools..."
    for cmd in curl unzip cmake cargo; do
        require_command "${cmd}"
    done
    echo "✅ Required tools detected."
}

create_dirs() {
    echo "📁 Preparing directory structure..."
    mkdir -p "${DOWNLOAD_DIR}"
    mkdir -p "${ASTATION_THIRD_PARTY_DIR}"
    mkdir -p "${ASTATION_RTC_MAC_DIR}"
    mkdir -p "${ASTATION_RTM_MAC_DIR}"
    mkdir -p "${ATEM_THIRD_PARTY_DIR}"
    mkdir -p "${ATEM_RTM_LINUX_DIR}"
    mkdir -p "${ASTATION_ROOT}/build"
    mkdir -p "${ASTATION_ROOT}/output"
    echo "✅ Directories ready."
}

download_and_extract() {
    local url="$1"
    local dest_dir="$2"
    local filename
    filename="${DOWNLOAD_DIR}/$(basename "${url}")"

    echo "⬇️  Downloading ${url}"
    if [[ ! -f "${filename}" ]]; then
        curl -L --progress-bar -o "${filename}" "${url}"
    else
        echo "   • Using cached archive ${filename}"
    fi

    echo "📦 Extracting to ${dest_dir}"
    rm -rf "${dest_dir}"
    mkdir -p "${dest_dir}"

    local temp_dir
    temp_dir="$(mktemp -d)"
    unzip -q "${filename}" -d "${temp_dir}"

    shopt -s dotglob nullglob
    local contents=("${temp_dir}"/*)
    if (( ${#contents[@]} == 1 )) && [[ -d "${contents[0]}" ]]; then
        mv "${contents[0]}"/* "${dest_dir}/"
    else
        mv "${temp_dir}"/* "${dest_dir}/"
    fi
    shopt -u dotglob nullglob

    rm -rf "${temp_dir}"
    echo "✅ Extracted ${url} -> ${dest_dir}"
}

prepare_agora_sdks() {
    download_and_extract "${AGORA_RTC_MAC_URL}" "${ASTATION_RTC_MAC_DIR}"
    download_and_extract "${AGORA_RTM_MAC_URL}" "${ASTATION_RTM_MAC_DIR}"
    download_and_extract "${AGORA_RTM_LINUX_URL}" "${ATEM_RTM_LINUX_DIR}"
}

build_astation() {
    echo "🏗️  Building Astation core..."
    cmake -S "${ASTATION_ROOT}" -B "${ASTATION_ROOT}/build" -DBUILD_TESTING=ON
    cmake --build "${ASTATION_ROOT}/build" --config Release
    echo "✅ Astation core build complete."
}

build_atem() {
    echo "🔨 Building Atem..."
    cargo build --release
    echo "✅ Atem build complete."
}

kill_processes() {
    local process_name="$1"
    if pgrep -f "${process_name}" >/dev/null 2>&1; then
        echo "🔪 Killing running ${process_name} processes..."
        pkill -f "${process_name}" || true
    fi
}

launch_astation() {
    local candidate
    candidate=""
    if [[ -x "${ASTATION_ROOT}/build/astation_core_tests" ]]; then
        candidate="${ASTATION_ROOT}/build/astation_core_tests"
    fi

    if [[ -n "${candidate}" ]]; then
        echo "🚀 Launching Astation placeholder: ${candidate}"
        "${candidate}" &
    else
        echo "⚠️ No Astation executable found. Please integrate the macOS host app before running."
    fi
}

launch_atem() {
    local atem_bin="${ROOT_DIR}/target/release/atem"
    if [[ ! -x "${atem_bin}" ]]; then
        echo "⚠️ Atem binary not built at ${atem_bin}. Run './build.sh build' first."
        exit 1
    fi
    echo "🚀 Launching Atem..."
    "${atem_bin}"
}

cmd_deps() {
    install_dependencies
    create_dirs
    prepare_agora_sdks
    echo "✅ Dependencies installed and SDKs prepared."
}

cmd_build() {
    local product="${1:-}"
    local os="${2:-}"

    if [[ -z "${product}" || -z "${os}" ]]; then
        echo "❌ Missing arguments for build command."
        echo "   Usage: ./build.sh build <product> <os>"
        echo "   Example: ./build.sh build atem linux"
        exit 1
    fi

    case "${product}" in
        astation)
            if [[ "${os}" != "mac" ]]; then
                echo "❌ Astation can only be built for mac (received '${os}')." >&2
                exit 1
            fi
            build_astation
            ;;
        atem)
            if [[ "${os}" != "linux" ]]; then
                echo "❌ Atem can only be built for linux (received '${os}')." >&2
                exit 1
            fi
            build_atem
            ;;
        *)
            echo "❌ Unknown product '${product}'. Expected 'astation' or 'atem'." >&2
            exit 1
            ;;
    esac

    echo "✅ Build finished for ${product} (${os})."
}

cmd_run() {
    kill_processes "Astation"
    kill_processes "atem"
    launch_astation
    sleep 1
    launch_atem
}

main() {
    local cmd="${1:-help}"
    case "${cmd}" in
        deps)
            cmd_deps
            ;;
        build)
            cmd_build "${2:-}" "${3:-}"
            ;;
        run)
            cmd_run
            ;;
        help|--help|-h)
            usage
            ;;
        *)
            echo "❌ Unknown command: ${cmd}" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
