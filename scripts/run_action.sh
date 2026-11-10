#!/usr/bin/env bash
# Composite-action execution and exit policy. Inputs arrive only through env.
set -uo pipefail

MODE="${PRUFGATE_EXECUTION:-auto}"
PROFILE="${PRUFGATE_PROFILE:-battery}"
EXIT_CODE=2

finish() {
  local code="$1" verdict scan_status=error
  if [ "${code}" -eq 0 ] || [ "${code}" -eq 1 ]; then
    if ! IFS= read -r scan_status < "${GITHUB_WORKSPACE}/reports/prufgate-result.status"; then
      echo '::error::The scanner did not produce its versioned scan status. Use an image built from the same PrufGate version.' >&2
      code=2
      scan_status=error
    fi
  elif [ -f "${GITHUB_WORKSPACE}/reports/prufgate-result.status" ]; then
    IFS= read -r scan_status < "${GITHUB_WORKSPACE}/reports/prufgate-result.status" || scan_status=error
  fi
  case "${code}:${scan_status}" in
    0:clean|0:findings|1:findings|2:incomplete|2:error) ;;
    *) code=2; scan_status=error ;;
  esac
  case "${code}" in
    0) verdict=PASSED ;;
    1) verdict=FAILED ;;
    *) code=2; verdict=ERROR ;;
  esac
  {
    echo "sarif_path=${GITHUB_WORKSPACE}/reports/prufgate.sarif"
    echo "markdown_path=${GITHUB_WORKSPACE}/reports/prufgate-review.md"
    echo "exit_code=${code}"
    echo "verdict=${verdict}"
    echo "execution_mode=${MODE}"
    echo "scan_status=${scan_status}"
    echo "result_path=${GITHUB_WORKSPACE}/reports/prufgate-result.json"
  } >> "${GITHUB_OUTPUT}"
  # Only blocker findings can be made advisory. Errors are always fatal.
  if [ "${code}" -eq 1 ] && [ "${FAIL_ON_BLOCKER}" = false ]; then
    return 0
  fi
  return "${code}"
}

native_ready() {
  [ -f "${ACTION_PATH}/prufgate.sh" ] || return 1
  local dependency
  local dependencies="python3 git"
  [ "${PROFILE}" != battery ] || dependencies="${dependencies} gitleaks sg zizmor"
  for dependency in ${dependencies}; do
    command -v "${dependency}" >/dev/null 2>&1 || return 1
  done
  # The executable named sg may be the Unix group utility, rather than ast-grep.
  if [ "${PROFILE}" = battery ]; then
    sg --version 2>/dev/null | head -1 | grep -qi 'ast-grep' || return 1
  fi
  python3 -I -c 'import sys, yaml; assert sys.version_info >= (3, 9); __import__("tomli") if sys.version_info < (3, 11) else __import__("tomllib")' >/dev/null 2>&1
}

case "${MODE}" in auto|native|container) ;; *)
  echo '::error::execution must be auto, native, or container.' >&2
  finish 2
  exit $?
esac
case "${FAIL_ON_BLOCKER}" in true|false) ;; *)
  echo '::error::fail_on_blocker must be true or false.' >&2
  finish 2
  exit $?
esac
case "${PROFILE}" in core|battery) ;; *) finish 2; exit $? ;; esac
case "${ALLOW_EXTERNAL_AI:-false}" in
  true) export PRUFGATE_ALLOW_EXTERNAL_AI=1 ;;
  false) export PRUFGATE_ALLOW_EXTERNAL_AI=0 ;;
  *) finish 2; exit $? ;;
esac

if [ -L "${GITHUB_WORKSPACE}/reports" ] || [ -L "${GITHUB_WORKSPACE}/reports/raw" ]; then
  echo '::error::Refusing symlinked report directories.' >&2
  finish 2
  exit $?
fi
mkdir -p "${GITHUB_WORKSPACE}/reports" || { finish 2; exit $?; }
# Failed setup must never upload a report from an earlier run.
rm -f "${GITHUB_WORKSPACE}/reports/prufgate.sarif" "${GITHUB_WORKSPACE}/reports/prufgate-review.md" "${GITHUB_WORKSPACE}/reports/prufgate-result.json" "${GITHUB_WORKSPACE}/reports/prufgate-result.status" || { finish 2; exit $?; }
CORE_ARGS=(check "${GITHUB_WORKSPACE}" --format sarif --result-out "${GITHUB_WORKSPACE}/reports/prufgate-result.json")
SINGLE_ENGINE=0
case "${PRUFGATE_BATTERY}" in
  bola|test-audit)
    SINGLE_ENGINE=1
    CORE_ARGS=("${PRUFGATE_BATTERY}" "${GITHUB_WORKSPACE}" --format result --result-out "${GITHUB_WORKSPACE}/reports/prufgate-result.json")
    if [ "${PRUFGATE_BATTERY}" = bola ] && [ -n "${TARGET_URL:-}" ]; then CORE_ARGS+=(--url "${TARGET_URL}"); fi
    ;;
esac
if [ "${PROFILE}" = core ]; then
  case "${PRUFGATE_BATTERY}" in
    fast|check) CORE_ARGS+=(--changed) ;;
    full|review) ;;
    *) echo '::error::Core profile supports fast/check or full/review.' >&2; finish 2; exit $? ;;
  esac
fi

if [ "${MODE}" = auto ]; then
  if native_ready; then MODE=native; else MODE=container; fi
fi
if [ "${MODE}" = native ]; then
  if ! native_ready; then
    echo '::error::Native execution requires Python >=3.9, PyYAML (tomli on Python <3.11), git, Gitleaks, ast-grep (sg), and zizmor. Install them or select execution: container.' >&2
    finish 2
    exit $?
  fi
  if [ "${SINGLE_ENGINE}" -eq 1 ]; then
    python3 -I "${ACTION_PATH}/prufgate/cli.py" "${CORE_ARGS[@]}"
  elif [ "${PROFILE}" = core ]; then
    CORE_OUTPUT="$(mktemp "${RUNNER_TEMP:-/tmp}/prufgate-output.XXXXXX")" || { finish 2; exit $?; }
    trap 'rm -f "${CORE_OUTPUT}"' EXIT
    python3 -I "${ACTION_PATH}/prufgate/cli.py" "${CORE_ARGS[@]}" > "${CORE_OUTPUT}"
  else
    WORKSPACE="${GITHUB_WORKSPACE}" bash "${ACTION_PATH}/prufgate.sh" "${PRUFGATE_BATTERY}"
  fi
  EXIT_CODE=$?
else
  if [ -z "${PRUFGATE_IMAGE:-}" ] || ! command -v docker >/dev/null 2>&1; then
    echo '::error::Container execution requires Docker and a non-empty image input.' >&2
    finish 2
    exit $?
  fi
  echo "Using PrufGate container image: ${PRUFGATE_IMAGE} (mode: ${PRUFGATE_BATTERY})"
  CONTAINER_ARGS=("${PRUFGATE_BATTERY}")
  if [ "${SINGLE_ENGINE}" -eq 1 ]; then
    CONTAINER_ARGS=(python3 -I /tools/prufgate/prufgate/cli.py "${PRUFGATE_BATTERY}" /workspace --format result --result-out /workspace/reports/prufgate-result.json)
    if [ "${PRUFGATE_BATTERY}" = bola ] && [ -n "${TARGET_URL:-}" ]; then CONTAINER_ARGS+=(--url "${TARGET_URL}"); fi
  elif [ "${PROFILE}" = core ]; then
    CONTAINER_ARGS=(python3 -I /tools/prufgate/prufgate/cli.py check /workspace --format sarif --result-out /workspace/reports/prufgate-result.json)
    case "${PRUFGATE_BATTERY}" in fast|check) CONTAINER_ARGS+=(--changed) ;; esac
  fi
  CORE_OUTPUT="$(mktemp "${RUNNER_TEMP:-/tmp}/prufgate-output.XXXXXX")" || { finish 2; exit $?; }
  trap 'rm -f "${CORE_OUTPUT}"' EXIT
  AI_ENV=()
  if [ "${PRUFGATE_ALLOW_EXTERNAL_AI}" = 1 ]; then
    AI_ENV=(-e OPENAI_API_KEY -e ANTHROPIC_API_KEY -e OLLAMA_HOST -e OPENAI_BASE_URL -e PRUFGATE_AI_MODEL -e PRUFGATE_AI_PROVIDER)
  fi
  docker run --rm --network host \
    ${AI_ENV[@]+"${AI_ENV[@]}"} \
    -e PRUFGATE_UID="$(id -u)" -e PRUFGATE_GID="$(id -g)" \
    -e TARGET_URL="${TARGET_URL:-}" -e PRUFGATE_BASE_REF="${PRUFGATE_BASE_REF:-}" \
    -e PRUFGATE_TEST_PROBE_TOKEN_A -e PRUFGATE_TEST_PROBE_TOKEN_B \
    -e PRUFGATE_TEST_PROBE_TENANT_A_ID -e PRUFGATE_TEST_PROBE_TENANT_B_ID \
    -e PRUFGATE_TENANT_A_TOKEN -e PRUFGATE_TENANT_B_TOKEN \
    -e PRUFGATE_TENANT_A_ID -e PRUFGATE_TENANT_B_ID \
    -e PRUFGATE_ALLOW_EXTERNAL_AI \
    -e GITHUB_BASE_REF="${GITHUB_BASE_REF:-}" -e CI=true \
    -v "${GITHUB_WORKSPACE}:/workspace" "${PRUFGATE_IMAGE}" "${CONTAINER_ARGS[@]}" \
    > "${CORE_OUTPUT}"
  EXIT_CODE=$?
  [ "${PROFILE}" = core ] || cat "${CORE_OUTPUT}"
fi
# A core scan's SARIF is published only when the scan completed (exit 0 or 1)
# and wrote one: an empty file would still be uploaded to code scanning.
if [ "${PROFILE}" = core ]; then
  if { [ "${EXIT_CODE}" -eq 0 ] || [ "${EXIT_CODE}" -eq 1 ]; } && [ -s "${CORE_OUTPUT}" ]; then
    mv "${CORE_OUTPUT}" "${GITHUB_WORKSPACE}/reports/prufgate.sarif" || EXIT_CODE=2
  else
    rm -f "${CORE_OUTPUT}"
  fi
fi
finish "${EXIT_CODE}"
