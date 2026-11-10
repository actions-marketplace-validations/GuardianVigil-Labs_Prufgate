#!/usr/bin/env bash
#
# PrufGate: verification gate orchestrator
# Usage: prufgate.sh [fast|check|review|full|all] [workspace]
#        prufgate.sh bola|test-audit [args...]   (passed to prufgate/cli.py)
#        prufgate.sh init|mcp|api|--self-check|--help
# Exit codes: 0 clean, 1 blocking findings (P0/P1), 2 an engine failed or bad usage.
#

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "/tools/prufgate" ]; then
  TOOL_ROOT="/tools/prufgate"
else
  TOOL_ROOT="${SCRIPT_DIR}"
fi
export TOOL_ROOT

MODE="${1:-fast}"
# `prufgate.sh fast /path/to/repo`: the second argument names the workspace.
case "${MODE}" in
  fast|check|review|full|all)
    if [ -n "${2:-}" ]; then
      if [ ! -d "$2" ]; then
        echo "prufgate.sh: workspace is not a directory: $2" >&2
        exit 2
      fi
      WORKSPACE="$(cd "$2" && pwd)"
    fi
    ;;
esac
export WORKSPACE="${WORKSPACE:-$([ -d /workspace ] && [ -w /workspace ] && echo /workspace || pwd)}"
cd "${WORKSPACE}" || exit 2
# Links above the workspace (macOS /tmp, /home -> /var/home) are the operator's,
# not the repository's: use the physical path so only links inside it are refused.
WORKSPACE="$(pwd -P)"

# Delegate direct CLI subcommands (init, mcp, api, --self-check, --help) to prufgate/cli.py
case "${MODE}" in
  init|mcp|api|--self-check|--help|-h|help|--version)
    exec python3 -I "${TOOL_ROOT}/prufgate/cli.py" "$@"
    ;;
esac

DEFAULT_REPORTS_DIR="${WORKSPACE}/reports"
REPORTS_DIR="${PRUFGATE_REPORTS_DIR:-${DEFAULT_REPORTS_DIR}}"
# Decide on where the folder really is, never on how its path is spelled:
# follow each existing component to its physical path, then append the rest.
# reports/ may sit inside the scanned repository, and a committed symlink there
# must not make PrufGate delete or overwrite files elsewhere, so no component
# inside the workspace may be a symlink.
refuse_reports_dir() { echo "prufgate.sh: PRUFGATE_REPORTS_DIR $1: ${REPORTS_DIR}" >&2; exit 2; }
case "${REPORTS_DIR}" in /*) _phys="" ;; *) _phys="${WORKSPACE}" ;; esac
_rest="${REPORTS_DIR}"
_tail=""
while [ -n "${_rest}" ]; do
  _part="${_rest%%/*}"
  case "${_rest}" in */*) _rest="${_rest#*/}" ;; *) _rest="" ;; esac
  case "${_part}" in ""|.) continue ;; ..) refuse_reports_dir "must not contain '..'" ;; esac
  _next="${_phys}/${_part}"
  if [ -n "${_tail}" ] || { [ ! -e "${_next}" ] && [ ! -L "${_next}" ]; }; then
    _tail="${_tail}/${_part}"
  elif [ -L "${_next}" ] && case "${_phys}/" in "${WORKSPACE}"/*) true ;; *) false ;; esac; then
    refuse_reports_dir "passes through the workspace symlink ${_next}"
  elif [ -d "${_next}" ]; then
    _phys="$(cd -P "${_next}" && pwd -P)" || exit 2
    _phys="${_phys%/}"
  else
    refuse_reports_dir "passes through ${_next}, which is not a directory"
  fi
done
REPORTS_DIR="${_phys}${_tail}"
# Inside the workspace only the default folder is allowed; anywhere else is the operator's choice.
case "${REPORTS_DIR}/" in
  "${WORKSPACE}"/*) [ "${REPORTS_DIR}" = "${DEFAULT_REPORTS_DIR}" ] || refuse_reports_dir "inside the workspace must be ${DEFAULT_REPORTS_DIR}" ;;
esac
RAW_DIR="${REPORTS_DIR}/raw"
export PRUFGATE_REPORTS_DIR="${REPORTS_DIR}"
export RAW_DIR
if [ -L "${RAW_DIR}" ]; then
  echo "prufgate.sh: ${RAW_DIR} is a symlink; refusing to use it" >&2
  exit 2
fi
mkdir -p "${RAW_DIR}" || exit 2
rm -rf "${RAW_DIR:?}"/* 2>/dev/null || true

START_TIME=$(date +%s)

echo "══════════════════════════════════════════════════════════════════════"
echo "  PRUFGATE VERIFICATION GATE (Mode: ${MODE})"
echo "  Target Workspace: ${WORKSPACE}"
echo "══════════════════════════════════════════════════════════════════════"

case "${MODE}" in
  fast|check)
    echo "⚡ Changed-files verification..."
    bash "${TOOL_ROOT}/runners/run_fast.sh" changed
    ;;
  review|full|all)
    echo "🔍 Full-workspace verification..."
    bash "${TOOL_ROOT}/runners/run_fast.sh" full
    ;;
  bola)
    echo "🎯 Running Multi-Tenant BOLA / IDOR Engine..."
    shift || true
    exec python3 -I "${TOOL_ROOT}/prufgate/cli.py" bola "$@"
    ;;
  test-audit|test)
    echo "🧪 Running Test Integrity & Anti-Reward-Hacking Engine..."
    shift || true
    exec python3 -I "${TOOL_ROOT}/prufgate/cli.py" test-audit "$@"
    ;;
  *)
    echo "Unknown mode: ${MODE}"
    echo "Supported modes: fast, check, review, full, bola, test-audit, init, mcp, api, --self-check"
    exit 2
    ;;
esac

# Execute SARIF 2.1.0 & Markdown Report Synthesizer
python3 -I "${TOOL_ROOT}/prufgate/synthesizer/parse_results.py"
EXIT_CODE=$?

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo "⏱ Audit completed in ${ELAPSED}s (Exit code: ${EXIT_CODE})"
echo "  SARIF:    ${REPORTS_DIR}/prufgate.sarif"
echo "  Markdown: ${REPORTS_DIR}/prufgate-review.md"
echo "  GitLab:   ${REPORTS_DIR}/gl-code-quality-report.json"
echo "  JUnit:    ${REPORTS_DIR}/prufgate-junit.xml"

exit ${EXIT_CODE}
