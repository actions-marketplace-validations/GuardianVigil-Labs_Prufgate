#!/usr/bin/env bash
#
# PrufGate Shared Runner Library
# Provides workspace/report directory resolution, execution manifest logging,
# and safe subprocess execution helpers across all battery runners.
#

if [ -z "${TOOL_ROOT:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [ -d "/tools/prufgate" ]; then
    TOOL_ROOT="/tools/prufgate"
  else
    TOOL_ROOT="${SCRIPT_DIR}"
  fi
fi
export TOOL_ROOT

WORKSPACE="${WORKSPACE:-$([ -d /workspace ] && [ -w /workspace ] && echo /workspace || pwd)}"
export WORKSPACE

REPORTS_DIR="${PRUFGATE_REPORTS_DIR:-${WORKSPACE}/reports}"
RAW_DIR="${REPORTS_DIR}/raw"
export REPORTS_DIR RAW_DIR
if [ -L "${REPORTS_DIR}" ] || [ -L "${RAW_DIR}" ]; then
  echo "prufgate: ${REPORTS_DIR} or ${RAW_DIR} is a symlink; refusing to use it" >&2
  exit 2
fi
mkdir -p "${RAW_DIR}"
# Reports never belong in the scanned repository's history: this makes git
# ignore the folder without touching the project's own .gitignore.
[ -e "${REPORTS_DIR}/.gitignore" ] || [ -L "${REPORTS_DIR}/.gitignore" ] || printf '# Written by PrufGate: reports are never committed.\n*\n' > "${REPORTS_DIR}/.gitignore" 2>/dev/null || true

# gitleaks configuration (PrufGate#16 follow-up): PrufGate's defaults plus the
# target's own .gitleaks.toml when it has one, so a project's rules are
# extended, never silently replaced by --config.
gitleaks_config() {
  local base="${TOOL_ROOT}/configs/gitleaks.toml"
  if [ -f "${WORKSPACE}/.gitleaks.toml" ]; then
    local merged="${RAW_DIR}/gitleaks.merged.toml"
    {
      printf '[extend]\npath = "%s"\n\n' "${WORKSPACE}/.gitleaks.toml"
      sed -n '/^\[allowlist\]/,$p' "${base}"
    } > "${merged}"
    echo "${merged}"
  else
    echo "${base}"
  fi
}

# A git repository gitleaks can read: `git rev-parse`, not `[ -d .git ]`,
# because in a worktree or submodule .git is a file.
in_git_repo() {
  git -C "${WORKSPACE}" -c core.hooksPath=/dev/null -c core.fsmonitor=false rev-parse --is-inside-work-tree >/dev/null 2>&1
}

MANIFEST_FILE="${RAW_DIR}/execution_manifest.jsonl"

# Record a scanner execution status entry into execution_manifest.jsonl
# Usage: record_tool_status <tool> <pillar> <status> <exit_code> <duration_s> [note]
record_tool_status() {
  local tool="$1"
  local pillar="$2"
  local status="$3"
  local exit_code="${4:-0}"
  local duration_s="${5:-0}"
  local note="${6:-}"

  python3 -c '
import json, sys, datetime
entry = {
    "tool": sys.argv[1],
    "pillar": sys.argv[2],
    "status": sys.argv[3],
    "exit_code": int(sys.argv[4]),
    "duration_seconds": float(sys.argv[5]),
    "note": sys.argv[6],
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
}
with open(sys.argv[7], "a", encoding="utf-8") as f:
    f.write(json.dumps(entry) + "\n")
' "$tool" "$pillar" "$status" "$exit_code" "$duration_s" "$note" "$MANIFEST_FILE" 2>/dev/null || true
}
