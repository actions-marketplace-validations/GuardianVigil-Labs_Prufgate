#!/usr/bin/env bash
#
# PrufGate verification gate: runs the six engines plus the optional ast-grep,
# zizmor and gitleaks steps, and records every step's exit code in
# reports/raw/execution_manifest.jsonl. The synthesizer turns a crashed step
# into an ERROR verdict (exit 2), never a pass.
#
# Usage: run_fast.sh [changed|full]
# Base ref: PRUFGATE_BASE_REF, origin/$GITHUB_BASE_REF (pull requests), then
# origin/HEAD, or HEAD~1 when the working tree has no changes, if HEAD is ahead
# of it. With uncommitted changes and no base ref, the working-tree diff is
# scanned against HEAD and the baseline is read as committed at HEAD. With nothing to compare, the changed scope is an error; the full
# scope skips the two diff-only engines (diff guard, reviewer) and says so.
# With a base ref the engines read the PrufGate configuration as it is at the
# base (git show), never the working tree: configuration changes take effect
# after merge. The full scope reads the working tree, except the diff guard.
#

set -uo pipefail

SCAN_SCOPE="${1:-changed}"

# shellcheck source=runners/lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

ENGINE="${TOOL_ROOT}/prufgate"

# Every engine appends the inline ignores it honoured (or refused for lack of a
# reason) here; the synthesizer counts and lists them in the report.
export PRUFGATE_SUPPRESSIONS_FILE="${RAW_DIR}/suppressions.jsonl"
rm -f "${PRUFGATE_SUPPRESSIONS_FILE}"

# run_step <tool> <pillar> <output-file-or-empty> <command...>
# Output goes to reports/raw/<tool>.log so a crash is visible, not swallowed.
run_step() {
  local tool="$1" pillar="$2"
  shift 2
  local t_start rc
  t_start=$(date +%s)
  "$@" >"${RAW_DIR}/${tool}.log" 2>&1
  rc=$?
  record_tool_status "${tool}" "${pillar}" "executed" "${rc}" "$(( $(date +%s) - t_start ))" ""
  [ "${rc}" -ge 2 ] && echo "  ✘ ${tool} exited ${rc}: see ${RAW_DIR}/${tool}.log" >&2
  return 0
}

# Base ref (see prufgate/cli.py resolve_base_ref): an empty value means "scan
# the working-tree diff". DIFF_OK=0 means there is nothing to diff against.
FULL=0
case "${SCAN_SCOPE}" in full|all) FULL=1 ;; esac
BASE_REF=""
DIFF_OK=1
if ! in_git_repo; then
  DIFF_OK=0
  if [ "${FULL}" -eq 0 ]; then
    record_tool_status "base-ref" "config" "error" 2 0 "not a git repository: the changed scope has nothing to compare (use full)"
  fi
elif ! BASE_REF="$(python3 "${ENGINE}/cli.py" base-ref "${WORKSPACE}" 2>"${RAW_DIR}/base-ref.log")"; then
  BASE_REF=""
  DIFF_OK=0
  if [ "${FULL}" -eq 0 ]; then
    record_tool_status "base-ref" "config" "error" 2 0 "$(tr '\n' ' ' <"${RAW_DIR}/base-ref.log")"
  fi
fi

SCOPE_ARGS=()
if [ "${FULL}" -eq 0 ]; then
  SCOPE_ARGS=("--changed${BASE_REF:+=${BASE_REF}}")
fi
DIFF_ARGS=("--changed${BASE_REF:+=${BASE_REF}}")
# The reviewer diffs <base>...HEAD; with no base, HEAD...HEAD is empty and it
# falls back to the working-tree diff.
REVIEW_ARGS=("--base=${BASE_REF:-HEAD}")
# The synthesizer reads the configuration and baseline at the same base ref (an
# empty file means HEAD). A full scan in a git repository does too, so a branch
# cannot turn on ai_adjudicate or widen its baseline for itself.
if [ "${FULL}" -eq 0 ] || in_git_repo; then
  printf '%s\n' "${BASE_REF}" >"${RAW_DIR}/base_ref"
fi

# A changed-files run judges only what the change touched: the lines it added or
# modified (prufgate/diff_scope.py). The synthesizer drops findings elsewhere, and
# ast-grep, zizmor and BOLA get only the changed files. A full run writes no scope.
export PRUFGATE_CHANGED_FILES=""
if [ "${FULL}" -eq 0 ] && [ "${DIFF_OK}" -eq 1 ]; then
  PRUFGATE_CHANGED_FILES="${RAW_DIR}/changed_files.txt"
  if ! python3 "${ENGINE}/diff_scope.py" "--base=${BASE_REF}" --json-out="${RAW_DIR}/changed_lines.json" \
      >"${PRUFGATE_CHANGED_FILES}" 2>"${RAW_DIR}/diff-scope.log"; then
    record_tool_status "diff-scope" "config" "error" 2 0 "$(tr '\n' ' ' <"${RAW_DIR}/diff-scope.log")"
  fi
fi

echo "▶ [PrufGate] Starting verification gate (scope: ${SCAN_SCOPE}${BASE_REF:+, base: ${BASE_REF}})"

# Optional structural and workflow checks (ast-grep, zizmor)
if [ -f "${TOOL_ROOT}/runners/run_ast_lint.sh" ]; then
  bash "${TOOL_ROOT}/runners/run_ast_lint.sh"
fi

# Optional secret scan
if command -v gitleaks >/dev/null 2>&1; then
  echo "  Running gitleaks secret scan..."
  if in_git_repo && [ -n "${PRUFGATE_CHANGED_FILES}" ]; then
    # Changed scope: the branch's commits, and uncommitted edits (line-scoped later).
    if [ -n "${BASE_REF}" ]; then
      run_step gitleaks security gitleaks git --no-banner --log-opts="${BASE_REF}..HEAD" --config "$(gitleaks_config)" --report-format json --report-path "${RAW_DIR}/gitleaks.json"
    else
      echo "[]" >"${RAW_DIR}/gitleaks.json"
    fi
    if [ -n "$(git -C "${WORKSPACE}" -c core.hooksPath=/dev/null -c core.fsmonitor=false status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
      run_step gitleaks-worktree security gitleaks dir --no-banner --config "$(gitleaks_config)" --report-format json --report-path "${RAW_DIR}/gitleaks_worktree.json" .
    fi
  elif in_git_repo; then
    run_step gitleaks security gitleaks git --no-banner --config "$(gitleaks_config)" --report-format json --report-path "${RAW_DIR}/gitleaks.json"
  else
    run_step gitleaks security gitleaks detect --no-git --config "$(gitleaks_config)" --report-format json --report-path "${RAW_DIR}/gitleaks.json"
  fi
else
  record_tool_status "gitleaks" "security" "skipped" 0 0 "gitleaks binary not found"
fi

# skip_step <tool> <pillar> <reason>
skip_step() { record_tool_status "$1" "$2" "skipped" 0 0 "$3"; }

if [ "${FULL}" -eq 0 ] && [ "${DIFF_OK}" -eq 0 ]; then
  # Recorded above as a base-ref error: the changed-files engines have no input.
  for t in anti-fabrication:security test-integrity:qa diff-guard:security pr-reviewer:quality; do
    skip_step "${t%%:*}" "${t##*:}" "no base ref (see base-ref error)"
  done
  CHANGED_ENGINES=0
else
  CHANGED_ENGINES=1
fi

if [ "${CHANGED_ENGINES}" -eq 1 ]; then
echo "  [Engine 1/6] Production anti-fabrication..."
run_step anti-fabrication security python3 "${ENGINE}/anti_fabrication/detector.py" ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} --json-out="${RAW_DIR}/anti_fabrication.json"

echo "  [Engine 2/6] Test integrity & anti-reward-hacking..."
run_step test-integrity qa python3 "${ENGINE}/anti_reward_hacking/test_integrity.py" ${SCOPE_ARGS[@]+"${SCOPE_ARGS[@]}"} --json-out="${RAW_DIR}/test_integrity.json"

echo "  [Engine 3/6] Diff tampering guard..."
if [ "${DIFF_OK}" -eq 1 ]; then
  run_step diff-guard security python3 "${ENGINE}/diff_guard/tamper_detector.py" "${DIFF_ARGS[@]}" --json-out="${RAW_DIR}/diff_guard.json"
else
  skip_step diff-guard security "no git diff to check (not a git repository, or no base ref)"
fi
fi

echo "  [Engine 4/6] Ghost dependency, API contract & env drift guard..."
CG_ARGS=()
[ "${SCAN_SCOPE}" = "changed" ] && CG_ARGS=("--changed${BASE_REF:+=${BASE_REF}}")
run_step contract-guard security python3 "${ENGINE}/contract_guard/__init__.py" ${CG_ARGS[@]+"${CG_ARGS[@]}"} --workspace="${WORKSPACE}" --json-out="${RAW_DIR}/contract_guard.json"

echo "  [Engine 5/6] Multi-tenant BOLA / IDOR..."
# Static checks always; the live two-token probe only when TARGET_URL is set.
if [ -n "${TARGET_URL:-}" ] && [ "${BOLA_STATIC_ONLY:-0}" != "1" ]; then
  BOLA_ARGS=("--url=${TARGET_URL}")
else
  BOLA_ARGS=("--static-only")
fi
# A changed-files run reads the PrufGate configuration at the base ref, like engines 1-4.
[ "${FULL}" -eq 0 ] && [ -n "${BASE_REF}" ] && BOLA_ARGS+=("--base=${BASE_REF}")
# Only the changed route, action and migration files.
[ -n "${PRUFGATE_CHANGED_FILES}" ] && BOLA_ARGS+=("--changed")
bola_json() { python3 "${ENGINE}/cli.py" bola "${WORKSPACE}" "${BOLA_ARGS[@]}" --format json >"${RAW_DIR}/bola_matrix.json"; }
run_step bola-matrix security bola_json

echo "  [Engine 6/6] Diff reviewer..."
if [ "${DIFF_OK}" -eq 1 ]; then
  run_step pr-reviewer quality python3 "${ENGINE}/review/reviewer.py" --workspace="${WORKSPACE}" "${REVIEW_ARGS[@]}" --output-json="${RAW_DIR}/pr_review.json" --output-md="${RAW_DIR}/pr_review.md"
elif [ "${FULL}" -eq 1 ]; then
  skip_step pr-reviewer quality "no git diff to review (not a git repository, or no base ref)"
fi

echo "✔ [PrufGate] Verification gate complete"
