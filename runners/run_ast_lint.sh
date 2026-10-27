#!/usr/bin/env bash
#
# PrufGate optional structural accelerators: ast-grep rules, zizmor workflow
# checks, and (only when the operator opts in) the scanned repository's own
# .prufgate/hooks/ scripts.
#
# Built-in ast-grep rules live in configs/ast-grep/rules/. Opinionated rules
# that only suit some architectures are in configs/ast-grep/examples/: copy
# one into the project's .prufgate/rules/ to turn it on.
#

set -uo pipefail

# shellcheck source=runners/lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# 1. ast-grep (sg)
SG_BIN=""
if command -v ast-grep >/dev/null 2>&1 && ast-grep --version 2>&1 | grep -q "ast-grep"; then
  SG_BIN="ast-grep"
elif command -v sg >/dev/null 2>&1 && sg --version 2>&1 | grep -q "ast-grep"; then
  SG_BIN="sg"
fi

if [ -n "${SG_BIN}" ]; then
  echo "  Running ast-grep structural rules..."
  T_START=$(date +%s)

  ACTIVE_RULES=()
  if [ -f "package.json" ] || [ -d "src" ] || [ -d "app" ]; then
    [ -f "${TOOL_ROOT}/configs/ast-grep/rules/action-authorization-guard.yml" ] && ACTIVE_RULES+=("${TOOL_ROOT}/configs/ast-grep/rules/action-authorization-guard.yml")
  fi

  # The project's own rules: declarative YAML, never executed as code.
  if [ -d ".prufgate/rules" ]; then
    for custom_rule in .prufgate/rules/*.yml .prufgate/rules/*.yaml; do
      if [ -f "${custom_rule}" ]; then
        ACTIVE_RULES+=("${custom_rule}")
      fi
    done
  fi

  if [ ${#ACTIVE_RULES[@]} -gt 0 ]; then
    # A rule that ast-grep cannot run, or output that is not JSON, is an
    # error recorded in the manifest, never an empty (passing) result.
    python3 -c '
import os, subprocess, json, sys
sg_bin, out_path, active_rules = sys.argv[1], sys.argv[2], sys.argv[3:]
# A changed-files run scans only the changed files (PRUFGATE_CHANGED_FILES lists them).
listing = os.environ.get("PRUFGATE_CHANGED_FILES")
paths = open(listing, encoding="utf-8").read().splitlines() if listing else []
all_matches, errors = [], []
for r in active_rules if paths or not listing else []:
    res = subprocess.run([sg_bin, "scan", "-r", r, "--json", "--", *paths], capture_output=True, text=True)
    # ast-grep exits 0 when clean and 1 when a rule matched; anything else
    # (an invalid or missing rule exits 6 or 8 with nothing on stdout) failed.
    try:
        items = json.loads(res.stdout) if res.returncode in (0, 1) else None
    except ValueError:
        items = None
    if not isinstance(items, list):
        errors.append(r)
        continue
    all_matches.extend(items)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(all_matches, f, indent=2)
for r in errors:
    print(f"  ast-grep could not run rule {r}", file=sys.stderr)
sys.exit(2 if errors else 0)
' "${SG_BIN}" "${RAW_DIR}/ast_grep.json" "${ACTIVE_RULES[@]}"
    SG_RC=$?
    if [ "${SG_RC}" -eq 0 ]; then
      record_tool_status "ast-grep" "ast" "executed" 0 "$(( $(date +%s) - T_START ))" "${#ACTIVE_RULES[@]} rule(s)"
    else
      record_tool_status "ast-grep" "ast" "error" "${SG_RC}" "$(( $(date +%s) - T_START ))" "a rule failed to run"
    fi
  else
    echo "[]" > "${RAW_DIR}/ast_grep.json"
    record_tool_status "ast-grep" "ast" "skipped" 0 0 "no applicable AST rules for repo languages"
  fi
else
  record_tool_status "ast-grep" "ast" "skipped" 0 0 "ast-grep binary not installed"
fi

# 2. Zizmor CI workflow auditing
if [ -d ".github/workflows" ]; then
  if command -v zizmor >/dev/null 2>&1; then
    echo "  Running zizmor on GitHub Actions workflows..."
    T_START=$(date +%s)
    ZM_TARGETS=(.github/workflows/)
    if [ -n "${PRUFGATE_CHANGED_FILES:-}" ]; then
      # A changed-files run audits only the workflows the change touched.
      ZM_TARGETS=()
      while IFS= read -r wf; do ZM_TARGETS+=("${wf}"); done < <(grep -E '^\.github/workflows/[^/]+\.ya?ml$' "${PRUFGATE_CHANGED_FILES}" || true)
    fi
    if [ ${#ZM_TARGETS[@]} -eq 0 ]; then
      echo "[]" > "${RAW_DIR}/zizmor.json"
      record_tool_status "zizmor" "ast" "skipped" 0 0 "no workflow changed"
    else
      zizmor --format json "${ZM_TARGETS[@]}" > "${RAW_DIR}/zizmor.json" 2>/dev/null
      ZM_RC=$?
      record_tool_status "zizmor" "ast" "executed" "${ZM_RC}" "$(( $(date +%s) - T_START ))" ""
    fi
  else
    record_tool_status "zizmor" "ast" "skipped" 0 0 "zizmor binary not installed"
  fi
fi

# 3. The scanned repository's own hook scripts (.prufgate/hooks/).
# They are code from the repository under review: running them by default
# would let any pull request execute commands on the machine that scans it.
# They run only when the operator sets PRUFGATE_ALLOW_REPO_HOOKS=1.
if [ -d ".prufgate/hooks" ]; then
  if [ "${PRUFGATE_ALLOW_REPO_HOOKS:-0}" != "1" ]; then
    echo "  Skipping .prufgate/hooks/: set PRUFGATE_ALLOW_REPO_HOOKS=1 to run the repository's own hook scripts"
    record_tool_status "repo-hooks" "ast" "skipped" 0 0 "PRUFGATE_ALLOW_REPO_HOOKS is not 1"
  else
    for hook in .prufgate/hooks/*.sh .prufgate/hooks/*.py; do
      if [ -f "${hook}" ]; then
        hook_name=$(basename "${hook}")
        echo "  Running custom audit hook ${hook_name}..."
        T_START=$(date +%s)
        if [[ "${hook}" == *.py ]]; then
          python3 "${hook}" > "${RAW_DIR}/hook_${hook_name}.log" 2>&1
        else
          bash "${hook}" > "${RAW_DIR}/hook_${hook_name}.log" 2>&1
        fi
        HOOK_RC=$?
        if [ "${HOOK_RC}" -ne 0 ]; then
          echo "HOOK_FAILURE" > "${RAW_DIR}/hook_${hook_name}.fail"
          record_tool_status "hook:${hook_name}" "ast" "error" "${HOOK_RC}" "$(( $(date +%s) - T_START ))" "custom hook failed"
        else
          record_tool_status "hook:${hook_name}" "ast" "executed" 0 "$(( $(date +%s) - T_START ))" "custom hook"
        fi
      fi
    done
  fi
fi
