# CI and agent integration

## GitHub Actions: the composite action

This repository is a composite action. It runs the `prufgate.sh` gate with the runner's `python3`, uploads the SARIF report to code scanning, and fails the job on P0/P1 findings or on an error.

```yaml
name: PrufGate
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write   # SARIF upload

jobs:
  prufgate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<commit-sha>   # pin actions to a commit SHA
        with:
          fetch-depth: 0                      # the base branch must be present
          persist-credentials: false
      - run: python3 -m pip install "PyYAML>=6.0"   # needed to read .prufgate/config.yaml
      - uses: GuardianVigil-Labs/Prufgate@<commit-sha>
        with:
          battery: fast            # fast (changed files) or full
          fail_on_blocker: 'true'
          sarif_upload: 'true'
```

| Input | Default | Meaning |
|---|---|---|
| `battery` | `fast` | `fast` scans what the pull request changed; `full` (alias `review`) scans everything; `bola` and `test-audit` run one engine. |
| `base_ref` | the pull request base | Ref that changed files are compared with. On pull requests `origin/$GITHUB_BASE_REF` is used automatically. |
| `target_url` | none | Base URL for live BOLA probing of a service the job starts. Pass the tokens as `PRUFGATE_TEST_PROBE_TOKEN_A` / `_B` in `env`. |
| `fail_on_blocker` | `true` | Fail the step on a FAILED or ERROR verdict. |
| `sarif_upload` | `true` | Upload `reports/prufgate.sarif` to code scanning (skipped when no report was written). |
| `image` | `ghcr.io/guardianvigil-labs/prufgate:1.2.0` | Only used when the runner has no `python3`: the signed release image of this version, or an image you built. |

Outputs: `verdict` (`PASSED` or `FAILED`), `sarif_path`, `markdown_path`.

### Alert tracking

Every SARIF result PrufGate writes (the gate report, `prufgate check --format sarif` and `prufgate review --format sarif`) carries `partialFingerprints`, so code scanning keeps one alert per finding across commits instead of reopening or duplicating it:

- `primaryLocationLineHash` is computed the same way as GitHub's `upload-sarif` action: a hash of the whitespace-stripped content starting at the finding's line, with an occurrence counter (`:1`, `:2`) for identical content. Inserting or deleting lines above a finding does not change it.
- `prufgateFindingHash/v1` combines that hash with the rule, so two rules on the same line never share a fingerprint.

A finding without a readable file or line (a live BOLA target, a path outside the scanned folder) gets a fallback built from its rule, path and message, so it is still stable between runs.

The gate's optional tools (ast-grep, gitleaks, zizmor) are skipped if they are not on the runner; install them in an earlier step if you want those checks.

Do not set `PRUFGATE_ALLOW_REPO_HOOKS=1` in workflows that run on pull requests from forks: it runs scripts from the pull request.

## Any CI: the CLI

The CLI needs only Python and Git:

```yaml
# GitLab CI
prufgate:
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y --no-install-recommends git
    - pip install "git+https://github.com/GuardianVigil-Labs/Prufgate.git@<tag-or-sha>"
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - BASE="origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - prufgate check --changed --base "$BASE" --format junit > prufgate-junit.xml || true
    - prufgate check --changed --base "$BASE" --format gitlab > gl-code-quality-report.json
  artifacts:
    when: always
    reports:
      codequality: gl-code-quality-report.json
      junit: prufgate-junit.xml
```

`prufgate check --format sarif` writes SARIF for engines 1 to 5; `--format gitlab` and `--format junit` write the same findings as a GitLab Code Quality report and as JUnit XML. The exit code is 0, 1 or 2 as described in [GETTING_STARTED.md](GETTING_STARTED.md#exit-codes): the last command decides the job, and 2 must fail it, never pass. The gate (`prufgate.sh`) writes both files to `reports/` next to the SARIF, so a job running it can point `codequality:` and `junit:` at `reports/gl-code-quality-report.json` and `reports/prufgate-junit.xml`.

- **Code Quality**: P0 is `blocker`, P1 `critical`, P2 `major`, P3 `minor`. Each issue's `fingerprint` is the SARIF `prufgateFindingHash/v1`, so GitLab tracks a finding across pipelines the way code scanning does. Honoured `prufgate-ignore` comments are left out.
- **JUnit**: one test suite per rule and one test case per finding, named `path:line` with a `file` attribute, so every row in a test tab points at code. P0/P1 findings are failures; P2/P3 are skipped, so they show without failing the test run. A clean run holds one passing test case, because a report without test cases is an error in Jenkins and Azure. When an engine of the gate crashed, each one is an `<error>` test case, and the Code Quality report has a `blocker` issue `prufgate-engine-error` for it: a gate that could not run never reads as a clean report.
- **Jenkins**: archive the file with the JUnit plugin, `junit testResults: 'reports/prufgate-junit.xml'`. **Azure Pipelines**: `PublishTestResults@2` with `testResultsFormat: JUnit` and `testResultsFiles: reports/prufgate-junit.xml`, and `condition: always()` so a failed gate still publishes.

## Semgrep and Opengrep: exported rules

If your pipeline already runs [Semgrep](https://semgrep.dev) or [Opengrep](https://github.com/opengrep/opengrep), you can run PrufGate's single-line pattern rules there too:

```sh
prufgate export-rules --format semgrep --out prufgate-rules.yaml           # default packs
prufgate export-rules --format semgrep --pack cti --out prufgate-rules.yaml  # plus the opt-in cti pack
semgrep scan --config prufgate-rules.yaml      # or: opengrep scan --config prufgate-rules.yaml
```

Without `--out` the YAML goes to standard output. The output is sorted and carries no timestamp, so you can commit it and review the diff when you upgrade PrufGate.

- **What is exported:** the Engine 1 rules that are one regular expression over one line (`documentation-address`, `always-current-fake`, `invented-event-timestamp`, `stub-click-handler`; with `--pack cti` also `hardcoded-cve`, `hardcoded-attribution`, `llm-generated-intel`, `substring-decides-verdict`, `zero-jarm-as-fingerprint`, `empty-input-digest-as-sample`). Each is a `pattern-regex` rule (`languages: [regex]`) with `pattern-not-regex` for comment lines, and `paths` that keep PrufGate's file types and its default skips (tests, fixtures, build output).
- **What is not:** rules that need a context window (error paths, catch blocks), the diff (Engines 2, 3 and 6), cross-file analysis (Engines 4 and 5), the project's configuration, or low-confidence rules, which are off by default. The comment header of the file lists every rule left out, with the reason. The built-in ast-grep rule `action-authorization-guard` is left out too: Semgrep's `pattern-not` cannot carry its regex on the callee.
- **IDs and metadata:** rule IDs are `prufgate.<rule>`; `metadata` holds `prufgate-rule-id`, `confidence`, `pack`, `source` (the rule's section of [ENGINES.md](ENGINES.md#engine-1-anti-fabrication)) and `license: Apache-2.0`. Severity maps P0 and P1 to `ERROR`, P2 to `WARNING` and P3 to `INFO`; every exported rule is P0 in PrufGate.
- **Regex flavour:** the patterns are PrufGate's own Python regexes, with their flags written inline (`(?i)`, `(?x)`). Semgrep and Opengrep use PCRE2 over the whole file, which differs from PrufGate in three ways: `\w` and `\b` are ASCII-only in PCRE2 and Unicode-aware in Python; a `\s` can match across a line break there, while PrufGate matches one line at a time; and PrufGate's skip of lines inside multi-line Python strings has no equivalent. `tests/test_export_rules.py` checks that every pattern compiles with Python `re`, that each rule flags its positive fixture and passes its near miss, that the detector agrees on both, and runs `semgrep --validate` when Semgrep or Opengrep is installed.

`prufgate check` remains the full gate; the export is for teams that want these checks inside the scanner they already run.

## pre-commit

This repository is a [pre-commit](https://pre-commit.com) hook repository (pre-commit 3.2 or newer). In your project's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/GuardianVigil-Labs/Prufgate
    rev: v1.2.0
    hooks:
      - id: prufgate
      - id: prufgate-full
```

- **`prufgate`** runs `prufgate check --changed` at the `pre-commit` stage. pre-commit sets unstaged edits aside before hooks run, so the scan covers the staged change, plus any untracked files. It runs on every commit and takes no file names.
- **`prufgate-full`** runs `prufgate check` on the whole repository at the `pre-push` stage. Enable it with `pre-commit install --hook-type pre-push`, or leave it out.

Both block on exit 1 (P0/P1 findings) and exit 2 (PrufGate could not run, for example a first commit with nothing to compare against). pre-commit installs PrufGate from the tagged release into its own environment; the `rev` must be a tag or commit, never a branch.

## Coding-agent hooks

`prufgate init --hooks` writes:

- **`.claude/settings.json`**: a Claude Code `Stop` hook. When the agent tries to finish, it runs `prufgate check --changed --format agent-hook` (or `python3 -m prufgate.cli` when `prufgate` is not on `PATH`). With P0/P1 findings it exits 2 and lists them, which sends the agent back once to fix them. When the hook input says a Stop hook is already active, it exits 0, so it cannot loop forever: the hook asks once, and the pre-commit hook and the CI gate are what enforce. An existing `settings.json` is merged; a malformed one is refused, never overwritten.
- **`.claude/settings.json`**, again: a Claude Code `PreToolUse` hook on `Bash` running `prufgate shell-guard`, described [below](#shell-command-guard). It is merged next to the `Stop` hook and any hooks you already have; running `init --hooks` again adds nothing twice.
- **`.claude/settings.json`**, a third time: a `PreToolUse` hook on `Edit|Write|MultiEdit|NotebookEdit` running `prufgate hook claude pre-tool`, which refuses edits to CI, PrufGate and agent-hook configuration.
- **`.cursor/hooks.json`**: fail-closed Cursor hooks (`beforeShellExecution`, `preToolUse` on `Write|Delete`, `stop`).
- **`.cursor/rules/prufgate-guardrails.mdc`**: an always-on Cursor rule describing what PrufGate rejects.
- **`.pre-commit-config.yaml`**: a local pre-commit hook running `prufgate check --changed`.

`--agent NAME` (repeatable: `claude`, `cursor`, `copilot`, `codex`, `gemini`) picks the agents; without it, Claude Code and Cursor. GitHub Copilot, OpenAI Codex and Gemini CLI, the payloads, block responses and what each agent can and cannot enforce are in [Agent hooks](AGENT_HOOKS.md).

Commit what suits your team; the files are ordinary project configuration.

### Shell-command guard

Coding agents sometimes get past a failing check by changing the check. `prufgate shell-guard` reads the Claude Code `PreToolUse` hook payload on stdin (`{"tool_name": "Bash", "tool_input": {"command": "..."}}`) and blocks the command before it runs. It blocks:

- skipping git hooks: `git commit --no-verify` / `-n` (also inside combined flags such as `-nm "msg"`), `git push --no-verify`, `git merge --no-verify`, `git pull --no-verify`, `git rebase --no-verify`, `git am --no-verify` / `-n`, setting `core.hooksPath` (`git -c core.hooksPath=...`, `git config [--global] core.hooksPath ...`, `GIT_CONFIG_KEY_n` / `GIT_CONFIG_PARAMETERS`), and `HUSKY=0`, `HUSKY_SKIP_HOOKS=...` or pre-commit's `SKIP=...` in front of git or in `export`;
- defining a git alias (`git -c alias.x=...` or `git config alias.x ...`) that would run any of the above, including `!` shell aliases;
- force pushes to any branch: `git push --force`, `-f`, `--force-with-lease`, and `+branch` refspecs;
- `rm`, `rmdir`, `unlink`, `shred`, `git rm`, `mv` and `git mv` on tests or CI configuration: test directories (`test`, `tests`, `__tests__`, `spec`, `specs`, any case), test files (`test_*.py`, `*_test.go`, `*.test.ts`, `*.spec.js`, `conftest.py` and similar), `.github/workflows/`, `.gitlab-ci.yml`, `.circleci/`, `Jenkinsfile`, `azure-pipelines.yml`, `.pre-commit-config.yaml`, `.prufgate/`, `.git/hooks/` and `.claude/settings*.json`, and the whole project (`rm -rf .`). Braces are expanded first; a glob (`test*`, `.github/*`, `*/tests`) is expanded against the files in the command's directory (the hook payload's `cwd`, otherwise the current directory) and refused when an actual match is protected, so `rm -rf build/*` is allowed unless `build/` holds tests. A glob that cannot be expanded (unknown or missing directory, a variable or command substitution in it, or an earlier `cd`, `pushd` or `env -C`) is refused when it could match a protected path at all. Moving a file into a test directory is allowed; moving a file over a test or CI file is not;
- a shell that reads its script from standard input (`... | bash`, `bash <<< ...`, `bash <<EOF`, `sh -s < file`), since it cannot be inspected.

The command is parsed with POSIX quoting rules, so text inside a commit message (`git commit -m "fix --no-verify docs"`), single-quoted text, or another command's flags (`grep -n`) is not mistaken for a flag. Chained commands (`&&`, `||`, `;`, `|`, new lines), subshells, `{ ...; }`, `if`/`while`/`until`/`for`/`case` bodies, functions, `!`, `sh -c "..."` (wherever `-c` sits among the options), `eval`, `$(...)` and backticks (also inside double quotes), process substitution, environment prefixes and wrappers (`sudo`, `doas`, `env` including `env -S`, `nice`, `ionice`, `chrt`, `taskset`, `timeout`, `stdbuf`, `watch`, `xargs`, `time`, `exec`, `command`, `builtin`, `nohup`, `setsid`, `busybox`, with their option values) are all inspected.

Exit code 2 blocks the command and Claude Code shows the reason on stderr to the agent; the reason tells it to ask you to run the command yourself if it is really needed. Exit 0 lets the command through to the normal permission prompt. Input that is not a valid hook payload, a command whose quoting cannot be parsed, or a crash all exit 2. When PrufGate is not installed, the hook blocks every shell command with a message saying so, rather than letting them through unchecked.

From Python: `from prufgate.hooks.shell_guard import check_command` returns the reason a command is blocked, or `None`.

It is a guard rail against an agent's habits, not a sandbox. Known gaps, which the pre-commit hook and the CI gate still catch:

- script files (`bash script.sh`, `source`), other interpreters (`python3 -c`, `node -e`) and shell aliases or functions defined in an earlier command (`alias g=git; g ...`);
- git aliases that already exist (`git ci`), configuration included from a file (`include.path`, `GIT_CONFIG_GLOBAL`), and `declare -x` / `typeset -x`;
- paths in variables (`rm -r $x`), file names read by `xargs` from standard input, and wrapper options PrufGate does not know that take a value;
- other ways to delete or empty files: `find -delete`, `git clean`, `truncate`, `> file`, `cp /dev/null file`, `sed -i`, `git checkout` / `git restore` / `git stash` of tests;
- other git commands that rewrite remote history: `git push --mirror`, `--delete` or `:branch`;
- files created between the check and the run (the glob is expanded when the hook runs).

## MCP server

`prufgate mcp` (or `prufgate-mcp`) serves the Model Context Protocol over stdio (protocol versions 2025-06-18, 2025-03-26 and 2024-11-05):

```json
{
  "mcpServers": {
    "prufgate": { "command": "prufgate", "args": ["mcp"] }
  }
}
```

Nine tools, all read-only. They write nothing into the workspace.

| Tool | Runs |
|---|---|
| `prufgate_fast_scan` | Engines 1 to 5 on the changed files |
| `prufgate_full_scan` | Every engine on the whole workspace, plus live BOLA probing only when `target_url` is given |
| `prufgate_anti_fabrication` | Engine 1 |
| `prufgate_test_audit` | Engine 2 |
| `prufgate_diff_guard` | Engine 3 |
| `prufgate_contract_check` | Engine 4 |
| `prufgate_bola_check` | Engine 5 (static, or live with `target_url`) |
| `prufgate_review` | Engine 6 |
| `prufgate_summary` | A summary of the last report in `reports/` |

Arguments: `workspace_path`, `base_ref`, `changed_only`, `target_url`. Each result has `status` (`ok` or `error`), `passed`, `blockers` and `findings`. An engine that fails sets `isError`; it never comes back as `passed: true`.

## REST API

`prufgate api` starts an HTTP service (default `127.0.0.1:8000`):

| Route | Purpose |
|---|---|
| `GET /api/v1/health` | Health check (no token). |
| `POST /api/v1/scan` | Start a scan: `{"workspace": "...", "battery": "fast|check|review|full"}`. |
| `GET /api/v1/scans/{id}` | Scan status and verdict (`PASSED`, `FAILED` or `ERROR`). |
| `GET /api/v1/scans/{id}/sarif`, `/report` | The SARIF and Markdown reports. |
| `POST /api/v1/webhook` | Signed GitHub or GitLab webhook (only when `PRUFGATE_WEBHOOK_SECRET` is set). |
| `GET /docs`, `/openapi.json` | API documentation. |

Every route except health needs `Authorization: Bearer $PRUFGATE_API_TOKEN`. Scans are confined to `PRUFGATE_WORKSPACE_ROOT`. From a checkout, a scan runs the `prufgate.sh` gate; from a pip install it runs `prufgate check --format sarif` (engines 1 to 5, SARIF only). The security model is in [SECURITY.md](../SECURITY.md#running-prufgate-safely), and the variables are in [CONFIGURATION.md](CONFIGURATION.md#environment-variables).
