# CI and agent integration

Use the [documentation index](README.md) for the full guide set. Detailed [API](API.md), [MCP](MCP.md), [review workflow](REVIEW_WORKFLOW.md) and [upgrade](UPGRADING.md) references cover current checkout features and installation compatibility.

## GitHub Actions: the composite action

This repository is a composite action. It runs the `prufgate.sh` gate natively or in a container, uploads the SARIF report to code scanning, and fails the job on P0/P1 findings or on an error.

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
      - uses: GuardianVigil-Labs/Prufgate@<commit-sha>
        with:
          battery: fast            # fast (changed files) or full
          execution: container     # use the release image with all dependencies
          fail_on_blocker: 'true'
          sarif_upload: 'true'
```

| Input | Default | Meaning |
|---|---|---|
| `battery` | `fast` | `fast` scans what the pull request changed; `full` (alias `review`) scans everything; `bola` and `test-audit` run one engine. |
| `profile` | `battery` | `core` matches Engines 1–5 from CLI check, MCP fast scan, API core and editor scans. `battery` adds diff review and external scanners. |
| `allow_external_ai` | `false` | Explicitly consent to AI adjudication, also requiring trusted enabled configuration. Destinations and content are described in [scan privacy](SCAN_RESULTS.md#external-ai-consent-and-destinations). |
| `base_ref` | the pull request base | Ref that changed files are compared with. On pull requests `origin/$GITHUB_BASE_REF` is used automatically. |
| `target_url` | none | Base URL for live BOLA probing of a service the job starts. Pass the tokens as `PRUFGATE_TEST_PROBE_TOKEN_A` / `_B` in `env`. |
| `fail_on_blocker` | `true` | Fail on blocking findings. With `false`, findings remain FAILED but do not fail the step. Execution errors always fail the step with ERROR. |
| `sarif_upload` | `true` | Upload `reports/prufgate.sarif` to code scanning (skipped when no report was written). |
| `execution` | `auto` | `native` validates the runner's dependencies; `container` always uses `image`; `auto` selects native only when all required dependencies are present, otherwise container. |
| `image` | `ghcr.io/guardianvigil-labs/prufgate:1.4.0` | Container image. Set `execution: container` to force an image you built even when Python is installed. |
| `job_summary` | `true` | Write a short summary of the run to the job summary page: see [the run summary](#the-run-summary-and-pull-request-comment). |
| `pr_comment` | `false` | Keep the same summary as one pull request comment, updated on every run. Needs `pull-requests: write`. |
| `github_checks` | `false` | Publish a separate Check Run with changed-line annotations, coverage and next actions. Requires `checks: write`; fork PR publication is skipped. |
| `checks_token` | `github.token` | Token used only by the opted-in Checks publishing step. |
| `github_token` | `github.token` | Token for the pull request comment. Passed to the summary step only when `pr_comment` is `true`. |

Outputs: `scan_status` (`clean`, `findings`, `incomplete`, `error`), `result_path` (versioned JSON), compatibility `verdict` (`PASSED`, `FAILED` or `ERROR`), `exit_code` (`0`, `1` or `2`), `execution_mode`, `sarif_path`, and `markdown_path`. Native core mode requires Python 3.9+, PyYAML, tomli on Python 3.9/3.10, and Git; battery mode also requires Gitleaks, ast-grep (`sg`), and zizmor. Container mode requires Docker (a Linux runner such as `ubuntu-latest`; macOS and Windows runners have no Docker) and an image from the same PrufGate version as the action. The default `image` is the signed release image of the action's own version, so an action pinned to a release tag works as is; an action pinned to an unreleased commit needs `image:` set to an image built from that commit, or `execution: native` with the dependencies installed, otherwise the run stops with an error because the older image writes no versioned scan status. The `execution`, `profile` and `allow_external_ai` inputs are not in the published 1.3.0 action; with 1.3.0, install PyYAML on the runner as the README shows. Missing dependencies or missing result metadata are errors; `fail_on_blocker: false` cannot suppress them. Previous result artifacts are cleared before execution. See [consistent scan results](SCAN_RESULTS.md).

### The run summary and pull request comment

See [the developer and PR workflow](REVIEW_WORKFLOW.md) for reviewed dismissals, gradual enforcement, Check Run previews/publication, and new-versus-existing finding comparisons using `--previous-sarif`.

After the gate, the action writes a short summary to the job summary page. It shows:

- the verdict, and the number of blocking (P0/P1), warning (P2) and note (P3) findings, plus how many were ignored with a reason or dismissed by AI adjudication;
- the first ten findings, most severe first, with rule, file and line;
- facts about the change, compared with the base ref the gate used: files and lines changed in production code, tests, build and CI configuration, and documentation; assertion lines added and removed in tests; dependency manifests and CI, lint, test or coverage configuration touched; and a note when production code changed but no test file did.

With `pr_comment: 'true'` the same summary is kept as one comment on the pull request. Each run edits that comment instead of adding a new one. Add the permission to the workflow:

```yaml
permissions:
  contents: read
  security-events: write   # SARIF upload
  pull-requests: write     # the summary comment
```

A pull request from a fork gets a read-only token, so no comment is posted there; the step logs a warning and the job summary is still written. Do not switch to `pull_request_target` to get a write token: that event runs with the base repository's secrets, and the gate reads the pull request's code.

The summary reports the result; it never changes it. If the summary cannot be written or posted, the step warns and the gate's verdict stands. Paths and messages come from the code under review, so they are shown only as inline code, which cannot mention anyone, link or render HTML; messages pass through the same redaction as AI adjudication, and a secret scanner's match is never included.

The same summary is available anywhere with `prufgate pr-summary` (see [GETTING_STARTED.md](GETTING_STARTED.md#commands)).

### Alert tracking

Every SARIF result PrufGate writes (the gate report, `prufgate check --format sarif` and `prufgate review --format sarif`) carries `partialFingerprints`, so code scanning keeps one alert per finding across commits instead of reopening or duplicating it:

- `primaryLocationLineHash` is computed the same way as GitHub's `upload-sarif` action: a hash of the whitespace-stripped content starting at the finding's line, with an occurrence counter (`:1`, `:2`) for identical content. Inserting or deleting lines above a finding does not change it.
- `prufgateFindingHash/v1` combines that hash with the rule, so two rules on the same line never share a fingerprint.

A finding without a readable file or line (a live BOLA target, a path outside the scanned folder) gets a fallback built from its rule, path and message, so it is still stable between runs.

When running `prufgate.sh` directly, ast-grep, Gitleaks and zizmor are optional and skipped if absent. The composite action validates these dependencies so its native and container modes provide the same scanner coverage.

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
    rev: v1.4.0
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

Ten tools, all read-only. They write nothing into the workspace.

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
| `prufgate_explain` | What a rule catches and how to fix it (`rule`; reads no workspace) |

Arguments include `workspace_path`, applicable `base_ref`, `changed_only` and `target_url`, and `rule` for `prufgate_explain`; discover exact per-tool schemas with `tools/list`. Results retain compatibility `status: ok|error` and expose the common `scan_status`, `exit_code`, coverage and policy decisions. Incomplete/error tools set `isError` and cannot be reported as a pass. The full tool is `core+review`, not the external-scanner battery. See [MCP](MCP.md).

## REST API

`prufgate api` starts an HTTP service (default `127.0.0.1:8000`):

| Route | Purpose |
|---|---|
| `GET /api/v1/health` | Health check (no token). |
| `POST /api/v1/scan` | Start a scan: `{"workspace": "...", "battery": "fast|check|review|full", "profile": "core|battery"}`. |
| `GET /api/v1/scans/{id}` | Scan status and verdict (`PASSED`, `FAILED` or `ERROR`). |
| `DELETE /api/v1/scans/{id}` | Cancel an active scan or delete a finished scan and its per-scan artifacts. |
| `GET /api/v1/scans/{id}/sarif`, `/report` | The SARIF and Markdown reports. |
| `POST /api/v1/webhook` | Signed GitHub or GitLab webhook (only when `PRUFGATE_WEBHOOK_SECRET` is set). |
| `GET /docs`, `/openapi.json` | API documentation. |

Scan submission, list/status, cancellation and artifacts require `Authorization: Bearer $PRUFGATE_API_TOKEN`; health and schema/docs routes are public, while webhooks use their own signature secret. Scans are confined to `PRUFGATE_WORKSPACE_ROOT`. The core profile uses the common Python scanner; checkout battery scans include additional engines/tools, while an installed-package fallback can have narrower coverage. Inspect the actual profile/coverage. See the [API reference](API.md), [security model](../SECURITY.md#running-prufgate-safely) and [environment variables](CONFIGURATION.md#environment-variables).

Set `profile: core` for equivalent CLI/MCP/editor scans and versioned coverage metadata with either installation. `scan_status` is separate from the API's job lifecycle `status`. Completed responses include explainable findings, coverage, privacy metadata, errors and incomplete reasons. The core profile is static; a live `target_url` requires the battery profile.

On POSIX, cancellation and timeout terminate the scan's process group, escalate to SIGKILL after a one-second grace period, and reap the scan process before dropping its registration. On Windows the scan process is terminated and reaped. A cancelled scan cannot publish a new shared report. Only an explicit request `target_url` enables live probes; an inherited `TARGET_URL` does not.

The server permits 16 simultaneous HTTP connections by default; excess connections receive 503. Each connection has a 30-second total deadline, including headers and body, so sending occasional bytes cannot hold a request thread indefinitely. Synchronous scans must finish within this connection deadline; use asynchronous scans for longer work, or increase `PRUFGATE_API_HTTP_TIMEOUT`.

Finished scan history and its per-scan artifacts are limited to 200 records and 24 hours by default. Cleanup runs on scan submission, completion and periodic server maintenance. Orphaned UUID report directories from a previous server run are reclaimed when that workspace is next scanned. Active scans are excluded; filesystem links are never followed during cleanup. The shared latest validated report remains available separately in `reports/`.
