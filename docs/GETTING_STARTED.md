# Getting started

## Requirements

- Python 3.9 or newer, with PyYAML (installed automatically).
- Git, for anything that looks at changes (`--changed`, `--base`, the diff engines).
- Optional, for the full `prufgate.sh` gate: [ast-grep](https://ast-grep.github.io/), [gitleaks](https://github.com/gitleaks/gitleaks) and [zizmor](https://docs.zizmor.sh/). A step whose tool is missing is reported as skipped.

## Install

| Method | What you get |
|---|---|
| `pipx install prufgate` or `pip install prufgate` | The `prufgate` and `prufgate-mcp` commands from PyPI: every engine, the CLI, the MCP server and the API. The `prufgate.sh` shell gate is not part of the wheel. |
| `docker run --rm -v "$PWD:/workspace" ghcr.io/guardianvigil-labs/prufgate:1.2.0` | The signed release image (amd64 and arm64): the `prufgate` command plus the full `prufgate.sh` gate with ast-grep, gitleaks and zizmor. With no arguments it runs `fast` on the mounted repository; `... prufgate:1.2.0 prufgate check .` runs the CLI. |
| `pip install .` (in a checkout) | The same commands from a checkout. |
| `./install.sh` | A `prufgate` launcher in `~/.local/bin` (or `/usr/local/bin`) that runs this checkout. Keep the checkout where it is. |
| `make build`, then `bin/prufgate --docker ...` | A container image built from your checkout, the same as the release image. It is about 460 MB uncompressed (about 100 MB gzipped): the Python base and git, plus the three scanners (ast-grep about 55 MB, zizmor 27 MB, gitleaks 22 MB). The pip install and the GitHub Action need none of that. |
| `bin/prufgate.ps1` | The same launcher for Windows PowerShell. |

Every release is signed and carries build provenance: [Verify a release](../SECURITY.md#verify-a-release).

Check the install:

```bash
prufgate --version
prufgate --self-check      # runs every engine against its built-in positive and near-miss fixtures
```

## Commands

```text
prufgate check [PATH] [--changed] [--base REF] [--config FILE] [--format text|json|sarif|gitlab|junit|agent-hook] [--ai-adjudicate [--ai-provider NAME]]
prufgate fast                     same as: prufgate check --changed
prufgate full                     same as: prufgate check
prufgate test-audit [PATH] [--changed] [--base REF] [--config FILE] [--json-out FILE]
prufgate bola [PATH] [--static-only] [--url URL --token-a T --token-b T --tenant-a ID --tenant-b ID] [--base REF] [--format text|json]
prufgate review [--workspace PATH] [--base REF] [--diff-file FILE] [--format markdown|json|sarif|github|reviewdog|gitlab|junit] [--ai --ai-provider NAME]
prufgate fix [PATH] [--base REF] [--format patch|github-suggestions] [--apply [--force]]
prufgate verify --differential [PATH] --allow-run-tests [--base REF] [--test-cmd CMD] [--timeout SECONDS] [--pass-env NAME] [--format text|json|sarif]
prufgate verify --mutation [PATH] --allow-run-tests [--base REF] [--tool NAME] [--max-mutants N] [--timeout SECONDS] [--pass-env NAME] [--format text|json|sarif]
prufgate init [PATH] [--hooks] [--overwrite]
prufgate shell-guard              Claude Code PreToolUse hook: hook JSON on stdin, exit 2 blocks
prufgate base-ref [PATH]          print the base ref the changed scope would use (exit 2 if none is usable)
prufgate mcp                      (or prufgate-mcp) the MCP server on stdio
prufgate api [--host 127.0.0.1] [--port 8000]
prufgate --self-check | --version | --help
```

- **`prufgate check`** runs engines 1 to 5 (anti-fabrication, test integrity, diff guard, contract guard, static BOLA) and prints one combined list. `PATH` defaults to the current directory and can be anywhere; paths in the output are relative to it.
- **`prufgate test-audit`** runs engine 2 alone.
- **`prufgate bola`** runs engine 5. It is static only unless you give a URL and two tokens: see [live probing](#live-bola-probing).
- **`prufgate review`** runs engine 6 on a diff. It is deterministic by default; `--ai` hands the changed hunks to an AI CLI or API you have configured (see [ENGINES.md](ENGINES.md#engine-6-diff-reviewer)).
- **`prufgate fix`** proposes deterministic fixes for safe findings: see [auto-fix](#auto-fix-prufgate-fix).
- **`prufgate verify --differential`** runs the base branch's tests against the head code. **It executes the repository's tests**, so it refuses to run without `--allow-run-tests` or `PRUFGATE_ALLOW_RUN_TESTS=1`; run it only in a sandbox or a disposable CI job. See [ENGINES.md](ENGINES.md#differential-test-verification-opt-in-runs-repository-code).
- **`prufgate verify --mutation`** mutates the lines the branch changed with a mutation tool you already have installed (mutmut, Stryker, PIT, gremlins, go-mutesting or cargo-mutants) and reports each surviving mutant. It runs the repository's tests, so it has the same opt-in. See [ENGINES.md](ENGINES.md#mutation-smoke-test-opt-in-runs-repository-code).
- **`prufgate init`** writes a starter `.prufgate/config.yaml`. With `--hooks` it also writes the coding-agent hooks described in [CI_INTEGRATION.md](CI_INTEGRATION.md#coding-agent-hooks).
- **`prufgate shell-guard`** is the shell-command guard those hooks run before an agent's shell command: see [the shell guard](CI_INTEGRATION.md#shell-command-guard).

### Which changes "changed" means

With `--changed`, PrufGate compares against a base ref and includes uncommitted and untracked files. The base is chosen in this order (first match wins):

1. `--base REF`
2. the `PRUFGATE_BASE_REF` environment variable
3. `origin/$GITHUB_BASE_REF` (set by GitHub Actions on pull requests)
4. `origin/HEAD`
5. on a clean working tree only: `HEAD~1`

A candidate the branch is not ahead of (for example `origin/HEAD` right after a pull) is skipped. A base ref that does not exist, or no usable base on a clean tree (often a shallow clone), is an error (exit 2), never "nothing changed". `prufgate base-ref` shows which base would be used. In CI, check out with full history (`fetch-depth: 0`).

### A changed scan judges only the changed lines

A pull request is judged on what it changed. With `--changed` (and in `prufgate.sh fast`, the GitHub Action and the container's default run), the engines still read whole files for context, but a finding is reported only when it sits on a line the change added or modified: debt already in a file you touched, and files you did not touch, are left to a full scan.

- A finding on a line that opens a block (a function, a test, an `if`, `catch` or `except` body) covers the block, and a BOLA finding covers its handler: deleting a test's assertions or a handler's guard is a change to that test or route.
- Rules about the diff itself keep working whatever line they point at: deleted test files, weakened assertions, skips and suppressions (`diff-*`, engine 3, the reviewer, configuration and baseline changes).
- BOLA reports only route, action and migration files the change touched. Auth configured application-wide is still read from the whole repository.
- In `prufgate.sh fast`, ast-grep gets only the changed files, zizmor only the changed workflows (a finding is kept when any of its locations, such as the trigger it depends on, is on a changed line), and gitleaks only the branch's commits (`<base>..HEAD`) plus uncommitted edits.
- A full scan (`prufgate check` without `--changed`, `./prufgate.sh full`) applies no scope and reports everything. The number of findings left out goes to stderr.

## Auto-fix: `prufgate fix`

`prufgate fix --base REF` prints a unified diff of fixes to stdout and changes nothing. Pipe it to `git apply`, or pass `--apply` to write it. `--format github-suggestions` prints the fixes as GitHub suggestion blocks, in the same shape as `prufgate review --format github`, so a reviewer accepts each one with a click.

Only these findings get a fix, and only on lines the branch adds against the base:

| Finding | Fix |
|---|---|
| A focus filter (`it.only`, `describe.only`, `test.only`, `fit`, `fdescribe`) | Remove `.only` or the `f` prefix. |
| An unjustified skip (`it.skip`, `xit`, a bare `@pytest.mark.skip`, `t.Skip()`) | Remove it, back to the base line. |
| `diff-assertion-weakening` | Restore the exact base lines, when the hunk only deletes assertions or replaces them one for one. |
| A suppression comment without a reason (`ignore-without-reason`, a bare `noqa`, `@ts-ignore`, ...) | Remove the comment. A reason is never invented. |
| `\|\| true` or `continue-on-error: true` in a CI workflow | Remove it. |

Everything else is listed on stderr as `no safe fix`. Each fix must match the expected text exactly, and is kept only when its rule stops firing once it is applied; anything ambiguous (two matches on one line, a comment marker that may sit inside a string, a hunk that changes more than assertions) gets no fix.

`--apply` writes only files inside the repository, never through a symlink, and refuses a file with uncommitted changes (exit 2) unless `--force`, which applies a fix only where its line still matches. Running it again after a successful apply changes nothing.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No blocking findings. |
| 1 | At least one P0 or P1 finding. |
| 2 | PrufGate could not do its job: a bad option or config, a base ref that does not exist, an unreadable file, an engine crash, missing engine output. |

Severities: **P0** fabricated or broken behaviour that must not merge, **P1** a likely problem that blocks by default, **P2** an advisory, **P3** information.

## The full gate: `prufgate.sh`

From a checkout (or the container), `prufgate.sh` runs all six engines plus the optional tools and writes reports:

```bash
./prufgate.sh fast [WORKSPACE]    # changed files
./prufgate.sh full [WORKSPACE]    # the whole repository (review and all are aliases)
```

| Output | Where |
|---|---|
| SARIF 2.1.0 for code scanning | `reports/prufgate.sarif` |
| Human summary | `reports/prufgate-review.md` |
| GitLab Code Quality | `reports/gl-code-quality-report.json` |
| JUnit XML for test tabs | `reports/prufgate-junit.xml` |
| Raw engine output | `reports/raw/*.json` |
| Each step's log | `reports/raw/<tool>.log` |
| What ran, how long, exit code | `reports/raw/execution_manifest.jsonl` |

The terminal table and the Markdown report end with a verdict: **PASSED**, **FAILED** (P0/P1 findings) or **ERROR** (a step did not finish, so the scan is incomplete). `reports/` gets its own `.gitignore`, so reports are never committed by accident.

Set `TARGET_URL` (and the probe tokens, below) to add live BOLA probing to the gate, or `BOLA_STATIC_ONLY=1` to force static analysis.

## Live BOLA probing

Only probe systems you own or are authorised to test. Give the base URL and two users' tokens from different tenants:

```bash
prufgate bola . --url http://127.0.0.1:3000 \
  --token-a "$TOKEN_A" --tenant-a org_a \
  --token-b "$TOKEN_B" --tenant-b org_b
```

The tokens can also come from `PRUFGATE_TEST_PROBE_TOKEN_A` / `PRUFGATE_TEST_PROBE_TOKEN_B` (and the tenant IDs from `PRUFGATE_TEST_PROBE_TENANT_A_ID` / `_B_ID`). PrufGate compares an unauthenticated request, each user's own resources, and each user's access to the other's, and reports cross-tenant reads. Reports show `$PRUFGATE_TOKEN_A` / `$PRUFGATE_TOKEN_B` in the `curl` reproductions, never the real tokens. An unreachable URL is an error (exit 2).

## Next steps

- Tune what is checked: [CONFIGURATION.md](CONFIGURATION.md)
- Understand a rule or a false positive: [ENGINES.md](ENGINES.md)
- Gate pull requests and coding agents: [CI_INTEGRATION.md](CI_INTEGRATION.md)
