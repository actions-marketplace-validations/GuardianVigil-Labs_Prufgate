<!-- mcp-name: io.github.GuardianVigil-Labs/prufgate -->
<div align="center">
  <img src="https://raw.githubusercontent.com/GuardianVigil-Labs/Prufgate/main/assets/prufgate-icon.svg" alt="PrufGate logo" width="128" />
  <h1>PrufGate</h1>
  <p><strong>Checks whether code, and the tests that claim it works, are real.</strong></p>
  <p>
    <a href="https://github.com/GuardianVigil-Labs/Prufgate/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-green.svg" alt="License: Apache 2.0" /></a>
    <a href="https://pypi.org/project/prufgate/"><img src="https://img.shields.io/pypi/v/prufgate?label=pypi" alt="PyPI version" /></a>
    <img src="https://img.shields.io/badge/Python-3.9%2B-blue" alt="Python 3.9+" />
    <a href="https://scorecard.dev/viewer/?uri=github.com/GuardianVigil-Labs/Prufgate"><img src="https://api.scorecard.dev/projects/github.com/GuardianVigil-Labs/Prufgate/badge" alt="OpenSSF Scorecard" /></a>
    <a href="https://www.bestpractices.dev/projects/15961"><img src="https://www.bestpractices.dev/projects/15961/badge" alt="OpenSSF Best Practices" /></a>
  </p>
</div>

Linters check that code compiles. PrufGate looks for code that compiles, passes review at a glance and still does not do the job. This is the kind of code an AI coding agent (or a hurried human) writes to make a task look finished:

- a `catch` block that returns a hard-coded success object;
- a click handler that does nothing;
- a test that asserts `true`, or mocks the very function it tests;
- a `.skip`, `@ts-ignore` or lowered coverage threshold slipped into a diff;
- an import of a package that is not declared anywhere;
- an API route that loads a record by ID without checking who owns it.

PrufGate is deterministic: plain Python, no network calls and no LLM unless you ask for one. It runs in seconds on a pull request, and writes SARIF for code scanning and Markdown for humans. It is meant to sit next to your linters and SAST tools, not replace them.

## The six engines

| # | Engine | What it catches |
|---|---|---|
| 1 | Anti-fabrication (`prufgate/anti_fabrication`) | Canned success on error paths, simulated return values, `MOCK_*`/`SAMPLE_*` data in production code, stub UI handlers, fake "fresh" timestamps, unimplemented stubs, LLM prompts that ask for a verdict without passing any evidence, documentation addresses in production. |
| 2 | Test integrity (`prufgate/anti_reward_hacking`) | Tests with no assertions, assertions that cannot fail, tests that mock the unit under test, swallowed exceptions, assertions deleted or weakened in a diff, test files deleted or test cases removed in a diff, production code special-casing a test's literal input. |
| 3 | Diff guard (`prufgate/diff_guard`) | Skips and focus (`.skip`, `.only`, `xit`, `pytest.mark.skip`, `t.Skip()`, `#[ignore]`, `@Disabled`) added without an issue reference, fake exits (`sys.exit(0)`, `process.exit(0)`, module-level `SkipTest`) added to tests or test setup, bare suppressions (`@ts-ignore`, `# noqa`, `// nolint`, `#[allow]`), `as unknown as T` casts, weakened linter/CI/coverage settings, and new exemptions in PrufGate's own config. |
| 4 | Contract guard (`prufgate/contract_guard`) | Imports not declared in `package.json`, `pyproject.toml`/`requirements*.txt`, `go.mod` or `Cargo.toml`; environment variables read without a default and missing from `.env.example`; frontend calls to API routes that do not exist. |
| 5 | BOLA / IDOR (`prufgate/bola`) | Route handlers that look up a record by a client-supplied ID with no auth guard or no tenant/owner scoping, across Express, Next.js, NestJS, FastAPI, Flask, Django, Go (net/http, Gin, Echo, Chi), Spring, Rails and Laravel. Optional live two-token probing of a running service you own. |
| 6 | Diff reviewer (`prufgate/review`) | High-precision rules on changed lines (SQL built from strings, shell injection, disabled TLS verification, hard-coded credentials, unsanitised HTML, ignored Go errors, credential logging), GitHub suggestion blocks, and optional delegation to an AI CLI or API you choose. |

Details, rule IDs, supported languages and known limits for each engine: [docs/ENGINES.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/ENGINES.md).

PrufGate uses pattern and structure heuristics, not a full parser for every language. It will miss things and it will sometimes flag correct code. Every finding names its rule, and [inline `prufgate-ignore: rule -- reason` comments, exemptions and baselines](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CONFIGURATION.md#suppressing-findings) let you record why.

## Quick start

PrufGate needs Python 3.9 or newer and Git.

```bash
pipx install prufgate     # or: pip install prufgate  (the `prufgate` and `prufgate-mcp` commands)
prufgate --self-check     # every engine against its built-in fixtures
uvx prufgate --version    # or run it without installing, with uv
```

Or download one file, `prufgate.pyz`, from the [latest release](https://github.com/GuardianVigil-Labs/Prufgate/releases/latest) (releases after 1.0.0). It is a [zipapp](https://docs.python.org/3/library/zipapp.html) with PyYAML (pure Python) inside, so it needs nothing but Python 3.9 or newer:

```bash
curl -LO https://github.com/GuardianVigil-Labs/Prufgate/releases/latest/download/prufgate.pyz
curl -LO https://github.com/GuardianVigil-Labs/Prufgate/releases/latest/download/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify prufgate.pyz --repo GuardianVigil-Labs/Prufgate
python3 prufgate.pyz --self-check
python3 prufgate.pyz check .
```

The hooks that `prufgate init --hooks` writes call `prufgate` on `PATH`, so for them install the file as a command: `install -m 755 prufgate.pyz ~/.local/bin/prufgate`. The zipapp runs every command a pip install has except `mcp` (use `pipx install prufgate` for the MCP server). Like a pip install, it does not include the shell batteries (`./prufgate.sh fast` / `full` with ast-grep, gitleaks and zizmor); `prufgate.pyz fast` and `full` run the Python engines only. For the full battery use the container image or a checkout. There are no native per-OS binaries: they would need a build on three operating systems for every release, and the zipapp covers the same need. `python3 scripts/build_pyz.py` builds the same file from a checkout; it downloads the hash-locked PyYAML sdist from PyPI and refuses one that does not match `requirements.txt`.

Or run the signed container image, which adds the full gate with ast-grep, gitleaks and zizmor:

```bash
docker run --rm -v "$PWD:/workspace" ghcr.io/guardianvigil-labs/prufgate:1.2.0          # the fast gate on this repository
docker run --rm -v "$PWD:/workspace" ghcr.io/guardianvigil-labs/prufgate:1.2.0 prufgate check .
```

Or add the GitHub Action to a pull-request workflow, pinned to the commit SHA of the `v1.2.0` tag ([full example](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CI_INTEGRATION.md)):

```yaml
- uses: actions/checkout@<commit-sha>
  with: { fetch-depth: 0, persist-credentials: false }
- run: python3 -m pip install "PyYAML>=6.0"
- uses: GuardianVigil-Labs/Prufgate@<commit-sha-of-v1.2.0>
```

Every release is signed and carries build provenance and an SBOM: [Verify a release](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/SECURITY.md#verify-a-release).

Or add it to your [pre-commit](https://pre-commit.com) configuration, `.pre-commit-config.yaml` ([details](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CI_INTEGRATION.md#pre-commit)):

```yaml
repos:
  - repo: https://github.com/GuardianVigil-Labs/Prufgate
    rev: v1.2.0
    hooks:
      - id: prufgate          # changed files, on every commit
      - id: prufgate-full     # whole repository, before a push (pre-commit install --hook-type pre-push)
```

Then, in your project:

```bash
prufgate check .                          # engines 1-5 on the whole repository
prufgate check --changed --base origin/main   # only what this branch changed
prufgate init --hooks                     # starter config + coding-agent hooks
```

Exit codes are the same everywhere: **0** clean, **1** blocking findings (P0/P1), **2** PrufGate could not run (bad config, bad base ref, unreadable file, engine crash). A crash never reads as a pass.

## Ways to run it

| Want | Use |
|---|---|
| A quick check while coding | `prufgate check --changed` |
| Findings inline in VS Code | The [VS Code extension](https://marketplace.visualstudio.com/items?itemName=GuardianVigil.prufgate) ([source](https://github.com/GuardianVigil-Labs/Prufgate/tree/main/editors/vscode)): runs `prufgate check --changed` on save, trusted workspaces only (install from a `.vsix` for now) |
| One engine | `prufgate test-audit`, `prufgate bola`, `prufgate review` |
| The full gate with SARIF and Markdown reports | `./prufgate.sh fast` (changed files) or `./prufgate.sh full`, from a checkout. Reports go to `reports/prufgate.sarif`, `reports/prufgate-review.md`, `reports/gl-code-quality-report.json` (GitLab Code Quality) and `reports/prufgate-junit.xml`. |
| A pull-request gate on GitHub | The composite action in this repository: [docs/CI_INTEGRATION.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CI_INTEGRATION.md) |
| A coding agent sent back to fix its findings before it stops | `prufgate init --hooks` (Claude Code Stop hook, which asks once; Cursor rule; the pre-commit hook and the CI gate enforce) |
| A coding agent stopped from skipping hooks, force-pushing or deleting tests and CI config | `prufgate init --hooks` (Claude Code, Cursor) or `--agent copilot\|codex\|gemini`: fail-closed hooks running `prufgate hook <agent> <event>` ([support table](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/AGENT_HOOKS.md)) |
| Base-branch tests run against the head code (executes repository tests: sandbox or CI only, opt-in) | `prufgate verify --differential --allow-run-tests` |
| Mutation smoke test on the changed lines with an installed mutmut, Stryker, PIT, gremlins, go-mutesting or cargo-mutants (executes repository tests: opt-in) | `prufgate verify --mutation --allow-run-tests` |
| PrufGate as a Claude Code plugin (hooks plus a `/prufgate:prufgate-check` skill) | `pipx install prufgate`, then in Claude Code `/plugin marketplace add GuardianVigil-Labs/Prufgate` and `/plugin install prufgate@prufgate` ([details](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/AGENT_HOOKS.md#claude-code-plugin)) |
| Other agents and AI reviewers (Cursor Bugbot, Copilot review) told to use PrufGate's findings | `prufgate init --agents-md` (AGENTS.md) and `--bugbot` (`.cursor/BUGBOT.md`): a marked section, updated in place on rerun ([details](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/AGENT_HOOKS.md#instructions-for-agents-and-reviewers-agentsmd-bugbotmd)) |
| An AI second opinion on PrufGate's own low-confidence findings only (opt-in, sends a few lines of code to a provider you choose) | `ai_adjudicate: true` in the configuration: see [AI adjudication](#ai-adjudication) |
| Tools for an agent over MCP | `prufgate mcp`: nine read-only tools |
| A service that scans on webhook | `prufgate api`: bearer token, loopback by default |

The full command and option reference is in [docs/GETTING_STARTED.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/GETTING_STARTED.md), and every configuration key is in [docs/CONFIGURATION.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CONFIGURATION.md).

## Configuration in one look

PrufGate works without configuration. To tune it, add `.prufgate/config.yaml`:

```yaml
version: 1
packs: [core, web-ui, ai-safety]      # cti is an opt-in domain pack
exclude: ["dist/**", "vendor/**"]
auth_guards: [requireUser, get_current_user]
tenant_keys: [organization_id, account_id]
exempt:
  src/legacy/adapter.ts:
    route-canned-fallback: "#104: legacy fallback until the payments API migration"
known_debt:
  stub-click-handler: 0                # a ceiling that can only go down
```

In a pull request (any run with a base ref) PrufGate reads this file as it is on the base branch, so configuration changes take effect after merge: a change cannot exempt its own findings.

## AI adjudication

PrufGate is deterministic by default and sends nothing anywhere. Two opt-in modes use an AI provider you choose (a `claude` CLI, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or `OLLAMA_HOST`; `--ai-provider` names another):

- `prufgate review --ai` asks the model to review the whole diff.
- `ai_adjudicate: true` in the configuration (read at the base ref in a pull request, by `prufgate check` and the `prufgate.sh` gate; `--ai-adjudicate` alone does nothing without it) asks one yes/no question per **low-confidence** finding (`medium` too if configured): is this real? The prompt holds the rule, the finding message and a few redacted lines around it, never whole files.

An adjudication verdict can only hide noise. A finding judged not real stops blocking and moves to an "AI-dismissed" list with the model's reason: a section of `prufgate check` output and of the Markdown report, and a SARIF `suppressions` entry of kind `external` (`AI-dismissed: <reason>`). High-confidence findings are never sent; nothing is ever added or raised. A provider error, a timeout, a reply that is not exactly `{"real": true|false, "reason": "..."}`, a run over its budget, or code that addresses the judge (a comment naming the AI, LLM, judge, reviewer or PrufGate) keeps the finding as it would be without AI. Verdicts are cached outside the repository. Settings: [docs/CONFIGURATION.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CONFIGURATION.md#ai-adjudication).

## Documentation

- [Getting started](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/GETTING_STARTED.md): install, commands, reports, exit codes
- [Configuration reference](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CONFIGURATION.md): every key, suppressions, environment variables
- [The engines](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/ENGINES.md): rules, languages and limits
- [CI and agent integration](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CI_INTEGRATION.md): GitHub Action, other CI, agent hooks, MCP, REST API
- [Custom rules](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/CUSTOM_RULES.md): your own ast-grep rules and hooks
- [Architecture](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/ARCHITECTURE.md)
- [Benchmark](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/BENCHMARK.md): measured precision and recall on a labelled corpus, and how to add a case
- [Changelog](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/CHANGELOG.md)

## Contributing and security

Contributions are welcome: see [CONTRIBUTING.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/CONTRIBUTING.md) and the maintainer guide [AGENTS.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/AGENTS.md). Please report vulnerabilities privately, as described in [SECURITY.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/SECURITY.md).

PrufGate is published by GuardianVigil under the [Apache License 2.0](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/LICENSE). The name and logo are trademarks: see [TRADEMARKS.md](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/TRADEMARKS.md).
