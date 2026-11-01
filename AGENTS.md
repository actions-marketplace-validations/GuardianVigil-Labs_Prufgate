# Maintaining PrufGate

A guide for anyone, human or AI, who works on this repository. `CLAUDE.md` points here; this file is the only copy.

This repository is public. Every file, commit message, branch name, issue, pull request, review comment and release note can be read by anyone, forever. Deleting it later does not unpublish it.

## Project layout

| Path | What it holds |
|---|---|
| `prufgate/cli.py` | The `prufgate` command: `check`, `test-audit`, `bola`, `review`, `verify` (`--differential`, `--mutation`), `fix`, `init`, `baseline` (`prufgate/baseline.py`), `explain` (`prufgate/explain.py`, kept in step with `prufgate/rules.py` and `docs/ENGINES.md` by `tests/test_explain.py`), `shell-guard`, `hook`, `transcript` (`prufgate/transcript.py`), `bench`, `export-rules`, `pr-summary` (`prufgate/pr_summary.py`), `mcp`, `api`, `--self-check`. |
| `prufgate/config.py` | `.prufgate/config.yaml` loading and validation. |
| `prufgate/anti_fabrication/` | Engine 1: production code that fakes its result. `packs/` holds opt-in domain packs. |
| `prufgate/anti_reward_hacking/` | Engine 2: tests that cannot fail. |
| `prufgate/diff_guard/` | Engine 3: skips, suppressions and weakened checks added in a diff. |
| `prufgate/contract_guard/` | Engine 4: undeclared imports, undocumented environment variables, calls to routes that do not exist. |
| `prufgate/bola/` | Engine 5: static tenant and auth checks on routes, and optional live two-token probing. |
| `prufgate/review/` | Engine 6: diff review, with optional AI delegation. |
| `prufgate/synthesizer/` | Merges engine output into SARIF and Markdown and decides the exit code. |
| `prufgate/mcp/`, `prufgate/api/`, `prufgate/hooks/` | The MCP server, the REST API, the coding-agent hooks written by `prufgate init --hooks`, and the AGENTS.md / BUGBOT.md section written by `--agents-md` / `--bugbot`. |
| `plugins/prufgate/`, `.claude-plugin/marketplace.json` | The Claude Code plugin and its marketplace. `hooks/hooks.json` is generated from `claude_plugin_hooks()`; the manifest version must equal `prufgate.__version__` (`tests/test_claude_plugin.py`). |
| `runners/`, `prufgate.sh` | The shell batteries (`fast`, `full`) used by the GitHub Action and the container. |
| `configs/` | ast-grep rules (`rules/` built in, `examples/` opt-in), gitleaks and ruff configuration. |
| `prufgate/bench.py`, `bench/cases/` | `prufgate bench` and its labelled corpus: one `.txt` file per case, so the cheats in it never reach the gate's own scan (`docs/BENCHMARK.md`). |
| `tests/` | `unittest` suites, including the leak guard `test_public_repo_hygiene.py`. |
| `docs/` | User documentation. |

## Local checks

Run all of these before opening a pull request. Every one must pass.

```sh
python3 prufgate/cli.py --self-check        # every engine's built-in fixtures
python3 -m unittest discover -s tests       # unit tests and the leak guard
ruff check --config configs/ruff.toml prufgate/ tests/
./prufgate.sh fast                          # the battery the GitHub Action runs
```

The leak guard scans tracked files only, so stage new files with `git add` before running it. Maintainers who keep a private list of project names pass it as `PRUFGATE_PRIVATE_TERMS_FILE=/path/outside/the/repo`; that list is never committed, not even hashed.

## What every engine must keep

- **Fail closed.** An engine that crashes, cannot read its input or is given a bad argument exits 2, and the run fails. A crash must never read as a pass.
- **Never run code from the repository being scanned.** Repository hook scripts run only when the operator sets `PRUFGATE_ALLOW_REPO_HOOKS=1`. The exceptions are `prufgate verify --differential` (`prufgate/differential.py`) and `prufgate verify --mutation` (`prufgate/mutation.py`), which run the repository's tests only with `--allow-run-tests` or `PRUFGATE_ALLOW_RUN_TESTS=1`, share their containment in `prufgate/repo_runner.py`, and must never be called from `check`, the batteries, the MCP server, the API or the hooks.
- **Never write a secret into a report.** Live BOLA tokens are redacted in PoCs, SARIF and Markdown.
- **Every rule has fixtures:** at least one invented sample it must flag and one near miss it must not, in the engine's `--self-check` cases or in `tests/`. A bug fix comes with a test that fails without it.
- **Exit codes:** 0 clean, 1 blocking findings (P0/P1), 2 an error.
- Domain-specific rules (for example threat-intelligence data) go in an opt-in pack, never in the default set.

## Privacy and leaks

Never commit personal data, local paths, credentials or non-public information: not in files, commit messages, branch names, issues, pull requests, test fixtures, logs or screenshots.

- Use invented examples: `example.com` and `.example` domains, and the documentation addresses 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
- Describe problems generically ("a scan of a Next.js project reported..."), never which project, how many or where it lives.
- A leak-guard finding is fixed by removing the content. Never weaken the guard or add an exception without a maintainer's approval.
- If you find something like this already in the repository or its history, do not repeat it in public. Tell the maintainers privately: prufgate@guardianvigil.io.

## Pull requests, commits and workflows

- Changes reach `main` only through a pull request reviewed by a code owner. Squash-merge.
- No AI attribution: no co-author trailers naming a model, no "generated with" lines, no bot signatures.
- Every action in `.github/workflows/` and `action.yml` is pinned to a commit SHA (`tests/test_workflows.py`). Nothing publishes on a branch push: images and releases come only from a version tag or a manual run.
