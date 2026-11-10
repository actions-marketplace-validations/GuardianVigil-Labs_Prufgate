# Developer guide

Read [AGENTS.md](../AGENTS.md), [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md) before contributing. Use public, invented examples; keep credentials, private project details, local logs and machine identifiers out of patches and commit metadata.

## Set up a checkout

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r .github/ci-requirements.txt
python -m pip install --no-deps -e .
python prufgate/cli.py --help
```

On Windows activate the environment using the shell's equivalent command. The repository supports Python 3.9+; CI also exercises newer interpreters and platform differences. External battery scanners are separate dependencies; use the matching development container or install the pinned tools described in the Dockerfile and CI configuration. Do not install dependencies from a repository being scanned.

## Code map

| Area | Files |
|---|---|
| Command parsing and core orchestration | `prufgate/cli.py` |
| Detectors and rule confidence | Engine packages, `rules.py`, `explain.py` |
| Configuration, baselines and diff scope | `config.py`, `baseline.py`, `diff_scope.py` |
| Result schema, coverage and privacy | `scan_result.py`, `coverage.py`, `privacy.py`, `result_validation.py` |
| Reviewed exceptions and enforcement | `dismissals.py`, `enforcement.py`, `workflow.py` |
| Shell process orchestration and synthesis | `prufgate.sh`, `runners/`, `engine_runner.py`, `synthesizer/` |
| Filesystem and process safety | `safe_fs.py`, `process.py`, `repo_runner.py` |
| API, MCP, Action and editor | `api/`, `mcp/`, `action.yml`, `scripts/run_action.sh`, `editors/vscode/` |
| PR rendering and optional publishing | `pr_summary.py`, `github_checks.py` |
| Evaluation and change impact | `bench.py`, `evaluation.py`, `evaluation_corpus.py`, `python_flow.py`, `change_impact.py` |

The [architecture](ARCHITECTURE.md) describes the boundaries. API/MCP/editor integrations must preserve effective scan status and policy; they must not reinterpret missing output as an empty finding list.

## Required checks

From the repository root:

```sh
python3 prufgate/cli.py --self-check
python3 -m unittest discover -s tests
ruff check --config configs/ruff.toml prufgate/ tests/
WORKSPACE="$PWD" ./prufgate.sh fast
python3 scripts/build_evaluation_corpus.py
```

Stage new intended files before the public-repository leak checks: they scan tracked content. Never stage generated `reports/`, local environments, private term lists or logs. The leak guard does not replace human review of names, prose, screenshots and metadata. Existing failures must be investigated; a restricted environment or unavailable external tool is not automatically a detector defect.

For editor changes:

```sh
cd editors/vscode
npm ci --ignore-scripts --no-audit --no-fund
npm run build
npm run typecheck
npm test
npm run test:integration
```

The integration test consumes real CLI output. API, Action, MCP and result-consistency tests use local fixture repositories and mocked publishing. Do not enable real publication or external AI to run unit tests. Inspect the relevant targeted tests while developing, then run the required checks before submitting.

## Add or change a rule

Provide at least one positive case and one near miss. Keep rule IDs, severity/confidence, explanations and engine documentation consistent. Preserve changed-line scope, trusted base configuration, inline-ignore reasons and reviewed-dismissal fingerprints. Errors must remain fatal even under advisory adoption. Suggested fixes need independent validation and must not execute scanned source.

Maintain the source/result boundary: scanner execution errors, invalid JSON/SARIF, unreadable files and incomplete live probes require explicit status. Use shared safe filesystem/Git/process helpers. Do not invoke differential/mutation verification from core scans, hooks, API or MCP tools.

## Evaluate without overstating evidence

`bench/cases` is the maintainer regression floor; `bench/evaluation` is synthetic syntax coverage. `bench/testdata/independent` is an exposed upstream-derived external set with retained permissions and partial labels. The extraction check detects case/evidence drift. Its first scores are not a required perfect-score assertion: retain misses and adjudicate scope/policy differences.

If changing detectors, compare equivalent profiles and case hashes, and describe observed improvements and remaining limits. Do not claim unseen validation from a dataset already used for tuning. See [evaluation methodology](EVALUATION.md).

## Submit a reviewable change

Update user-facing docs and the changelog for behavior changes. Review staged content and metadata for public suitability. Describe the resulting behavior, compatibility, validation and material limitations in the PR. Changes reach `main` through code-owner review; do not merge or publish a release as part of preparing a PR.
