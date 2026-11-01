# Architecture

PrufGate is plain Python (3.9+, one dependency: PyYAML) plus a small shell gate. It makes no network calls unless you ask for live BOLA probing or AI review.

```text
                 prufgate check / test-audit / bola / review          prufgate.sh fast|full  (GitHub Action, container, API)
                                  |                                          |
                                  v                                          v
  prufgate/config.py  ->  engines 1-5 in process  ->  one finding list    runners/run_fast.sh
  (.prufgate/config.yaml)                              (text/json/sarif)   - ast-grep, gitleaks, zizmor (optional)
                                                                        - each engine as its own process
                                                                        - reports/raw/*.json + execution_manifest.jsonl
                                                                                     |
                                                                                     v
                                                                        prufgate/synthesizer/parse_results.py
                                                                        -> reports/prufgate.sarif, prufgate-review.md,
                                                                           gl-code-quality-report.json, prufgate-junit.xml
                                                                        -> verdict PASSED / FAILED / ERROR, exit 0/1/2
```

## Engines

| Engine | Module | Input |
|---|---|---|
| 1 Anti-fabrication | `prufgate/anti_fabrication/detector.py`, packs in `packs/` | Source files (all, or changed) |
| 2 Test integrity | `prufgate/anti_reward_hacking/test_integrity.py` | Test files, plus the diff for weakening and special-casing |
| 3 Diff guard | `prufgate/diff_guard/tamper_detector.py` | A diff only |
| 4 Contract guard | `prufgate/contract_guard/` | Source files and manifests |
| 5 BOLA | `prufgate/bola/bola_engine.py` | Route handlers; optionally a running service |
| 6 Reviewer | `prufgate/review/reviewer.py`, `ai_adapter.py` | A diff |

Every engine module runs on its own (`python3 prufgate/<engine>/<module>.py --help`) and has a `--self-check` with invented positive and near-miss cases. `prufgate --self-check` runs them all.

## Around the engines

| Module | What it does |
|---|---|
| `prufgate/baseline.py` | Reads `.prufgate/baseline.yaml` (at the base ref in a changed scan) and leaves out the findings it lists. `prufgate check` and the synthesizer both use it, after the debt ceilings, so a baselined finding still counts toward `known_debt`. `prufgate baseline` writes the file. |
| `prufgate/pr_summary.py` | `prufgate pr-summary`: the verdict, the first findings and facts about the change, from `reports/prufgate.sarif`. The GitHub Action writes it to the job summary and, when asked, keeps it as one pull request comment. It reports the result and never changes it. |
| `prufgate/explain.py` | `prufgate explain` and the MCP tool `prufgate_explain`: what each rule catches and how to fix it. A test keeps it in step with `prufgate/rules.py` and `docs/ENGINES.md`. |
| `prufgate/console.py` | Switches output that cannot print PrufGate's characters (Windows sends piped output in cp1252) to UTF-8, so printing a report never crashes a run. |

## Changed files

"Changed" means the diff between a base ref and the working tree, plus untracked files. The base is chosen once (`--base`, `PRUFGATE_BASE_REF`, `origin/$GITHUB_BASE_REF`, then `origin/HEAD`, or `HEAD~1` on a clean tree) and passed to every engine. Git is always run with the workspace as its directory, with `--end-of-options`, and refs that start with `-` are refused.

## Failing closed

A scanner that crashes and reports nothing looks exactly like a clean scan. PrufGate treats every way of not finishing as an error:

- each engine exits 0 (clean), 1 (P0/P1 findings) or 2 (could not run);
- the gate records every step's exit code and duration in `execution_manifest.jsonl` and keeps its log;
- the synthesizer's verdict is ERROR, with exit 2, if any step exited 2 or more, wrote no output or unreadable output, or if the manifest is missing;
- the CLI, MCP server and API pass that through: a failed engine is never reported as `passed`.

## Trust boundaries

- The repository being scanned is untrusted input. PrufGate reads it and never executes it: `.prufgate/rules/` are declarative ast-grep YAML, and `.prufgate/hooks/` scripts run only with `PRUFGATE_ALLOW_REPO_HOOKS=1`.
- Live probing and AI review are the only network traffic, and both need explicit options. Tokens and API keys never reach reports or logs.
- The REST API binds to loopback, needs a bearer token, confines scans to `PRUFGATE_WORKSPACE_ROOT` and verifies webhook signatures.
