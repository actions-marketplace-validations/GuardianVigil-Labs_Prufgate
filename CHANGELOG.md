# Changelog

All notable changes to PrufGate. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.2.0]

### Changed
- **A changed scan judges only what the change touched.** `prufgate check --changed`, `prufgate.sh fast` and the GitHub Action report a finding only when it is on a line the change added or modified (a finding on a block's first line covers the block; a BOLA finding covers its handler). Rules about the diff itself (deleted tests, weakened assertions, skips, suppressions, configuration changes) are unchanged. BOLA reports only the changed route, action and migration files; ast-grep scans only the changed files, zizmor only the changed workflows, and gitleaks only the branch's commits and uncommitted edits. A full scan still reports everything.
- zizmor findings take their severity from zizmor's severity and confidence (only High blocks; Low and Informational are P3), and their line from the primary location, no longer one line too early. ast-grep lines were one too early as well.

### Added
- Engine 5 follows a project's guard wrapper one hop: a call at the top of the handler to a function that calls a recognised guard and refuses the request counts as auth. `auth_guards` still names guards it cannot follow.
- `undocumented-env-var-drift` reads `vars` from `wrangler.toml`, `wrangler.json(c)` and `.dev.vars*`, and accepts a fallback on the variable an env read is assigned to, within three lines.
- `prufgate bola --changed` limits the static checks to changed files.
### Fixed
- `test-input-special-casing` reads only literals from the tests paired with the production file (by import or name, same language), whole quoted tokens only (no Go import blocks, no keys inside JSON blobs), compared with `==`, `===`, `!=`, `in`, `case` or a match arm. A literal production already uses apart from the added lines (at the base, elsewhere in the file, in an untouched file, or in two or more changed files) is vocabulary, not special-casing. Newly caught: a new `case` for a test-only value in an existing `switch`.
- `diff-test-file-deleted` and `diff-assertion-weakening` recognise a test retired with its feature: tsconfig and jsconfig `paths` aliases are resolved, a test is retired when every first-party symbol it imports is gone (shared live helpers don't keep it alive), Go pairs `x_test.go` with `x.go`, and removed assertions on code that left production, or a removed `t.Fatal(err)` setup guard together with its call, are not weakening.
- `self-mocked-unit-under-test` compares the resolved module, not the file name: mocking a package (`@scope/name`) is never mocking the subject.
- `caught-and-ignored-test-exception`: an error stored in a variable that is asserted later is handled. `zero-assertion-test` counts a `throw` inside a JavaScript or TypeScript test as an assertion.
- `unhandled-empty-catch` (JavaScript, TypeScript): a catch returning the function's "no value" answer (`null`, `false`, `undefined`, `{}`) is not empty, nor is a catch whose comment gives a reason, a best-effort release in a `close` / `cleanup` function, a retry loop, a `return` in the try with the failure path below, or a read into a variable that already holds its default. `// ignore` and `// TODO` still fire. Only a catch opened on the reported line is read, so a later one is no longer reported on the wrong line.
- `canned-error-fallback`: an object returned from a catch is canned when it claims success (`ok: true`, `status: "ok"`) or holds only literals and no word of the failure; `{ success: false, error }` and `{ state: "unavailable", reason }` are not. A Go `c.JSON(200, gin.H{...})` that carries `"error"` is not. Newly caught: `promise.catch(() => ({ ok: true }))`.
- `disconnected-form-submit` fires only in a submit handler that does nothing but `preventDefault()`, log or alert, read to the handler's closing brace; keyboard, drag and focus handlers are not forms.
- `documentation-address` accepts a `placeholder` up to three lines above (a multi-line ternary) and "for example" / "e.g." text.
- `stub-click-handler` and `simulated-return-value` ignore code quoted inside a string literal (a help text or a list of examples).
- `test-skip-smuggling` accepts a skip guarded, on the skip expression or its enclosing `if`, by a check of a capability the test needs: `exec.LookPath`, `net.Listen`, `runtime.GOOS`, `shutil.which`, `process.env`, `process.platform` and the like (excluding `CI`).
- `suppression-comment-smuggling` ignores a directive quoted in a string literal. A line-scoped directive that names its rule (`eslint-disable-next-line no-console`) in a test file is a P2 warning; a bare or file-wide one still blocks.
- `unsafe-type-cast-cascade`: a single `as unknown as T` is a P2 warning; `any`, or double casts within five lines of each other, still block. `any` inside a string is not a cast.
- `pr-sql-injection-vector` fires only when `${...}` is inside a template literal that is the query's first argument, not in the bind parameters or a plain string, and now also when that template literal starts on the next line or spans several. `pr-shell-command-injection-risk` and the SQL rule ignore a call quoted inside a string literal.

## [1.1.0]

### Changed
- **Inline ignores need a reason:** `prufgate-ignore: rule -- why`. An ignore without one (at least three characters) no longer suppresses and is reported as `ignore-without-reason`. Every honoured ignore is listed in the report and as a SARIF suppression. An ignore now hides only the rules it names, in every engine.
- **With a base ref, the configuration and baseline are read from the base:** a change to `.prufgate/config.yaml` takes effect after it is merged, and the change itself is reported (`prufgate-config-not-applied`). If the base config is rejected by this version, the branch's config is used and compared with the defaults (`prufgate-config-base-invalid`).
- Review rule IDs are normalised to `pr-` plus lowercase letters, digits and hyphens, the same in Markdown and SARIF.
- `linter-or-ci-config-weakening` compares linter configs (ruff, mypy, tsconfig, eslint, biome, golangci) by value with the base, so new per-file ignores, excludes, disabled rules and shrunk `select` lists are caught wherever they sit in the file.

### Added
- Fuzz targets for the config loader, the diff parsers and the source and test scanners (`fuzz/`), run by ClusterFuzzLite on pull requests.
- Each release attaches `<file>.intoto.jsonl` with the wheel's and sdist's signed attestations, for offline verification.
- Test-cheat rules in the diff: `test-fake-exit` (an exit or module-level skip added to tests, conftest or test setup), `diff-test-file-deleted` (including a rename to a name the test runner doesn't collect) and `diff-test-count-drop`.
- `prufgate shell-guard` and `prufgate hook <agent> <event>`: fail-closed hooks for Claude Code, Cursor, GitHub Copilot, Codex and Gemini CLI. They block skipping git hooks (`--no-verify`, `core.hooksPath`, `HUSKY=0`), force pushes, and removing or editing tests, CI files, PrufGate's config or the agents' own hook config. `prufgate init --agent NAME` writes the hook configuration.
- `.pre-commit-hooks.yaml`: `prufgate` (staged changes, pre-commit) and `prufgate-full` (pre-push).
- A confidence level (high, medium, low) on every rule and finding, in JSON, Markdown and SARIF (`precision`). Low-confidence rules are off unless `enable_low_confidence: true`.
- An opt-in registry check for newly added dependencies (`registry_check: true`): `dependency-not-on-registry`, `dependency-recently-published` and `dependency-typosquat` for npm, PyPI, crates.io and Go modules, with a local cache. It fails closed when a lookup fails, unless `offline_ok` is set.
- Stable SARIF `partialFingerprints` (GitHub's `primaryLocationLineHash`), so code scanning tracks an alert across commits.
- Test-harness rules in the diff: `test-runner-monkeypatch`, `always-true-equality`, `pytest-result-rewrite`, `pytest-collection-deselect`, `test-config-weakening` and `test-script-neutered`.
- `prufgate verify --differential`: runs the base branch's tests against the head code in a temporary worktree and reports `differential-base-tests-fail`. It executes repository code, so it runs only with `--allow-run-tests` (or `PRUFGATE_ALLOW_RUN_TESTS=1`), with a scrubbed environment and a timeout.
- `undocumented-env-var-drift` also counts variables declared in zod and pydantic-settings schemas, docker-compose, Kubernetes and Helm manifests, and workflow `env:` blocks.
- `prufgate init --agents-md` and `--bugbot` write a marked section telling other agents and AI reviewers to use PrufGate's findings.
- A Claude Code plugin: `/plugin marketplace add GuardianVigil-Labs/Prufgate`, then `/plugin install prufgate@prufgate`.
- GitLab Code Quality and JUnit reports: `--format gitlab|junit`, and `reports/gl-code-quality-report.json` and `reports/prufgate-junit.xml` from the batteries.
- `prufgate check --ai-adjudicate`: an AI provider judges only low-confidence findings (yes/no) and can only dismiss them. It runs only when the base config enables `ai_adjudicate`. Never runs from the hooks, the MCP server or the API. Errors keep the finding.
- `prufgate bench`: a labelled corpus of 90 invented cases with measured precision and recall (`docs/BENCHMARK.md`).
- `prufgate bola --routes-from FILE`: extra route paths for the live probe from an OpenAPI, Postman or HAR file (GET and HEAD only, joined onto `--url`; hosts, headers and credentials in the file are ignored).
- BOLA static checks cover Laravel implicit route-model binding, tenant values traced through local variables, Django generic views and DRF viewsets, NestJS global guards, Spring global and method security, Express/Fastify app-wide middleware and Rails member routes. `bola.global_tables` lists tables shared by every tenant.
- `prufgate.pyz`: a reproducible single-file build (Python 3.9+), signed and attached to each release.
- `ghost-symbol`: an added import or call names something the target module doesn't define (first-party Python and relative TS/JS imports; installed Python packages read from source with `ghost_symbols: {third_party: true}`, never imported).
- `prufgate fix`: deterministic fixes for safe cases (focused or unjustified skipped tests, a deleted or weakened assertion, an ignore without a reason, `|| true` / `continue-on-error` in CI), as a patch, `--apply`, or GitHub suggestions. Each fix is checked to clear its finding.
- `prufgate transcript FILE`: reads Claude Code, Codex or plain shell transcripts and reports git-history lookups, hook bypasses and test or CI tampering by the agent. Passwords, tokens, URL credentials and auth headers in a reported command are redacted.
- `prufgate export-rules --format semgrep`: the single-file pattern rules as Opengrep/Semgrep YAML.
- `prufgate verify --mutation`: runs an installed mutation tool (mutmut, Stryker, PIT, gremlins or go-mutesting, cargo-mutants) on the changed lines and reports `mutation-survivor` and `mutation-no-coverage`. It executes repository code, so it shares differential verify's opt-in, sandbox and cleanup; reports committed to the repository are ignored, and a tool failure or no mutants on changed lines is an error, never a pass.
- A role matrix for the live probe: `prufgate bola --url URL --roles FILE` checks which of the operator's own test roles may reach which routes (GET and HEAD, tokens from environment variables, redirects counted as denials) and reports `bfla-role-allowed`.
- A VS Code extension (`editors/vscode`): findings as editor diagnostics from the installed CLI, off in untrusted workspaces, with a machine-scoped CLI path.

### Fixed
- Benchmark misses: hard-coded success in Python and Go error paths, a bare `except: pass`, `jest || true` in a one-line scripts object, a replaced `assertEqual`, an empty inline snapshot, and more. A parametrised test merge no longer reads as a test-count drop, and a test removed together with the production module it imports is not reported.
- A test deleted with a helper module, a fixtures file, a package `__init__.py` or a Go `doc.go` it shares a package with is reported again: the retired-feature exemption now needs every first-party module the test imports deleted (Go: every non-test file of the package), and none of their names re-defined elsewhere in the diff.
- `diff-test-count-drop`: duplicate parametrize or `it.each` cases count once, cases the test body never uses count as one, parametrize cases above a helper no longer multiply the next test, and cases cut far from the test's definition line count (the modified file is counted whole).
- `unhandled-empty-catch` and `canned-error-fallback` also read `except (Exception,):` and other tuples naming `Exception`, and a comment line inside a handler no longer ends it. `except Exception: pass` inside a `close`, `cleanup`, `shutdown`, `teardown`, `dispose`, `__exit__` or `__del__` function is not reported.
- `test-script-neutered` checks every test script on a one-line `"scripts"` object, not only the first.
- `test-input-special-casing` no longer treats dunder names such as `__main__` as test input.
- A `.prufgate/config.yaml` with a non-string top-level key (for example a bare `?`) crashed with a `TypeError` instead of a configuration error. Found by fuzzing.

### Security
- The live BOLA probe refuses cloud-metadata, link-local and non-HTTP targets on every path (CLI, batteries, MCP, API and running the engine directly).
- The container's base images are pinned by digest, and every `pip install` in the image and the workflows uses hash-locked requirements.
- The container and fuzz builds use setuptools 84.2.1 (CVE-2026-59890, GHSA-xmj3-9gf7-h52w), and install PrufGate from a locally built wheel.

## [1.0.0]

The first public release: six verification engines (anti-fabrication, test integrity, diff guard, contract guard, BOLA/IDOR and diff review), the `prufgate` CLI, a GitHub Action, an MCP server, coding-agent hooks and a container image. The Changed, Fixed and Security entries are against the pre-release development versions.

Distribution: `pip install prufgate` (or `pipx install prufgate`), the image `ghcr.io/guardianvigil-labs/prufgate:1.0.0`, and the Action `GuardianVigil-Labs/Prufgate@v1.0.0`. Releases are built from a tag by `.github/workflows/release.yml`: PyPI Trusted Publishing, a keyless Sigstore signature on the image, SLSA build provenance and an SBOM for the wheel and the image (see "Verify a release" in `SECURITY.md`).

### Added
- `prufgate` CLI (`check`, `fast`, `full`, `test-audit`, `bola`, `review`, `init`, `mcp`, `api`, `--self-check`, `--version`) and `.prufgate/config.yaml`.
- Test-integrity analysis for PHP, C# and Ruby, and canned-error rules for Java, Kotlin, C#, PHP and Ruby.
- Diff-guard rules `coverage-threshold-lowering` and `prufgate-config-self-exemption`.
- BOLA analysis of Rails and Laravel controllers, Sequelize and Mongoose lookups, and per-handler auth checks.
- A structural leak guard (`tests/test_public_repo_hygiene.py`) and workflow pin checks (`tests/test_workflows.py`).
- The PrufGate logo in `assets/`, in the shared GuardianVigil open-source tile and blue (`#05070a` tile, `#1d232d` hairline, `#2f80ff` glyph): the code-shield icon (SVG, with thicker variants for 16 and 32 pixels, and PNGs from 16 to 1024), the mark on its own for dark and light backgrounds, a lockup with the wordmark, and a 1280x640 social preview.

### Changed
- Exit codes are the same everywhere: 0 clean, 1 P0/P1 findings, 2 error. The BOLA engine, the contract guard and the reviewer used to exit 0 on findings.
- Threat-intelligence rules moved to the opt-in `cti` pack.
- Two architecture-specific ast-grep rules became opt-in examples in `configs/ast-grep/examples/`.
- Container downloads are pinned and checksum-verified.
- Workflows publish only from a version tag or a manual run, and every action is pinned to a commit SHA.
- The `multi-tenant` pack is removed: no engine read it. A config that still lists it is rejected; Engine 5 always runs.
- The container image no longer installs `curl`; the docs state its real size (about 460 MB, about 100 MB gzipped).
- The container runs Python 3.14 (newest stable series with PyYAML wheels; 3.15 has none yet).

### Fixed
- Test-input special-casing no longer reads version pins in requirements, lock and other data files as production branches.
- The gate, CLI, MCP server and API reported success when an engine crashed or wrote no output. They now report an error (exit 2).
- `--changed` scanned nothing on a clean CI checkout, and missed untracked files.
- Path filters matched substrings, so folders such as `checkout/`, `contest/` or a checkout under `build/` were skipped.
- Live BOLA tokens appeared in report `curl` examples.
- The PR reviewer could emit injected workflow commands, and comment-only suggestions that deleted code.
- Python 3.9 compatibility, and standard-library modules flagged as undeclared imports on 3.9.
- In the changed scope the contract guard read only uncommitted files or the last commit; it now uses the same base ref as the other engines, from `prufgate check`, the gate and the MCP tool.

### Security
- The diff guard compares the configuration in effect on the branch with the one in effect at the base, by value, so no YAML spelling, file location, shadowing config or `.gitattributes` can hide a change. A new exclusion, exemption, known debt or raised ceiling, a dropped pack, a narrowed language list or a widened guard list is a P1 `prufgate-config-self-exemption` finding; an exclusion covering every file or the configuration itself (`**`, `.prufgate/**`) is P0. The configuration under review cannot exclude, exempt or set a debt ceiling for that finding. A branch could previously switch PrufGate off with `exclude: ["**"]` and pass. Diffs are read with `--text --no-ext-diff --no-textconv`.
- The scanned repository's `.prufgate/hooks/` scripts no longer run by default (`PRUFGATE_ALLOW_REPO_HOOKS=1` opts in).
- Arguments that start with `-` are refused as git refs.
- `review --ai` runs local agent CLIs one-shot, with the least tool access each offers, in a fresh private directory, with the diff on stdin; `auto` picks only `claude` (every tool off). An AI review that did not run is reported on stderr.
- Live BOLA probes follow redirects only within the target origin. A redirect to another origin is not followed and is reported as `BOLA-PROBE-REDIRECT-REFUSED` (P1), so untested routes never pass silently.
