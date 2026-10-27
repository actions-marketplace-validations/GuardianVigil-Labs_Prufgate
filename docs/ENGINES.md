# The engines

Each engine can run alone (its module has a command line and a `--self-check`), through `prufgate check`, or as a step of the `prufgate.sh` gate. Every rule has invented positive and near-miss fixtures in its engine's self-check or in `tests/`.

All engines use pattern and structure heuristics over source text, not a compiler front end for each language. That keeps PrufGate fast and dependency-free, and it means two things: an unusual code shape can slip past a rule, and correct code can occasionally be flagged. Report either with a minimal invented sample (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

Suppressions, exemptions and baselines are described in [CONFIGURATION.md](CONFIGURATION.md#suppressing-findings). Every engine reads inline `prufgate-ignore` comments the same way: one honours only an ignore that carries a reason (`-- why`), the report lists each one it honoured, and an ignore without a reason is reported as `ignore-without-reason` (P2) while the finding it names stays.

Every rule has a confidence (`high`: an exact structural match; `medium`: a heuristic with known false positives; `low`: a fuzzy or naming-based heuristic), shown in the tables below. Low-confidence rules are off by default: not reported and not blocking until `enable_low_confidence: true` (see [CONFIGURATION.md](CONFIGURATION.md#confidence)).

## Engine 1: anti-fabrication

`prufgate/anti_fabrication/detector.py`. Production code that compiles but fakes its result. Test files, fixtures and build output are skipped.

Languages: TypeScript, JavaScript (including `.vue` and `.svelte`), Python, Go, Rust, Java, Kotlin, PHP, Ruby, C#. Not every rule applies to every language; error-path rules cover all of them.

| Rule | Confidence | What it flags |
|---|---|---|
| `canned-error-fallback` | medium | A `catch` / `except` / `rescue` / `if err != nil` that returns a hard-coded success value. |
| `route-canned-fallback` | medium | An API route that answers a failed upstream call with canned data. |
| `unhandled-empty-catch` | medium | An error swallowed with nothing done about it: an empty JavaScript/TypeScript `catch`, or a Python `except:` / `except Exception:` whose body is only `pass`. |
| `verdict-on-error-path`, `score-on-error-path` | medium | A decision or score produced on an error path. |
| `score-outside-scoring` | medium | A score computed outside the files listed in `score_owners`. |
| `simulated-return-value` | medium | A literal returned under a comment admitting it is simulated or a placeholder. |
| `fake-named-data` (`demo-named-data`) | low | `MOCK_*`, `FAKE_*`, `DUMMY_*`, `SAMPLE_*`, `fallbackData` and similar in production code. |
| `synthetic-delay-mock` | medium | A sleep or timer paired with a hard-coded result, faking asynchronous work. |
| `stub-click-handler`, `disconnected-form-submit` | high | UI handlers that do nothing, or a submit that only calls `preventDefault()` (pack `web-ui`). |
| `always-current-fake-timestamp`, `invented-event-timestamp` | medium | "Now minus a fixed offset" computed at read time, so static data looks fresh. |
| `asserted-state` | low | A status literal asserted rather than derived. |
| `unimplemented-production-stub` | high | `NotImplementedError`, `todo!()`, `panic("not implemented")`, `throw new Error("TODO")` in reachable code. |
| `prompt-invents-finding` | medium | An LLM call asked for a structured decision (score, verdict, severity) with no runtime evidence in the prompt (pack `ai-safety`). |
| `documentation-ip-or-domain` (`documentation-address`) | high | RFC 5737 / RFC 3849 addresses or `example.com` served from production code. |
| `stale-exemption`, `debt-ceiling-breached` | high | Config hygiene: an exemption that matches nothing, or a `known_debt` ceiling exceeded. |

Opt-in pack `cti` (threat-intelligence products): `zero-jarm-as-fingerprint` and `empty-input-digest-as-sample` (high); `hardcoded-cve`, `hardcoded-attribution`, `ui-verdict-literal`, `substring-decides-verdict` and `llm-generated-intel` (medium); `keyword-selected-attribution` (low).

## Engine 2: test integrity

`prufgate/anti_reward_hacking/test_integrity.py`. Tests that cannot fail, which is how an agent turns a red build green without fixing anything.

Languages and frameworks: Python (pytest, unittest), JavaScript/TypeScript (Jest, Vitest, Mocha, node:test, Playwright), Go (`testing`), Rust (`#[test]`), Java/Kotlin (JUnit), PHP (PHPUnit, Pest), C# (xUnit, NUnit, MSTest), Ruby (RSpec, Minitest).

| Rule | Confidence | What it flags |
|---|---|---|
| `zero-assertion-test` | medium | A test that runs code and asserts nothing. Pytest fixtures named `test_*` are not tests. |
| `tautological-assertion` | high | `assert True`, `expect(true).toBe(true)`, `assertEqual(x, x)`, or an existence check as the only assertion. |
| `self-mocked-unit-under-test` | medium | A test that mocks the module it is testing, or asserts a mock's own return value. |
| `caught-and-ignored-test-exception` | medium | A test that catches the failure it should report. |
| `snapshot-blind-update-or-empty` | high | Empty or unfilled (`toMatchInlineSnapshot()`) inline snapshots, or snapshots updated without review. |
| `diff-assertion-weakening` | medium | A diff that deletes assertions or widens what is accepted (for example `== 200` becoming `in (200, 500)`). |
| `test-input-special-casing` | medium | A diff where production code gains a branch for the exact literal a test passes in. |
| `diff-test-file-deleted` (P1) | high | A diff that deletes a test file whose tests are not added back anywhere. A git rename is not a deletion, nor is a file whose test names all reappear in another file (or, for languages whose test names are not read, a new test file of the same name). A test retired with its feature is not reported either: one that imports a production module the same diff deletes (Python imports, relative JavaScript/TypeScript imports, or for Go a deleted non-test file in the same package directory). |
| `diff-test-count-drop` (P1) | medium | A diff that removes more test cases than it adds, counted across every file: Python `def test_*` (functions and unittest methods), JavaScript/TypeScript `it(`/`test(` with a string title, Go `func Test*` (not `TestMain`). A parametrised test counts once per case: `@pytest.mark.parametrize` with a literal list (stacked decorators multiply), `it.each([...])` / `test.each([...])` with an array, and a Go test running a literal table with `t.Run`; cutting cases from one lowers the count. A test that is renamed or moved to another file keeps the count. Tests in a deleted file already reported by `diff-test-file-deleted` are not counted twice. |

The two removal rules see only the diff. When a removal is intended and not recognised above (for example cases moved into a list held in a variable), acknowledge it with an `exempt` entry for the path and rule, with a reason; engine 3 reports the new exemption as `prufgate-config-self-exemption`, so the reviewer sees it. Remove the entry once the change has merged:

```yaml
exempt:
  - { path: tests/test_refunds.py, rule: diff-test-file-deleted, reason: "#42: refunds feature removed" }
```

## Engine 3: diff guard

`prufgate/diff_guard/tamper_detector.py`. Works on a diff (`--changed`, `--base REF` or `--diff-file`), so it sees only what was added. It is language-independent where it can be.

| Rule | Confidence | What it flags |
|---|---|---|
| `test-skip-smuggling` | high | Skips and focus added without an issue reference: `.skip`/`.only`/`xit`/`xdescribe`, `this.skip()`, `t.skip()`, `pytest.mark.skip`/`xfail`, `unittest.skip`, `t.Skip()`, `#[ignore]`, `@Disabled`, `[Fact(Skip=...)]`, `[Ignore]`, `markTestSkipped`, RSpec `xit`. |
| `test-fake-exit` (P0) | high | An exit with status 0 added to a test file, `conftest.py`, a Jest/Vitest/Playwright/Mocha setup or config file, or any code file under a `tests`/`test`/`__tests__`/`spec` folder, which makes the run report success without running the tests: Python `sys.exit(0)`, `os._exit(0)`, `exit()`/`quit()`, `raise SystemExit`, `pytest.exit(returncode=0)`, or an unindented `raise SkipTest` / `pytest.skip(...)` (honours an issue reference); JavaScript/TypeScript `process.exit(0)`; Go `os.Exit(0)` (for example in `TestMain` in place of `os.Exit(m.Run())`). Not flagged: a non-zero or computed status (`sys.exit(main())`), exits under `if __name__ == "__main__":`, exits a test expects (`pytest.raises(SystemExit)`, `assertRaises(SystemExit)`, `expect(...).toThrow()`), and files outside the test tree. |
| `test-runner-monkeypatch` (P0) | high | The test runner or its assertions replaced. Python: an assignment, `setattr`, `object.__setattr__` / `type.__setattr__`, `patch.object`, `patch("...")` or `monkeypatch.setattr("module.attr", value)` on `unittest` / `pytest` / `TestCase` internals (`unittest.TestCase.assertEqual = ...`, `pytest.approx = ...`; not `maxDiff`, `longMessage` or `unittest.util._MAX_LENGTH`), on `builtins.isinstance`, `builtins.AssertionError` and similar, or on `sys.modules["pytest"]`, through import aliases and names bound once to a constant; `self.assertEqual = ...` in a test file; an `assert*` / `fail*` method of a `TestCase` subclass overridden with a body that only returns a constant or an argument. JavaScript/TypeScript test and setup files: `global.expect = ...`, `globalThis["expect"] = ...`, `Object.assign(globalThis, { expect })`, `Object.defineProperty(globalThis, "expect", ...)`, `expect = ...`, `const expect = () => ...` (not `const expect = chai.expect`), `expect.x = ...`, chai `Assertion.prototype.x = ...` or `["x"] = ...`, `vi.mock("vitest")`, and `expect.extend` matchers whose every `pass` is a truthy constant. |
| `always-true-equality` (P1) | medium | `__eq__` returning True or `__ne__` returning False for any input: a `def` or `lambda` in the class body (including when the class line is outside the hunk), `Money.__eq__ = lambda ...` or `setattr(Money, "__eq__", ...)`, and bodies such as `return x or True`. `__bool__` is not checked, since every object is truthy by default. The `mock.ANY` idiom is allowed only when exact: a class in a test file named `Any`, `Any<Capitalised>`, `<X>Anything`, `<X>Matcher` or `<X>Wildcard` (case-sensitive), or a subclass of `unittest.mock._ANY`. The same name in application code is flagged. |
| `pytest-result-rewrite` (P0) | high | In pytest plugin files only (`conftest.py`, `pytest_*.py`, or a file defining `pytest_*` hooks, using `hookimpl` or setting `pytest_plugins`): a report's `outcome` set to `"passed"` (or `"skipped"` in `pytest_runtest_makereport`) by assignment or `setattr`, `exitstatus` forced to 0 or `ExitCode.OK`, the `failed` / `error` entries of the terminal stats dropped, or `pytest_pyfunc_call` / `pytest_runtest_call` returning True without running the test. The same names in application code are not flagged. |
| `pytest-collection-deselect` (P1) | medium | In pytest plugin files: `pytest_collection_modifyitems` removing collected items (`clear`, `pop`, `remove`, `del`, slice assignment, `-=`, `config.hook.pytest_deselected`, with `items` found by name) or marking every item skip / xfail with no condition; `pytest_ignore_collect` returning True for every path or a condition naming test files; `collect_ignore` / `collect_ignore_glob` in a `conftest.py` listing test files, or any path when the conftest is under a test directory (not build, docs, fixture and similar directories). A conditional opt-in marker (`--runslow`) is not flagged. |
| `test-config-weakening` (P1) | medium | A change that narrows the test run. pytest (`pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini`, in the pytest section): `addopts` gaining `-k`, `-m`, `-p no:<plugin>` (not `cacheprovider` and similar), `--deselect`, `--ignore` (not docs or build directories), `--continue-on-collection-errors` or `--collect-only`; `testpaths` / `python_files` / `python_classes` / `python_functions` losing entries; new `norecursedirs` entries. Jest (`jest.config.*`, the `package.json` `jest` key): `passWithNoTests`, `roots` / `testMatch` / `testRegex` narrowed or emptied, new `testPathIgnorePatterns` entries, `silent` with `forceExit`. Vitest (`vitest.config.*`, `vite.config.*`, `vitest.workspace.*`): `include` / `exclude` in the `test` block only, not `coverage` or `optimizeDeps`. With a base, TOML, INI and JSON files are compared by value (an entry added on its own line counts); JavaScript configs and runs without a base use the line check. Ignore entries for dependencies, build output, docs, fixtures and end-to-end suites are not flagged. Removing `bail` is not flagged: it makes the run report more failures, not fewer. |
| `test-script-neutered` (P0) | high | A `package.json` `test` / `test:*` script whose exit status cannot reflect a failure: only `exit`, `true`, `:` or `echo`, `\|\| true`, `\|\| echo`, `\|\| exit 0`, `; exit 0`, or a pipe (`\| cat`, `\| tee`) without `pipefail`; a `test` script running lint commands only. A Makefile `test`/`check`/`unit`/`integration`/`coverage`/`ci` recipe judged as a whole: flagged when no line can fail (a `-` prefix, a swallowed status, a pipe without `pipefail`, `echo` only), including when the runner line is deleted; a target with prerequisites is not flagged, since they can fail. A tox command that cannot fail (`- cmd`, `\|\| true`, `ignore_outcome = true`); nox `success_codes` that accept 1. npm's default `echo "Error: no test specified" && exit 1` is not flagged. |
| `suppression-comment-smuggling` | high | `@ts-ignore`, `@ts-expect-error`, `eslint-disable`, `biome-ignore`, `# noqa`, `# type: ignore`, `// nolint`, `#[allow(...)]`, `@SuppressWarnings`, `prufgate-ignore`, added without a justification (`-- reason`) or issue reference. |
| `unsafe-type-cast-cascade` | high | `as unknown as T`, `as any`, `cast(Any, ...)`, unjustified `unsafe` blocks. |
| `linter-or-ci-config-weakening` | medium | Linter and type-checker config compared by value with the base (TOML: `ruff.toml`, `.ruff.toml`, `pyproject.toml` `[tool.ruff]` / `[tool.mypy]`; JSON or JSONC: `tsconfig*.json`, `biome.json(c)`, `.eslintrc(.json)`; YAML: `.golangci.yml`, `.eslintrc.yml`), wherever the entry sits in the file: new `ignore`, `extend-ignore`, `exclude`, `extend-exclude`, `disable`, `ignorePatterns`, `exclude-dirs`, `exclude-rules` or golangci `exclusions` entries; new `per-file-ignores` / `extend-per-file-ignores` keys or new codes under an existing key; entries removed from `select`, `extend-select` or `enable`; a strictness flag set to its lax value (`strict`, `noImplicitAny`, `disallow_untyped_defs`, `ignore_errors = true` including inside an existing `[[tool.mypy.overrides]]` block, `recommended: false`, `disable-all: true`; `skipLibCheck: true` is P2) or an explicit strict value removed; an eslint or biome rule turned `off` / `0`, also inside `overrides`. A tsconfig `exclude` counts only for source or test paths (`src`, `tests`, `*.test.*`), not build output. The message names the entries. A new config file is compared with an empty one; tightening is not flagged. Without a base (a diff file), for files that cannot be parsed at either side (INI files, JavaScript configs, invalid syntax) and for TOML on Python 3.9 and 3.10 (no `tomllib`), each added line is matched instead: `"strict": false`, `ignore = [`, rules turned off. In CI config: `continue-on-error: true`, `allow_failure: true`, `\|\| true`. |
| `coverage-threshold-lowering` | high | A lowered `fail_under` or Jest/Vitest coverage threshold. |
| `prufgate-config-self-exemption` | high | The configuration in effect loosened compared with the base, compared by value (any YAML spelling, location or shadowing file): new exclusions, exemptions, known debt or higher ceilings, dropped packs, fewer languages, more auth guards, tenant keys, score owners or evidence markers, low-confidence rules, the registry check or the third-party ghost-symbol check turned off, or `registry_check.offline_ok` turned on (P1); an exclusion covering every file or the config itself, such as `**` (P0). The config under review cannot exclude, exempt or set a debt ceiling for this finding. Without a base (a diff file), the diff lines of the config are checked instead. With a base ref the branch's config is not applied at all (every engine uses the base's), and the finding says so. |
| `prufgate-config-not-applied` | high | P2, informational: with a base ref, the change edits or introduces the PrufGate configuration or baseline. The run applied the base's (or the defaults) and ignored the branch's: configuration changes take effect after merge. |
| `prufgate-config-base-invalid` | high | P2, informational: this version rejects the configuration at the base, so the run applied the branch's (which must be valid). The diff lines of the configuration are still checked. |

An issue reference is `#123`, `ABC-123` or an issue URL. Acronyms such as `UTF-8` and `SHA-256` do not count.

## Engine 4: contract guard

`prufgate/contract_guard/`. Things that look plausible in a diff but do not exist.

| Rule | Confidence | What it flags |
|---|---|---|
| `undeclared-or-hallucinated-import` | medium | An import of a package declared in none of `package.json`, `pyproject.toml` (dependency tables only), `requirements*.txt` / `requirements/`, `go.mod`, `Cargo.toml`. Standard-library modules, relative imports and local packages are not flagged. A hallucinated or typo-squatted name is how a malicious package gets installed. |
| `ghost-symbol` | high | A name that its module does not define: `from shop.billing import charge_card` when `shop/billing.py` has no `charge_card`, a call such as `billing.charge_card(...)` on an imported module, or `import { charge } from "./billing"` when `./billing.ts` exports no `charge`. A hallucinated API. P1. See [ghost symbols](#ghost-symbols). |
| `undocumented-env-var-drift` | high | `process.env.X` (unless a fallback follows: `?? 5000`, `\|\| 5000` or a ternary, after the read or on its variable within three lines, as in `const n = Number(process.env.X);` then `return n > 0 ? n : 5000;`), `os.environ["X"]` / `os.getenv("X")` without a default, `os.Getenv("X")`, `env!("X")`, when `X` is missing from `.env.example` (or `.env.sample`, `.env.template`) and from every config schema and deploy manifest (below). |
| `frontend-backend-route-mismatch` | medium | `fetch("/api/...")` / `axios.*("/api/...")` to a path that no backend route or OpenAPI spec defines. |

### Ghost symbols

With `--changed`, only added lines are checked (against the merge base with the base ref, otherwise `HEAD`; an untracked file counts as wholly added). A full scan checks every line. Nothing from the scanned repository or from an installed package is imported or run: modules are located with `importlib.machinery.PathFinder.find_spec`, which unlike `importlib.util.find_spec` never imports a parent package, and read with `ast`.

- **Python in the repository.** Absolute imports resolve from the repository root, `src/` and the importing file's folder; relative imports from the file's package. A name counts as defined when the module has a top-level `def`, `class`, assignment, import or `__all__` entry for it, including inside `if`/`try` blocks (both branches count), or a submodule of that name. `module.attr(...)` is checked for modules bound by `import a.b`, `import a.b as m` or `from a import b`, unless the name is bound again anywhere in the file.
- **Third-party Python (opt-in).** `ghost_symbols: {third_party: true}` in the configuration, or `--ghost-third-party` on `prufgate/contract_guard/__init__.py`, also checks packages installed in the environment of the interpreter running PrufGate (standard-library modules are not checked). A `.pyi` stub beside a module is read in preference to its source. The result depends on that environment, so CI must install the project's dependencies before the gate runs; a package that is not installed is not checked.
- **TypeScript/JavaScript in the repository.** `import { a, b as c, type D } from "./relative"` resolves `.ts`, `.tsx`, `.mts`, `.cts`, `.d.ts`, `.js`, `.jsx`, `.mjs`, `.cjs`, `index.*` and `./x.js` written for `x.ts`. Exports are read from `export function/class/const/let/var/type/interface/enum/namespace`, `export { a, b as c }` and `export * as ns from`, following `export * from "./other"`.

Unknown is never a finding: a star import, a module-level `__getattr__`, `globals()`/`vars()` in the module, a namespace package, a compiled module without a stub, a module outside the repository (third-party mode off), CommonJS exports (`module.exports`, `exports.x`, `export =`), `export * from` a package or a file that cannot be resolved, and import paths through aliases (`@/lib`) all produce nothing.

### Where environment variables count as documented

`undocumented-env-var-drift` runs when the repository has an example env file (`.env.example`, `.env.template`, `.env.sample`, `.env.defaults`). A variable is documented when any of these declares it:

| Source | Files read | What counts |
|---|---|---|
| Example env files | the files above, at the root | `KEY=` lines, commented or exported |
| zod | JS/TS files whose name contains `env` (`src/env.ts`, `env.mjs`) | upper-case keys whose value starts with `z.`, in `z.object({...})` or t3-env `createEnv({ server, client })`. Comments are ignored. |
| pydantic-settings | Python files whose name contains `settings`, `config`, `conf` or `env` | fields of `BaseSettings` subclasses (also subclasses of those in the same file), read with `ast`: `env_prefix` from `model_config = SettingsConfigDict(...)` or a v1 `class Config`, upper-cased. `Field(alias=..., validation_alias=..., env=...)` and `AliasChoices(...)` replace the prefixed name. |
| docker-compose | `docker-compose*.y*ml`, `compose*.y*ml` | `environment:` in list (`- KEY=value`, `- KEY`) and map form, and the `KEY=` lines of each `env_file:` inside the repository |
| Kubernetes | YAML under `k8s/`, `kubernetes/`, `kube/`, `manifests/`, `deploy/`, `deployment(s)/`, `helm/`, `charts/`, `kustomize/`, `infra/` | `env: - name:`; `envFrom` adds the keys (with `prefix`) of a ConfigMap or Secret defined in a scanned manifest |
| Helm | `values*.yaml`; files under a `templates/` directory | `env:` blocks in values; in templates, `- name: UPPER_CASE` lines (Kubernetes object names are lower case) |
| GitHub Actions | `.github/workflows/*.yml` | workflow, job and step `env:` maps |
| Cloudflare Workers | `wrangler.toml`, `wrangler.json`, `wrangler.jsonc`, `.dev.vars*` | `[vars]` and `[env.<name>.vars]` tables (and inline `vars = { ... }`) in TOML; `vars`, top level and under each `env.<name>`, in JSON with comments; `KEY=` lines in `.dev.vars` files |

Schemas and manifests only add documented names: on their own they do not switch the rule on. Files over 1 MB, test paths and `exclude` paths are skipped. Multi-document YAML is read with `yaml.safe_load_all`. A file that cannot be read or parsed (malformed YAML) is skipped with a `contract_guard: warning:` line on stderr, the same way an unreadable `.env.example` is skipped: a skipped source can only add findings, never hide one.

`envFrom` that names a ConfigMap or Secret not defined in the repository (created by hand, by an operator or by a secret manager) cannot be resolved, so drift for that workload is unknown. It is treated conservatively: it documents nothing, and variables the workload reads still need another source (or an inline ignore with a reason). Otherwise adding any `envFrom` would silence the rule.

There is no reverse rule (declared but never read): zod and pydantic read variables through the library, and compose and Kubernetes variables are often read by the image, not by repository code, so it would not be precise.

The import check runs only for ecosystems that have a manifest in the repository. In the changed scope it reads the same changed files as the other engines: the diff against the chosen base ref, plus untracked files.

### Registry check for new dependencies (opt-in)

An import of a package that the agent also added to the manifest passes the import check, even when the name was hallucinated. With `registry_check: true` in the configuration (or `PRUFGATE_REGISTRY_CHECK=1`), engine 4 compares the manifests at the base ref (the merge base with `--base` / `PRUFGATE_BASE_REF`, otherwise `HEAD`) with the working tree, and looks up each newly added name on its public registry:

| Rule | Severity | Confidence | What it flags |
|---|---|---|---|
| `dependency-not-on-registry` | P0 | high | The registry has no such package (or an npm package that was unpublished, or a PyPI project with no files). An attacker can register the name and wait for the install. |
| `dependency-recently-published` | P1 | medium | The first release is younger than `max_age_days` (default 30). npm, PyPI and crates.io only: the Go module proxy gives no cheap first-release date. |
| `dependency-typosquat` | P1 | medium | The name differs from a popular package only in `-`, `_` or `.`, or by one edit (two for names of 8 characters or more; swapping two neighbouring letters counts as one). Names under 4 characters are not compared. |

Manifests read: `package.json` (registry versions only, not `file:`, `git`, `workspace:` or `user/repo`; an `npm:` alias is looked up under the name it installs), `pyproject.toml` and `requirements*.txt` (not URLs or `name @ url` references), `Cargo.toml` (not `path`, `git` or `workspace = true` dependencies), `go.mod` (`require` lines).

| Ecosystem | Lookup |
|---|---|
| npm | `https://registry.npmjs.org/<name>`: 404 means missing; `time.created` is the first release. |
| PyPI | `https://pypi.org/simple/<name>/` with `Accept: application/vnd.pypi.simple.v1+json` (the JSON API's `releases` key is deprecated): 404 means missing; the oldest file `upload-time` is the first release. |
| crates.io | `https://crates.io/api/v1/crates/<name>` with a `User-Agent`, at most one request a second: 404 means missing; `crate.created_at` is the first release. |
| Go | `https://proxy.golang.org/<module>/@v/list` (upper case escaped as `!` + lower case): 404 or 410 means missing. |

Network policy:

- **Off by default**, because it needs the network and PrufGate also runs air-gapped.
- Fixed HTTPS hosts only, redirects only to HTTPS, no credentials, a 10-second timeout, and at most `max_lookups` (default 50) lookups per run; more new names than that stop the run.
- **Fails closed.** A lookup that fails (network error, rate limit, 5xx, an answer that cannot be read) stops engine 4 with exit 2, unless `offline_ok: true`, which prints the names it could not check and goes on.
- Results are cached for 24 hours in `$XDG_CACHE_HOME/prufgate/registry.json` (default `~/.cache/prufgate/registry.json`); the cache is never written inside the scanned repository, and a cache that cannot be written is skipped.
- It needs a git repository and a usable base: without one the run stops with exit 2.

The popular-name list is short and bundled in `prufgate/contract_guard/registry_check.py`, hand-picked from the top of each registry's public download rankings (npm, the top-pypi-packages list for PyPI, crates.io sorted by downloads) and widely used Go modules. Engine 3 reports a diff that turns the check off or sets `offline_ok` (`prufgate-config-self-exemption`).

## Engine 5: BOLA / IDOR

`prufgate/bola/bola_engine.py`. Broken object-level authorisation: a handler loads a record by an ID the client controls, without checking that the caller may see it.

Static analysis discovers routes in OpenAPI specs, Express/Fastify, NestJS, Next.js (App and Pages router, server actions), FastAPI, Flask, Django function views, Django generic views and DRF viewsets, Go (net/http, Gin, Echo, Chi), Spring, Rails controllers and Laravel controllers. Each handler is checked on its own, up to the next route:

- **missing auth**: no recognised guard in the handler or the decorators above it, no file-wide middleware (`router.use`, `before_action`, a class-level guard, a Fastify `addHook('onRequest', auth)`), and no application-wide auth resolved from another file (below);
- **unscoped access** (`static-bola-unscoped-access`): a lookup such as `findUnique`, `findById`, `findByPk`, `get_object_or_404`, `find(params[:id])` keyed by request input, with no tenant key or caller identity inside the lookup and no explicit ownership comparison. A tenant ID taken from the URL alone does not count, because the caller chooses it.

| Rule | Confidence | What it flags |
|---|---|---|
| `static-bola-unscoped-access` | medium | A route handler with missing auth or an unscoped lookup, as above. |
| `BOLA-UNGUARDED-SERVER-ACTION` | medium | A Next.js server action with no recognised guard. |
| `BOLA-TABLE-MISSING-TENANT-COLUMN` | low | A `CREATE TABLE` in a migration with no tenant or owner column. Tables shared by every tenant are skipped only when listed in `bola.global_tables`; PrufGate does not guess which tables are lookup tables. |
| `BOLA-UNAUTHENTICATED-ACCESS`, `BOLA-CROSS-TENANT-ACCESS` | high | Live probing: a response that leaks without a token or across tenants. |
| `BOLA-PROBE-REDIRECT-REFUSED` | high | Live probing: a redirect to another origin, not followed. |
| `bfla-role-allowed` | high | Role matrix: a role the matrix denies got a 2xx (P0). |
| `bfla-allow-denied` | medium | Role matrix: a role the matrix allows got 401/403, so the matrix may be stale (P3, advisory). |

Add your own guards and tenant keys with `auth_guards` and `tenant_keys`.

A project guard wrapper is followed one hop without configuration: when one of the handler's first three statements (before any lookup) calls a function, defined in the same file, in a file it is imported from (relative or `@/` paths), a Python module or the Go package, whose body calls a recognised guard and refuses the request (a 401 or 403, a throw or raise, an abort or a redirect), the handler counts as guarded. For example `const g = await staffOnly("widgets:write"); if (!g.ok) return g.response;` where `staffOnly` calls `assertStaff` and returns 403. A wrapper deeper than one hop, or one that never refuses, needs `auth_guards: [staffOnly]`.

### What the static checks resolve

The checks are heuristics over handler text, not a type-aware analysis. Resolved:

- **Values traced through local variables.** A tenant key whose value is a local variable (`where: { orgId: org }`, `filter_by(org_id=org)`, `where('org_id', $org)`, a shorthand `{ orgId }`) is followed back through up to two simple assignments in the handler (`const`/`let`/`var`, `:=`, `$x =`, typed Java/Kotlin locals, destructuring `const { orgId } = req.query`). A value that comes from request input (query, params, body, headers, cookies, `self.kwargs`, `$request->input`, `params[...]`, `c.Query`) is not scoping; one from the authenticated caller (`req.user`, `req.session`, `ctx.state.user`, `current_user`, `request.user`, `auth()->user()`, `Auth::user()`, `getServerSession`) is. When both appear in one expression the caller's identity wins. A value that cannot be traced keeps the earlier behaviour and counts as scoping.
- **Laravel implicit route-model binding.** `show/edit/update/destroy` taking a type-hinted model (`show(Invoice $invoice)`, not a `*Request`) are analysed although no lookup is visible. They are scoped only by a policy check in the action (`$this->authorize`, `Gate::authorize`, `->can(`), `authorizeResource` in the controller, an ownership comparison, or on the route in `routes/*.php`: `->scopeBindings()`, `->scoped()`, `->can(...)`, `can:` middleware, or a `Route::scopeBindings()->group(...)` that contains the controller.
- **Django generic views and DRF viewsets** (`DetailView`, `UpdateView`, `DeleteView`, `Retrieve*APIView`, `ModelViewSet`, the retrieve/update/destroy mixins). `get_object()` loads the record, so the class is unscoped unless `get_queryset`/`get_object` filters by `self.request.user` or a tenant key not taken from the request, the class compares ownership, or it lists a permission class that defines `has_object_permission`. `queryset = Model.objects.all()` alone is unscoped. `LoginRequiredMixin`, `permission_classes` and DRF's `DEFAULT_PERMISSION_CLASSES` (with `IsAuthenticated`, `IsAdminUser` or `DjangoModelPermissions`, for DRF classes that set no `permission_classes`) count as auth.
- **NestJS global guards.** `{ provide: APP_GUARD, useClass: X }` in any module, or `app.useGlobalGuards(new X())`, counts as auth for every controller when `X` names an auth guard (`auth`, `jwt`, `session`, `passport`, `clerk`, `keycloak`, `access`); a `ThrottlerGuard` does not. A controller file using `@Public()`, `@SkipAuth()`, `@AllowAnonymous()`, `@IsPublic()` or `@NoAuth()` does not inherit it.
- **Spring global security.** `.anyRequest().authenticated()` (or `hasRole`/`hasAuthority`) counts as auth for every controller, except paths under a `requestMatchers(...).permitAll()` pattern. With `@EnableMethodSecurity`/`@EnableGlobalMethodSecurity` in the project, a `@PreAuthorize`/`@PostAuthorize` expression that ties the object to the caller (`hasPermission(#id, ...)`, a bean check `@acl.canRead(#id)`, or `authentication`/`principal` together with `#param` or `returnObject`) counts as scoping. `@PreAuthorize("hasRole(...)")` is auth only.
- **Middleware registered in another file** (Express, Fastify), one level deep and in order: in an entry file, `app.use(auth)` or `app.use('/api', auth)` on a line before `app.use('/api/x', router)`, or Fastify `addHook('onRequest'|'preHandler', auth)` before `fastify.register(plugin)`, where the router is a relative import of a file that registers routes; and auth passed inline, `app.use('/x', auth, router)`. A path-prefixed `app.use` protects only mounts under that prefix.
- **Rails custom member actions.** Besides `show/edit/update/destroy`, actions declared in `config/routes.rb` as `member do get :preview end`, `member { post :approve }` or `get :preview, on: :member` inside `resources :x do` are checked in `XController`.

Not resolved (findings may be missed or reported falsely): auth applied after the mount or by sub-routers the mounted router mounts itself, routers built by a function or imported from a package, values passed through function calls or more than two assignments, Go `Where("org_id = ?", org)` placeholders, Rails namespaces and `controller:` options (member actions are matched by controller file name), lookups in `before_action` callbacks, Laravel `Route::resource` actions other than show/edit/update/destroy, DRF `APIView` and plain `ViewSet` methods, Django settings outside `*.py` files, and Spring method security whose `@Enable...` annotation lives outside the scanned project. `@PreAuthorize` counts as auth even when method security is not enabled in the project.

**Live probing** (optional, only against systems you are authorised to test) sends each discovered route as an unauthenticated request, as user A, and as user A for user B's resource (and the reverse). It reports responses that leak across tenants, with `curl` reproductions that use `$PRUFGATE_TOKEN_A` / `$PRUFGATE_TOKEN_B` placeholders. Redirects are followed only within the target's origin; a redirect elsewhere is not followed, so the tokens never leave that origin, and is reported as `BOLA-PROBE-REDIRECT-REFUSED` (P1). See [GETTING_STARTED.md](GETTING_STARTED.md#live-bola-probing).

**Route sources.** Live probing uses the routes found in your source code plus `PRUFGATE_BOLA_PATHS`. Add your own API description with `--routes-from FILE` (repeatable): an OpenAPI 3.x or Swagger 2 document (YAML or JSON), a Postman collection v2.1 or a HAR export. Only the method and URL path of each entry are read; hosts, headers, cookies, bodies, query strings, auth blocks and variables are ignored. Only GET and HEAD entries are kept, and the others are counted as skipped. Every path is probed on `--url`, joined exactly like a `PRUFGATE_BOLA_PATHS` entry. Path parameters take the document's `example` or `default` value; without one they become the tenant placeholder and join the cross-tenant probes, like a discovered `{id}` route. Paths already known are dropped, and at most `--max-routes N` (default 200) new paths are added. A file that cannot be read or parsed, is over 5 MB, or uses YAML aliases (`*name`, which can expand without bound) stops the run with exit 2.

**Role matrix.** `prufgate bola PATH --url URL --roles FILE` checks function-level authorisation (OWASP API5) with test accounts you create yourself. The file lists your roles and which of them may call each route:

```yaml
roles:
  admin: { token_env: PRUFGATE_ROLE_ADMIN }
  member: { token_env: PRUFGATE_ROLE_MEMBER }
  anonymous: {}
routes:
  - { path: /api/admin/users, allow: [admin] }
  - { path: /api/reports/export, allow: [admin, member] }
  - { path: /api/admin/health, method: HEAD, allow: [admin] }
```

Each route is sent once per role, as a GET (or HEAD with `method: HEAD`), to `--url` plus the path, instead of the two-token probe; the same target check and timeout apply. Redirects are never followed: a 3xx counts as a denial, since a denied role is often sent to a login page that answers 200. A 2xx for a role not in `allow` is `bfla-role-allowed` (P0); a 3xx, 401 or 403 for a role in `allow` is `bfla-allow-denied` (P3). Tokens are read only from the named environment variables, sent as `Authorization: Bearer`, and never printed: PoCs use `$PRUFGATE_ROLE_ADMIN`-style placeholders. Only GET and HEAD are accepted; a path must start with `/` and must not contain `//`, a scheme, a backslash or `.`/`..` segments. The file is read as safe YAML with the same 5 MB cap and alias refusal as `--routes-from`. A malformed file, another method, a bad path, an unset environment variable, more routes than `--max-routes`, or a request that cannot connect stops the run with exit 2.

## Engine 6: diff reviewer

`prufgate/review/reviewer.py`. Reviews changed lines only.

Deterministic rules (default, offline):

| Finding | Severity | Confidence |
|---|---|---|
| SQL injection vector (query built from string interpolation) | P0 | medium |
| Hard-coded credential | P0 | medium |
| Shell command injection risk | P0 | medium |
| Disabled TLS certificate verification | P1 | high |
| Unsanitised HTML injection (XSS) | P1 | medium |
| Credential logged to the console | P1 | low |
| Server action without an authorisation guard | P1 | medium |
| Ignored Go error return, unbounded goroutine spawn | P2 | low |

It also folds in the diff findings of engines 1 to 4. Output formats: `markdown`, `json`, `sarif`, `github` (workflow annotations, with every field escaped), `reviewdog`, `gitlab` (Code Quality) and `junit`. Suggestion blocks are emitted only when they are valid replacement code, never comment-only. It exits 1 on a P0/P1 finding, and 2 when no diff can be read (no repository, or a base ref that does not exist).

`--ai` (optional) sends the changed hunks to a provider you choose: an API (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_HOST`, model in `PRUFGATE_AI_MODEL`) or a local agent CLI. The model's output is treated as untrusted: a comment must point at a line the diff adds, and suggestions are validated like the deterministic ones. API keys are never printed, and provider errors are redacted. Sending code to a provider is your decision; the default mode sends nothing anywhere. The diff can carry prompt injection, so local agent CLIs get it on stdin and run one-shot with the least tool access each offers: `auto` picks only `claude`, run with every tool and MCP server off. `codex` (`exec`, read-only sandbox), `gemini` (`-p`, plan mode) and `opencode` (`run`) can still read files on your machine, so they run only when you name them with `--ai-provider`.

## Differential test verification (opt-in, runs repository code)

`prufgate verify --differential` is the strongest evidence of test tampering: it runs the base branch's tests on the head code. A test that was deleted or weakened so the change would pass fails again in its base version.

**This executes code from the repository under review.** It is a separate command and is never part of `prufgate check`, `prufgate.sh fast` or `full`, the GitHub Action, the MCP server, the API or the agent hooks. It refuses to start (exit 2) unless the operator passes `--allow-run-tests` or sets `PRUFGATE_ALLOW_RUN_TESTS=1`. Run it only in a sandbox or a disposable CI job, never on a machine holding credentials, and never on pull requests from forks in a job with secrets.

How it runs:

1. The comparison base is `git merge-base <base> HEAD`, so tests added to the base branch after your branch forked are not run against code that never saw them. A worktree left by an earlier run that was killed is removed first.
2. The committed `HEAD` is checked out with `git worktree add --detach` into a temporary directory. Your checkout is never touched, and uncommitted changes are not part of the comparison. The worktree is always removed, including after an error, a timeout, SIGTERM or SIGINT. git runs with repository hooks and `core.fsmonitor` off and without your tokens in its environment.
3. The files of the test run are compared with the base: test files, `conftest.py` and other helpers and setup files, every file under a test directory, and test-runner configuration (`pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini`, `package.json`, Vitest and Mocha configuration). When none differs, there is nothing to compare: exit 0 without running anything.
4. The head's own tests run. If they fail, the comparison is inconclusive: exit 2.
5. Every process the run left behind is killed (on Linux, also ones that detached into their own session), and the worktree is reset to `HEAD`, so nothing the tests wrote survives. Then the test run becomes the base's: each file of the test run is written in its base version, and those the base does not have (a `conftest.py` with `collect_ignore`, a new helper) are removed. In `package.json` only the test-runner keys (`jest`, `mocha`, `ava`, `vitest`, `c8`, `nyc`) and the `test`, `pretest` and `posttest` scripts are restored. Symlinks, hardlinks, FIFOs and directories head put in the way are removed, never written through.
6. The tests run again: head's code, base's tests. A failure is reported as `differential-base-tests-fail` (P0, high confidence), one finding per failing test read from a JUnit XML report, or one per restored or removed file when no report was written.

The test command comes from `--test-cmd` (split like a shell command line, but run without a shell). Otherwise it is detected, conservatively: `python -m pytest --junitxml=…` when `pytest.ini`, `conftest.py`, or a pytest section in `pyproject.toml`, `setup.cfg` or `tox.ini` exists; else `npm test` when `package.json` has a real test script (not the `npm init` placeholder); else `go test ./...` when `go.mod` exists. When nothing matches it exits 2 and asks for `--test-cmd`. A custom command can write a JUnit report to the path in `PRUFGATE_JUNIT_XML` so failures are named per test.

Each run has a timeout (`--timeout`, default 600 seconds); on expiry the whole process group is killed and the command exits 2. The output goes to a file, so a child that keeps it open cannot hold the run past its timeout. The tests get a reduced environment: `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `TERM` (and `SYSTEMROOT` on Windows), plus `CI=1` and `PRUFGATE_JUNIT_XML`. Tokens, API keys and cloud credentials in your environment are not passed; name any variable the tests really need with `--pass-env NAME`. A reduced environment is not isolation: the tests can still read files your user can read, which is why this belongs in a sandbox.

Output formats are `text`, `json` and `sarif`, as for `check`. Exit codes: 0 clean, 1 a base test fails on the head code, 2 refused, no test command, no base ref, head tests failing, timeout or any other error.

## Mutation smoke test (opt-in, runs repository code)

`prufgate verify --mutation` catches tests that were hollow from the start. A test that calls the code but checks nothing passes on the base and on the head, so no diff check sees it. Mutating the lines the branch changed does: when a mutant (a flipped comparison, a removed call, a replaced return value) survives, no test fails when that line does the wrong thing.

**This executes code from the repository under review**, exactly like `--differential`, and is contained the same way (`prufgate/repo_runner.py`): it refuses to start (exit 2) without `--allow-run-tests` or `PRUFGATE_ALLOW_RUN_TESTS=1`; it runs in a temporary detached worktree of the committed `HEAD` that is always removed (also after a timeout, SIGTERM or SIGINT, and a worktree left by a killed run is pruned by the next one); the tool gets the same reduced environment (`--pass-env NAME` adds a variable); the whole process group is killed at `--timeout`; and on Linux no detached descendant survives. It is never part of `check`, the batteries, the GitHub Action, the MCP server, the API or the hooks. Run it only in a sandbox or a disposable CI job.

PrufGate does not mutate code itself and **never installs anything**. It uses a mutation tool already on `PATH`, picked per language of the changed files (or named with `--tool`):

| Language | Tool (`--tool`) | Restricted to | Report read |
|---|---|---|---|
| Python | `mutmut` (3.x) | mutants of the changed modules (`mutmut run "<module>.*"`) | `mutants/<file>.meta`, and `mutmut show` for each survivor's line and change |
| JavaScript, TypeScript | `stryker` | the changed line ranges (`--mutate file:start-end`) | `reports/mutation/mutation.json` (`--reporters json`) |
| Java (Maven) | `pit` | the changed classes (`-DtargetClasses`), Maven offline (`-o`) | `pit-reports/mutations.xml` (`-DoutputFormats=XML`) |
| Go | `gremlins`, else `go-mutesting` | gremlins: the diff against the merge base (`--diff`); go-mutesting: the changed files | gremlins `--output` JSON; go-mutesting `report.json` (the avito-tech fork, `json_output`) |
| Rust | `cargo-mutants` | the diff against the merge base (`--in-diff`) | `mutants.out/outcomes.json` |

When a changed file's language has no tool installed, it exits 2 and names what to install. PIT runs Maven offline, so a pitest plugin that is not already in the local Maven repository is an error, not a download. The temporary worktree holds tracked files only, so a tool that needs installed dependencies (`node_modules`, a virtualenv) finds those on `PATH` or in your home directory, not in the worktree.

How it runs:

1. The comparison base is `git merge-base <base> HEAD`. The changed lines are the lines `HEAD` adds or changes in production files; test files, test helpers and test-runner configuration are never mutated. With no changed production line it exits 0 without running anything.
2. Report paths committed in the repository (`mutants/`, `reports/mutation/`, `pit-reports/`, go-mutesting's `report.json`) are deleted first, so only a report this run writes is read; one reached through a committed symlink out of the worktree is an error. The tool runs in the worktree, restricted as in the table, within `--timeout` seconds for the whole run (default 1800). `--max-mutants N` (default 200) is passed where the tool has a cap (PIT's `CLASSLIMIT`); the other tools are bounded by the restriction to the change and by `--timeout`. On expiry everything is killed and the command exits 2.
3. Its report is read. A surviving mutant on a changed line is a `mutation-survivor` finding (P1, medium confidence) with the line and the mutation; a mutant no test runs is a `mutation-no-coverage` finding (P1, medium confidence). Killed and timed-out mutants on changed lines are summarised; mutants on other lines are counted and ignored. A tool that exits non-zero (except cargo-mutants' 2 and 3, missed mutants and timeouts), writes no report, or reports no mutant on any changed line is an error (exit 2), never a pass. A failing threshold in the tool's own configuration (Stryker's `thresholds.break`, PIT's `mutationThreshold`) is therefore an error too.

mutmut mutates whole functions; a survivor's line is the function's line plus the offset of the change in `mutmut show`, and the other outcomes count on the function's first changed line. Medium confidence because an equivalent mutant (one that changes nothing observable) survives every test.

Output formats are `text`, `json` and `sarif`. Exit codes: 0 no survivor or uncovered mutant on a changed line, 1 one of those, 2 refused, no tool, no base ref, timeout, no report or any other error.

## Agent transcripts

`prufgate transcript FILE` reads a coding agent's session transcript after the run and reports the commands it ran to copy an answer or get past checks. Nothing in the transcript is executed.

| Rule | Confidence | What it reports |
|---|---|---|
| `transcript-history-lookup` | medium | `git log --all` / `--branches` / `--remotes` / `-g`, `git reflog`, `git cat-file` on anything but HEAD, `git checkout` / `switch` / `restore --source` to a branch or tag other than the default, and `git show <branch-or-tag>:path` or `git diff <branch-or-tag>` (`origin/...`, a tag like `v1.2.0`, or a name before `--`). Also `git cherry-pick`, `merge`, `grep`, `archive`, `ls-tree` and `worktree add` with another branch or tag, and `$(git rev-parse <branch>)` handed to any command. Ordinary development is not reported: every `git stash` command, a commit hash, `HEAD~n`, ranges such as `<hash>...HEAD`, and the default branch (`main`, `master`, `develop`, `origin/main`, `origin/master`, `origin/HEAD`, `@{upstream}`). |
| `transcript-hook-bypass` | high | `--no-verify`, `git commit -n`, `core.hooksPath`, `HUSKY=0`: what the [shell guard](AGENT_HOOKS.md) blocks, with the same parser. |
| `transcript-test-tamper-command` | medium | Removing or moving tests, test directories or CI configuration (the shell guard's protected paths), and editing CI configuration with a redirection, `sed -i`, `tee` or `cp`. |

A branch name with a slash (`feature/x`) after `git checkout` is read as a path and not reported; `git switch` and remote-tracking names (`origin/...`) are. Only real shell commands are read, with the shell guard's parser: here-document bodies, `python3 -c` scripts and quoted arguments of other commands are never taken for git commands; `bash -c '...'` is read.

Formats are detected from the content; `--format-in claude|codex|text` overrides it:

- `claude`: Claude Code session JSONL (`~/.claude/projects/`), `tool_use` blocks named `Bash` with `input.command`.
- `codex`: Codex CLI rollout JSONL (`~/.codex/sessions/`): `response_item` payloads of type `function_call` (`command` or `cmd` in the arguments) and `local_shell_call`; also the event stream of `codex exec --json` (`command_execution` items).
- `text`: a shell log; each line starting `$ ` is a command, optionally after a `[timestamp]`.

Each finding names the transcript line and, when the transcript has one, the timestamp. Commands are redacted (token shapes, secret-named assignments, values of secret environment variables; `/home/<user>/` and `/Users/<user>/` become `.../`) and cut to 300 characters before they are printed. Output formats: `text`, `json`, `sarif`. Exit codes: 0 nothing found, 1 a finding (every rule is P1), 2 the file cannot be read, is larger than 64 MiB, has a malformed JSON line or is in no known format.

## The gate's extra tools

`prufgate.sh` also runs these when they are installed. Each is skipped (and says so) when it is not.

- **ast-grep**: the built-in rule `configs/ast-grep/rules/action-authorization-guard.yml` and your own rules in `.prufgate/rules/`. See [CUSTOM_RULES.md](CUSTOM_RULES.md).
- **gitleaks**: secret scanning with PrufGate's defaults (`configs/gitleaks.toml`) extended by your `.gitleaks.toml`.
- **zizmor**: GitHub Actions workflow security. Severity follows zizmor's own severity and confidence: High is blocking (P1; a High-confidence `template-injection` is P0), Medium is P2 (P3 with Low confidence), Low and Informational are P3, and `unpinned-uses` is always P2. The reported line is the finding's primary location.

In a changed-files run each tool sees only the change: see [A changed scan judges only the changed lines](GETTING_STARTED.md#a-changed-scan-judges-only-the-changed-lines).
