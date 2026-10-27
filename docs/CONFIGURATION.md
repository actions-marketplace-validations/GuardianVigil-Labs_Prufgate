# Configuration reference

PrufGate runs with sensible defaults and no configuration. To tune it, add one of these files at the root of the repository (first found wins): `.prufgate/config.yaml`, `.prufgate/config.yml`, `.prufgate.yaml`, `.prufgate.yml`. The older `.prufgate/fabrication.json` and `.prufgate/debt-ceiling.json` are still read.

`prufgate init` writes a starter file. An invalid file (bad YAML, an unknown pack, a reason missing where one is required, invalid UTF-8) stops the run with exit 2 and a message naming the problem.

## Configuration changes take effect after merge

When a run compares against a base ref (`prufgate check --changed` or `--base`, `PRUFGATE_BASE_REF`, `GITHUB_BASE_REF` in a pull request, `prufgate.sh fast`), every engine reads the configuration and the baseline as they are at the base (`git show`), not from the working tree. A change cannot switch off the checks that review it: an exemption, exclusion, debt entry or baseline entry added in a pull request applies only once that pull request is merged.

- The run reports the edit as `prufgate-config-not-applied` (P2, informational) and says it used the base configuration, or the defaults when the base has none. An edit that loosens the gate is also a `prufgate-config-self-exemption` blocker (see below).
- Without a base ref (a full sweep, a repository's first commit, or a local `prufgate check` with uncommitted changes and no base) the working-tree files are used, so you can try a configuration locally.
- A base ref git cannot read (a typo, or a shallow CI clone without it) stops the run with exit 2.
- A base configuration that this PrufGate version rejects (for example a key a newer version removed) is not the change's doing, since it is already merged. The run applies the branch's configuration instead, which must itself be valid or the run stops with exit 2, and reports `prufgate-config-base-invalid` (P2). The diff lines of the configuration are still checked, so the change that fixes the file is not blocked.
- There is no override. A maintainer who changes the configuration on purpose merges the change; the next runs apply it.
- A `--config` file outside the repository belongs to the operator, not the change, and is read from disk.

## Keys

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | `1` | Schema version. |
| `packs` | list | `[core, web-ui, ai-safety]` | Rule packs to run. See [packs](#packs). |
| `languages` | list | all | Limit engine 1 to these languages (`typescript`, `javascript`, `python`, `go`, `rust`, `java`, `kotlin`, `php`, `ruby`, `csharp`). |
| `exclude` (alias `allowed_paths`) | list of paths/globs | build output, dependencies | Paths no engine scans. |
| `auth_guards` | list | none (added to the built-ins) | Extra function or decorator names that count as an authentication check for engine 5 (a wrapper that calls a built-in guard and refuses the request is already followed one hop). Built in: `assert*`, `verify*`, `require*`, `protect*`, `auth()`, `getSession`, `getCurrentUser`, `get_current_user`, `Depends(get_current_*)`, `@login_required`, `@UseGuards`, `@PreAuthorize`, `@Secured`, `authenticate_user!`, Laravel `auth` middleware and similar. |
| `tenant_keys` | list | none (added to the built-ins) | Extra column or field names that scope a query to a tenant or owner. Built in: `tenant_id`, `organization_id`, `org_id`, `workspace_id`, `user_id`, `owner_id`, `account_id`, `customer_id`, in snake_case and camelCase. |
| `bola` | mapping | none | Engine 5 settings. `global_tables`: tables shared by every tenant (`[countries, currencies]`) that `BOLA-TABLE-MISSING-TENANT-COLUMN` skips. Only listed tables are skipped. Adding a table is reported by the diff guard like other exemptions. |
| `score_owners` | list of paths | none | Files that are allowed to compute scores or verdicts (engine 1 flags scores computed anywhere else). |
| `model_call_patterns` | list of regexes | common LLM SDKs | Extra patterns that identify an LLM call for the unseeded-prompt rule. |
| `evidence_markers` | list of regexes | common forms | Patterns that show runtime evidence is passed into a prompt. |
| `exempt` | see below | none | Per-path rule exemptions, each with a reason. |
| `known_debt` | see below | none | Ratcheting ceilings for rules you cannot fix yet. |
| `registry_check` | `true`, `false` or a mapping | `false` | Look up dependencies added in the diff on their public registry (engine 4). See [registry check](#registry-check). |
| `ghost_symbols` | mapping | `{third_party: false}` | `third_party: true` also checks names imported from installed Python packages for `ghost-symbol` (engine 4). CI must install the dependencies first. See [ENGINES.md](ENGINES.md#ghost-symbols). |
| `enable_low_confidence` | boolean | `false` | Turn on low-confidence rules. See [confidence](#confidence). |
| `ai_adjudicate` | `true`, `false` or a mapping | `false` | Let an AI provider dismiss low-confidence findings it judges not real. See [AI adjudication](#ai-adjudication). |

Paths in `exclude`, `exempt` and `known_debt` match a file exactly, a directory and everything below it, or a glob (`src/legacy/**`). They never match a substring, so `a.ts` does not cover `data.ts`.

## Registry check

Off by default because it needs the network. `true` turns it on with the defaults; a mapping turns it on with settings:

```yaml
registry_check:
  max_age_days: 30   # a first release younger than this is dependency-recently-published (P1)
  max_lookups: 50    # registry requests per run; more new names than this stop the run (exit 2)
  offline_ok: false  # true: a failed lookup is printed and skipped instead of stopping the run
```

A failed lookup stops the run with exit 2 unless `offline_ok` is `true`. Lookups are cached for 24 hours outside the repository. Rules, endpoints and limits: [ENGINES.md](ENGINES.md#registry-check-for-new-dependencies-opt-in).

## Packs

Packs switch rules of engine 1 on or off. Engine 5 (BOLA) always runs; tune it with `tenant_keys` and `auth_guards`.

| Pack | Default | What it adds |
|---|---|---|
| `core` | on | The language-independent rules of engine 1. |
| `web-ui` | on | Stub click handlers and disconnected form submits. |
| `ai-safety` | on | LLM prompts that ask for a decision with no evidence passed in. |
| `cti` | **off** | Rules for threat-intelligence products: hard-coded verdicts and attributions, zero JARM fingerprints, the empty-input digest used as a sample, model-generated intelligence. Turn it on only if you build such a product. |

## Confidence

Every rule has a confidence, listed in the rule tables of [ENGINES.md](ENGINES.md) and carried by each finding (`confidence` in JSON, a tag in the Markdown report, `properties.confidence` on SARIF results and `properties.precision` on SARIF rules):

| Confidence | Meaning |
|---|---|
| `high` | An exact structural match: a hit is almost always what the rule names. |
| `medium` | A heuristic with known false positives. |
| `low` | A fuzzy or naming-based heuristic. **Off by default.** |

A rule that is off is not reported and does not block, everywhere PrufGate reports: the gate, `prufgate check`, `review`, `bola` and `test-audit`, the MCP tools and the REST API. `enable_low_confidence: true` turns the low rules on, with their usual severity, so a low P0 finding blocks like any other. Rules from other tools (gitleaks, zizmor, your own ast-grep rules) and AI review comments count as `medium`. A change that sets `enable_low_confidence` back to `false` is reported as `prufgate-config-self-exemption`.

```yaml
enable_low_confidence: true
```

## AI adjudication

Off by default: it sends code to a provider, and it can dismiss findings. Only the configuration turns it on: `ai_adjudicate: true` (or a mapping) turns it on for `prufgate check` and the `prufgate.sh` gate. In a run with a base ref that is the configuration at the base, so a change cannot turn it on for itself. `prufgate check --ai-adjudicate` is a request: without `ai_adjudicate` enabled in the configuration in effect it prints a notice and runs without AI. No environment variable turns it on. The MCP server, the REST API and the agent hooks never call it: `--format agent-hook` and `PRUFGATE_NO_AI_ADJUDICATE` (which they set) switch it off.

```yaml
ai_adjudicate:
  confidence: [low]        # which findings are sent: low and/or medium; high never is
  max_findings: 20         # provider calls per run (0 to 500); findings past it are kept
  timeout: 30              # seconds per call (1 to 300)
  context_lines: 8         # lines either side of the finding (0 to 50)
  max_window_bytes: 2000   # cap on the code sent per finding (200 to 16000)
```

Low-confidence rules are reported only with `enable_low_confidence: true`, so with the default `confidence: [low]` turn that on too.

For each eligible finding the provider gets a fixed prompt: the rule ID, its confidence and description, the finding message and the code window, the last two between random delimiters and marked as untrusted data whose instructions must be ignored. The window is built around the finding's own line, so context never pushes that line out. A window or message holding anything that looks like a credential (values of credential-like environment variables, common token shapes, strings assigned to secret-named keys) is not sent at all: the judge never sees a placeholder where the code was. The reply must be exactly `{"real": true|false, "reason": "..."}`.

- **Only downgrades.** `real: false` hides the finding from blocking and lists it as AI-dismissed with the reason: in `prufgate check` text output, in the Markdown report (section "AI-dismissed"), and in SARIF as a result with `suppressions: [{kind: external, justification: "AI-dismissed: ..."}]`, which code scanning shows as dismissed. `--format json`, GitLab Code Quality and JUnit leave dismissed findings out. Nothing is added or raised, and `known_debt` ceilings count findings before adjudication.
- **Fails closed.** No provider, a provider error or timeout, or any other reply keeps the finding exactly as it would be without AI. So does a code window or message that addresses the judge (the words AI, LLM, judge, reviewer, grader, evaluator, assistant, bot, instructions, a model name, "PrufGate", "model reading this", "ignore previous", "false positive", "verdict", or `real` set to false): it is not sent at all. The text is normalised first (NFKC, Cyrillic and Greek lookalike letters folded, zero-width characters, `_`, `-` and camelCase read as word breaks, lines joined), so `note_for_ai_reviewer` or a phrase split across comment lines is caught too.
- **PrufGate's own rules only.** A finding is sent only when its rule is listed with a confidence in PrufGate's rule table. Findings from gitleaks, zizmor and ast-grep, unlisted rules, and AI review comments are never sent, whatever `confidence` says.
- **Budget and cache.** At most `max_findings` findings judged per run, cached verdicts included. Verdicts are cached in `$XDG_CACHE_HOME/prufgate/adjudicate.json` (default `~/.cache`) by rule, SARIF fingerprint and a hash of the code window, so an unchanged finding is not sent again; errors are not cached. The agent shell guard refuses writes to that file.
- **Provider.** `--ai-provider` or `PRUFGATE_AI_PROVIDER` (default `auto`), the same providers as `prufgate review --ai`.
- **Configuration drift.** With a base ref the setting is read at the base like every other key; a changed scan with no base reads it at HEAD. A full scan in a git repository needs it on at the base (else HEAD) too. A change that turns `ai_adjudicate` on, adds a confidence level or raises `max_findings` is not applied and is reported as `prufgate-config-self-exemption`. So is a CI workflow or script (`.sh`, `Makefile`, `package.json`) that adds `--ai-adjudicate`. Options are never abbreviated (`--ai-adj` is an error).

## Suppressing findings

Give every suppression a reason, so a reviewer can see why a finding was accepted (exempt forms 1 and 3 require one).

**Inline**, on the line or on a comment line just above it:

```ts
return cachedPrices; // prufgate-ignore: route-canned-fallback -- served from the documented offline cache
```

- Name one or more rules, separated by commas (`prufgate-ignore: rule-a, rule-b -- reason`), or none to cover every rule on that line (`prufgate-ignore -- reason`). Engine 6 rules use the ID the report shows, for example `pr-disabled-tls-certificate-verification`.
- **The reason is required.** Write it after `--` (the older ` - ` separator is still read). An ignore without a reason suppresses nothing: the finding stays, and the report adds an `ignore-without-reason` finding (P2) on that line telling you to add one.
- **Every honoured ignore is reported.** The Markdown report counts them in its summary and lists each with its reason under "Inline Ignores"; the SARIF report keeps each as a result with an in-source `suppressions` entry and the reason as its `justification`, which GitHub code scanning shows as a dismissed alert. `prufgate check` prints them before its findings, and adds them the same way to `--format sarif`. The GitLab Code Quality and JUnit reports leave honoured ignores out.

Engine 3 also flags a new `prufgate-ignore` added in a diff without a justification, like any other bare suppression.

**`exempt`** accepts three forms; use one per file:

```yaml
# 1. path -> rule -> reason
exempt:
  src/legacy/adapter.ts:
    route-canned-fallback: "#104: legacy fallback until the payments API migration"
```

```yaml
# 2. rule -> list of paths
exempt:
  demo-named-data:
    - examples/**
```

```yaml
# 3. a list of entries
exempt:
  - { path: scripts/seed.ts, rule: fake-named-data, reason: "seed data for local development" }
```

An exemption that no longer matches anything is reported as `stale-exemption`, so the list does not rot.

**`known_debt`** sets a ceiling that can only go down:

```yaml
known_debt:
  stub-click-handler: 3                 # at most 3; a 4th is a P0 debt-ceiling-breached
  unhandled-empty-catch:
    - { path: src/old/client.ts, reason: "#88: replace the old client" }
```

**Baseline** (the `prufgate.sh` gate only): `.prufgate/baseline.yaml`, `.yml` or `.json` holds a list, or a mapping under `ignore`, `ignored` or `baseline`, of `{file, rule}` entries (`file_path` and `rule_id` are accepted too; `"*"` in one field matches any value there; an entry needs a real value in at least one field). Rule names are matched case-insensitively against the report's rule IDs, where anti-fabrication rules carry an `anti-fabrication-` prefix. `prufgate check`, the MCP server and the API do not read the baseline. A baseline file that cannot be parsed is ignored, which keeps every finding. In a changed-files run the baseline is read at the base ref, like the configuration.

Engine 3 reports a diff that adds a new exemption, debt entry or score owner to the PrufGate config itself (`prufgate-config-self-exemption`), so loosening the gate is always visible in review. With a base ref the edit is not applied until merge either way.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `PRUFGATE_BASE_REF` | CLI, gate | Base ref for the changed scope. |
| `GITHUB_BASE_REF` | CLI, gate | Set by GitHub Actions; `origin/<it>` is used when `PRUFGATE_BASE_REF` is not set. |
| `WORKSPACE` | gate | The repository to scan (default: the current directory, or `/workspace` in the container). |
| `PRUFGATE_REPORTS_DIR` | gate | Where reports go (default `WORKSPACE/reports`). |
| `TARGET_URL` | gate | Base URL for live BOLA probing. |
| `BOLA_STATIC_ONLY` | gate | `1` skips live probing even when `TARGET_URL` is set. |
| `PRUFGATE_TEST_PROBE_TOKEN_A`, `_B` | engine 5 | Bearer tokens for live probing. |
| `PRUFGATE_TEST_PROBE_TENANT_A_ID`, `_B_ID` | engine 5 | Tenant IDs for live probing. |
| `PRUFGATE_ALLOW_REPO_HOOKS` | gate | `1` runs the scanned repository's `.prufgate/hooks/` scripts. Off by default: they are code from the repository under review. |
| `PRUFGATE_ALLOW_RUN_TESTS` | `verify` | `1` lets `prufgate verify --differential` and `--mutation` run the repository's tests, as `--allow-run-tests` does. Off by default: the tests are code from the repository under review. Set it only in a sandbox or disposable CI job. |
| `PRUFGATE_INFO_URI` | reports | The `informationUri` written into SARIF. |
| `PRUFGATE_AI_MODEL` | engine 6 | Model name for `--ai` with an API provider. |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_HOST` | engine 6 | Providers for `prufgate review --ai` and AI adjudication. Never written to output. |
| `PRUFGATE_AI_PROVIDER` | `check`, gate | Provider for AI adjudication (default `auto`). |
| `PRUFGATE_NO_AI_ADJUDICATE` | `check`, gate | Any value switches AI adjudication off. Set by the MCP server, the REST API and the agent hooks. |
| `PRUFGATE_API_TOKEN` | API | Bearer token for every scan and report route. Generated and printed once when unset on loopback. |
| `PRUFGATE_API_HOST` | API | Bind address (default `127.0.0.1`). A non-loopback address needs `PRUFGATE_API_TOKEN`. |
| `PRUFGATE_WORKSPACE_ROOT` | API | Scans are confined to this directory; anything resolving outside it, including through a symlink, is refused. |
| `PRUFGATE_DEFAULT_WORKSPACE` | API | Workspace used when a request names none. |
| `PRUFGATE_WEBHOOK_SECRET` | API | Turns on `/api/v1/webhook`; deliveries must carry a valid GitHub or GitLab signature. |
| `PRUFGATE_API_MAX_SCANS`, `PRUFGATE_API_SCAN_TIMEOUT` | API | Concurrent scan limit, and seconds per scan (default 600). |
| `PRUFGATE_MCP_TIMEOUT` | MCP | Seconds per tool call (default 300). |
| `PRUFGATE_REGISTRY_CHECK` | engine 4 | `1` turns the registry check on, as `registry_check: true` does. It cannot turn off a check the configuration turns on. |
| `XDG_CACHE_HOME` | engine 4, adjudication | Where the registry check and AI adjudication keep their caches (`prufgate/registry.json`, `prufgate/adjudicate.json`; default `~/.cache`). |
| `PRUFGATE_ALLOW_LINK_LOCAL` | MCP, API | `1` allows link-local probe targets, which are refused by default (cloud metadata endpoints). |
| `PRUFGATE_IMAGE`, `PRUFGATE_DIR` | `bin/prufgate` | Image for `--docker` (required: none is published), and the checkout to run. |
