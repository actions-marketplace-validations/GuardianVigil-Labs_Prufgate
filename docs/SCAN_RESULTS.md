# Scan results, coverage and privacy

`prufgate check --format result` emits the versioned result contract used by integrations. `--result-out reports/prufgate-result.json` also saves it locally. The shell battery writes the same file automatically. `review`, `bola` and `test-audit` support `--format result` too.

## Status and exit codes

| `scan_status` | Meaning | Exit code |
|---|---|---|
| `clean` | Requested checks completed and reported no active findings. | 0 |
| `findings` | Checks completed and reported findings. | 1 with P0/P1 blockers; 0 with only P2/P3 advisories. |
| `incomplete` | A requested verification could not be established, such as a failed live-probe control. Confirmed findings remain in the report. | 2 |
| `error` | Invalid input, engine failure, unreadable output or another execution error. Confirmed findings remain when available. | 2 |

Errors take precedence over incomplete checks; incomplete checks take precedence over findings. `passed` is false for either error state and for blocking findings. A zero exit code alone does not mean there were no advisory findings.

Project [enforcement policies](REVIEW_WORKFLOW.md#gradual-enforcement) can make ordinary findings advisory or block only selected rules. `blocking` is independent of original risk severity; errors and incomplete checks remain fatal. Versioned results also include effective `enforcement`, reviewed-dismissal `governance`, and Git `revision` metadata. Protected gate-integrity findings remain blockers.

Every result includes `schema_version: "1.0"`, `scan_status`, `profile`, `exit_code`, `passed`, `findings`, `summary`, `coverage`, `errors`, `incomplete_reasons`, and `privacy`. Finding counts are derived from the active findings, after confidence filtering, suppression and baseline handling. Existing CLI `--format json` arrays remain available. New clients should use `result` to distinguish an empty completed scan from one that did not run.

The REST API keeps `status: queued|running|completed` for job lifecycle and exposes `scan_status` when finished. MCP keeps its compatibility `status: ok|error` and adds the common fields; incomplete tools also set MCP `isError: true`. The Action exposes `scan_status` and `result_path`. SARIF carries the status, coverage and privacy metadata in `runs[0].properties.prufgate`, with explanation and evidence properties on active results. Legacy `PASSED`, `FAILED`, and `ERROR` verdicts remain for existing integrations.

## Equivalent scan profiles

For equivalent core scans, use the same checkout, base ref, configuration, baseline, confidence settings and scope:

| Integration | Core scan |
|---|---|
| CLI | `prufgate check . --changed --base origin/main --format result` |
| GitHub Action | `profile: core`, `battery: fast`, `base_ref: origin/main` |
| MCP | `prufgate_fast_scan` with the same workspace and `base_ref` |
| REST | `POST /api/v1/scan` with `{"profile":"core","battery":"fast","workspace":"."}`; configure `PRUFGATE_BASE_REF` in the service environment. |
| VS Code | Changed scope, using the same installed scanner and checkout. The editor resolves the default base like the CLI. |

Core scans run Engines 1–5, with diff guard when diff input exists. Engine 6 and external scanners are explicitly listed as outside this profile. The Action's default `battery` profile additionally runs diff review and available external scanners; those results are intentionally broader. MCP full scans also add diff review and optionally live probes, and do not run the external scanners. Compare matching profiles rather than expecting different coverage to yield identical findings.

Use an Action container image built from the same scanner version as the action checkout. A container that does not emit the result status file fails with an error rather than having its output guessed. The editor similarly requires the versioned format; older CLI output produces a visible scan error.

## What coverage measures

`files_checked` and `lines_checked` count unique successful file reads by Python engines, including source context and manifests. Repeated reads count once. The report lists each measured file and its line count. This is static input coverage, not a claim that every line was subject to every rule, and not runtime branch or test coverage. Reads of Git's stored base blobs are not included in workspace file-read totals.

Changed core scans also report `lines_in_scope`: added/modified lines in measured files, separate from whole-file context read by an engine. Removed lines and diff-only input can be checked without being present in workspace file-read counts. Report folders and `.git` internals are excluded from these measurements.

Coverage lists configured exclusion patterns, built-in traversal policies and known skipped paths, with engine-specific reasons. Selection by file type and language still applies. An engine may read a file as context even when another engine excludes it from production rules. Coverage is not a complete enumeration of every ignored path on disk.

Engine entries identify completed, skipped, incomplete and failed checks and their reasons. Optional tools being unavailable, checks outside the selected profile, and missing diff input are visible skips. External scanners do not expose reliable input counts; their additional file/line coverage is explicitly unknown. Individual legacy engine tools likewise report unknown counters when they do not provide instrumentation. `null` means unknown, not zero. Confirmed finding counts do not substitute for coverage.

## Explainable findings

Each versioned finding includes its location, severity and confidence, plus:

- `explanation.reasoning`: what the rule detected;
- `explanation.suggested_fix`: the rule's recommended correction;
- `explanation.could_be_incorrect_when`: limitations or context to verify;
- `evidence`: a bounded, redacted source excerpt and its starting line, or a reason no safe excerpt is available.

Rule explanations come from the offline `prufgate explain` catalog. External or unknown rules use a conservative generic correction instead of inventing an exact patch. Suggested fixes require review; they are not automatically applied. Secret-scanner excerpts and live response bodies are omitted. `check --no-code --format result` omits excerpts and scanner detail fields; finding messages can still describe code and contain names.

## External AI consent and destinations

No external AI is used by default. `ai_adjudicate: true` permits adjudication in the trusted configuration but does not authorize transmission on its own. Also pass `check --ai-adjudicate`, explicitly set `PRUFGATE_ALLOW_EXTERNAL_AI=1` for a local CLI/battery invocation, or set the Action input `allow_external_ai: 'true'`. The Action defaults this permission off. The API, MCP tools, agent hooks and editor disable AI adjudication even when the parent environment permits it. `review --ai` separately consents to AI diff review.

| Provider | Destination | Content |
|---|---|---|
| OpenAI-compatible | `OPENAI_BASE_URL` plus `/chat/completions`, default `https://api.openai.com/v1/chat/completions` | Review: redacted unified diff, including paths, names and code. Adjudication: rule, finding message and bounded code window. |
| Anthropic | `https://api.anthropic.com/v1/messages` | Same content categories. |
| Ollama | `OLLAMA_HOST` plus `/api/chat`, default localhost on port 11434 | Same categories; a configured host may be remote. |
| Local agent CLI | The selected CLI and its configured provider; downstream destination is not visible to PrufGate | The review or adjudication prompt. Explicitly named Codex, Gemini and OpenCode CLIs can still access files; their own settings may allow additional reads. |

`privacy.external_ai` records the permission, resolved provider, destination, purpose, content category and redaction limitations. Permission does not prove a request was transmitted: findings may be skipped or verdicts served from cache. No provider's retention or training policy is implied by this metadata.

Review prompts redact known credential environment values, recognized token shapes and credential assignments. Adjudication skips a source window or message if redaction detects credentials, instead of sending a substituted window. Filenames, project names, identifiers, comments and application-specific sensitive data may remain. Redaction is best effort, not anonymization or a guarantee that all secrets were found. Inspect what you intend to send and choose the provider accordingly.

AI consent does not govern separately requested live HTTP probes or opt-in package-registry lookups. These have their own destinations and settings described in [ENGINES.md](ENGINES.md).

## Consistency tests

`tests/test_scan_result.py` runs equivalent real core scans through CLI, Action and API worker commands and MCP dispatch, comparing state, exit code, finding identity/severity, counts and measured files. Editor tests validate the same state policy and consume real CLI output without changing finding identity or severity. CI builds, typechecks and tests the extension, then runs its CLI integration test on Linux and Windows. Test fixtures are local and synthetic; no AI provider, webhook service, repository push or hosted workflow is needed.
