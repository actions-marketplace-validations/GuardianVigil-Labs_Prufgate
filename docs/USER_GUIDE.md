# User guide

Use a checkout with the documented features installed as described in [Upgrading](UPGRADING.md). These commands run from the repository you want to review. Scans read source and Git diffs; they do not execute that repository's code. Differential/mutation verification and explicitly enabled repository hooks have separate execution opt-ins.

## Run a local review

Initialize configuration, then scan the workspace:

```sh
prufgate init .
prufgate check . --format result --result-out reports/prufgate-result.json
```

Review a change against an available comparison base:

```sh
prufgate check . --changed --base origin/main --format result --result-out reports/prufgate-result.json
prufgate review --workspace . --base origin/main --format markdown
```

`check` runs the core engines; `review` adds deterministic diff-review rules as a separate scan. The shell battery includes review and external scanners:

```sh
./prufgate.sh fast .
./prufgate.sh full .
```

The battery needs a checkout or matching container and its documented dependencies. It is broader than `prufgate check`. Fetch the intended comparison base through your normal Git workflow; an unknown base is an error. See [changed scope](GETTING_STARTED.md#which-changes-changed-means).

## Interpret the result

| Field or code | Meaning |
|---|---|
| `scan_status: clean` | Completed selected checks have no active findings |
| `findings` | Findings exist, including advisory findings that do not block |
| `incomplete` | Some requested verification could not finish |
| `error` | An engine, configuration, input or result validation failed |
| Exit `0` | No effective policy blockers and no incomplete/error state |
| Exit `1` | Effective policy blockers exist |
| Exit `2` | The scan cannot establish a pass |

Inspect `coverage`, skipped/failed checks and their reasons before accepting a result. Unknown counts are not zero. `severity` describes risk; `blocking` describes the effective enforcement decision. A P0/P1 finding can remain advisory during adoption, but protected guardrail-integrity findings remain blocking. Errors and incomplete verification always exit 2.

Findings carry rule IDs, confidence, reasoning, suggested fixes, caveats and bounded source evidence. Read the evidence in context:

```sh
prufgate explain canned-error-fallback
prufgate check . --changed --base origin/main --no-code --format result
```

`--no-code` removes source excerpts/detail fields, not every identifier from messages. Suggested fixes require review. The [result contract](SCAN_RESULTS.md) explains formats and coverage measurements.

## Adopt enforcement gradually

For an existing repository, add this to `.prufgate/config.yaml`:

```yaml
enforcement:
  mode: advisory
```

After reviewing a rule's precision, select it explicitly:

```yaml
enforcement:
  mode: selected
  blocking_rules: [unimplemented-production-stub]
  minimum_confidence: high
```

`strict` is the default. Configuration changes in a PR are evaluated against trusted base settings and require normal review; they do not weaken their own scan. Use `prufgate baseline .` for recorded debt only after reviewing what it records. Baseline entries and numeric debt allowances are different concepts. See [configuration](CONFIGURATION.md) and [enforcement](REVIEW_WORKFLOW.md#gradual-enforcement).

## Handle a finding

Fix the underlying behavior and rerun with the same scope. `prufgate fix --base origin/main` previews supported deterministic patches; `--apply` writes them, subject to safety checks. It does not fix every finding.

When an exception is justified, request a reviewed dismissal from a saved result:

```sh
prufgate dismiss request --workspace . --result reports/prufgate-result.json --finding 1 --owner owning-team --actor requester-role --reason 'Documented intentional behavior'
prufgate dismiss list --workspace .
prufgate dismiss approve DISMISSAL_ID --workspace . --actor reviewer-role --reason 'Reviewed with the owning team'
```

Actor labels are declared metadata, not authenticated identity. Protect the ledger with CODEOWNERS and branch protection. Optional expiration, revocation, exact fingerprints and base-only application are described in [reviewed dismissals](REVIEW_WORKFLOW.md#reviewed-dismissals). Approvals in the same PR do not suppress its own findings. Legacy inline ignores still require reasons; optional owner/expiry metadata does not constitute a reviewed approval.

## Review a PR

Run the Action with matching implementation versions and a fetched base. `profile: core` matches equivalent core CLI/API/MCP/editor scans; `profile: battery` includes additional checks. Execution errors remain fatal even when `fail_on_blocker` is false.

For a battery report:

```sh
prufgate pr-summary . --base origin/main
prufgate pr-summary . --previous-sarif reports/previous.sarif
prufgate github-check --workspace . --result reports/prufgate-result.json --base origin/main --output reports/check-preview.json
```

The summary separates active findings, debt, reviewed dismissals, coverage gaps and next actions. New/existing comparisons need compatible reports with stable fingerprints. The Check command previews locally; publishing requires explicit `--post-check`, a repository and an environment token with `checks: write`. Publication also requires matching clean scan provenance. Neither preview command posts to GitHub. Fork PR publication restrictions and Action setup are in [CI integration](CI_INTEGRATION.md).

## Check related changes and rule accuracy

```sh
prufgate impact --workspace . --base origin/main
prufgate bench --cases bench/cases --format markdown
prufgate evaluate --cases bench/testdata/independent --independent-only --format html --output reports/independent-accuracy.html
```

`impact` provides bounded Python relationships and transitive review leads for callers/tests/schema imports, literal routes and configuration reads. It does not prove runtime breakage or analyze every language. Evaluation commands need a corpus from a checkout. The external dataset covers two rule families; its fixture agreement is not deployment-wide accuracy. See [evaluation](EVALUATION.md).

## Choose an integration and protect data

Use the [API](API.md) for authenticated job-based scans, [MCP](MCP.md) for local client tools, or [VS Code](../editors/vscode/README.md) for inline diagnostics. Keep profile, base, scope, policy and tool versions equal when comparing results.

External AI is off by default and requires explicit consent in addition to trusted configuration. Reporting, live probing and registry lookups have separate destinations/permissions. Redaction is best effort; inspect artifacts and permitted destinations before transmitting code. See [privacy](SCAN_RESULTS.md#external-ai-consent-and-destinations) and [supported scope](SUPPORT_MATRIX.md).
