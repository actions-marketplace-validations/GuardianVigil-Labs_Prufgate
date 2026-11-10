# Developer and pull request workflow

The versioned [scan result](SCAN_RESULTS.md) separates risk severity from enforcement, records reviewed exceptions, and feeds PR summaries and GitHub Checks. These features do not push commits or change repository settings.

## GitHub Checks and inline annotations

Prepare a reviewable payload locally:

```sh
prufgate check --changed --base origin/main --format result --result-out reports/prufgate-result.json
prufgate github-check --base origin/main --output reports/check-preview.json
```

The second command prints and optionally saves the payload. It makes no HTTP request. To publish intentionally, pass `--post-check --repo OWNER/REPOSITORY` and provide `PRUFGATE_CHECKS_TOKEN` in the environment. The token needs `checks: write`; no token is accepted on the command line or included in the payload.

The Check attaches to the commit recorded by the scan. Publication requires the same clean committed checkout: uncommitted source changes, missing provenance and a different HEAD are refused before any request. Generated `reports/` artifacts do not make source dirty. A local dirty scan can still produce a preview; commit the reviewed source and regenerate the scan before publishing. Preview payloads are not attestations, and publication assumes the supplied scan artifact is trusted.

Only findings on added or modified lines receive inline annotations. Paths outside the repository and findings on unchanged lines are omitted from annotations and counted in the summary; they remain in the full result. A missing or unusable comparison base is disclosed, rather than placing annotations on arbitrary lines. A failed scan still yields a failing Check when its commit is known. Annotation uploads use batches of at most 50 and a cap of 1000 per run, with omitted counts reported. No source-code evidence or live response body is added to annotation messages.

The Check summary shows scan status, coverage, failed/skipped checks, adoption mode and next actions. Blocking findings, errors and incomplete scans conclude `failure`; advisory-only findings conclude `neutral`; a completed scan with no findings concludes `success`. On rerun, an older matching Check is cancelled and replaced so GitHub's append-only annotation updates cannot duplicate old annotations. If upload fails partway, the replacement Check is not marked completed. API redirects are refused so credentials cannot be forwarded to another destination.

Enable publication in the composite Action:

```yaml
permissions:
  contents: read
  checks: write

steps:
  - uses: actions/checkout@<commit-sha>
    with: { fetch-depth: 0, persist-credentials: false }
  - uses: GuardianVigil-Labs/Prufgate@<commit-sha>
    with:
      execution: container
      github_checks: 'true'
```

`github_checks` defaults to false. `checks_token` defaults to `github.token` and reaches only the opted-in publishing step. Fork pull requests skip publication with a notice because their tokens are normally read-only; the local scan result and ordinary job result remain available. Do not use `pull_request_target` to expose a write token to fork code. Use a container built from the same implementation as the action checkout. Checks publishing errors fail the reporting step but do not rewrite the stored scan result.

## Reviewed dismissals

Reviewed exceptions are stored in `.prufgate/dismissals.json`, a versioned event ledger. They match an exact file, canonical rule ID and fingerprint, not a rule-wide wildcard. The fingerprint follows the existing baseline algorithm: normalized finding-line content and an occurrence counter. Moving a line can preserve a dismissal; editing the line invalidates it. Changes elsewhere in a handler are not proof that its reviewed context is unchanged, so use ownership, expiration and normal code review as well.

Request review of one finding from a recent result:

```sh
prufgate dismiss request --result reports/prufgate-result.json --finding 1 \
  --owner owning-team --actor requester-role --reason 'Documented intentional behavior' \
  --expires 2027-12-31
prufgate dismiss list
prufgate dismiss approve DISMISSAL_ID --actor reviewer-role --reason 'Reviewed with the owning team'
```

Finding indices are 1-based. Ownership and reasons are required. Expiration is optional and valid through that UTC date. `reject` refuses a pending request; `revoke` cancels an approved one, always with an explicit actor and reason. Requesters cannot approve their own request, including differences only in case or surrounding whitespace. Expired, rejected, revoked and pending requests suppress nothing. A new reviewed request is needed to extend an expired exception.

Commands modify only the local ledger. They never commit, push, contact GitHub, or infer an identity from this machine. Actor and owner labels are declared review metadata, **not authenticated proof of a GitHub review**. Protect the ledger and enforcement configuration with CODEOWNERS and branch protection requiring the owning maintainer's review. Configure those controls yourself; the tool does not grant authority to a label.

Each event links to its predecessor's hash. The parser rejects broken chains, duplicate IDs, self-approval, invalid state transitions and rewritten history relative to the trusted comparison base. A local lock prevents concurrent command writes from losing audit events. This is a tamper-evident record, not a signature; an authorized maintainer can rewrite hashes, so version control and protected review remain the authority. Redacted audit details are included in result artifacts; verify a complete chain against the version-controlled ledger itself.

In a Git scan the ledger at the comparison base applies, or committed HEAD when no base is provided. Approvals added by the branch do not apply to its own scan; a protected review finding makes the proposed exception visible. In a directory without Git, local policy and ledger files apply. Guardrail-integrity findings cannot be dismissed. A malformed ledger is a scan error, including in advisory mode.

Legacy reasoned inline ignores and existing configuration exemptions remain supported; they are not silently presented as reviewed approvals. Inline ignores can also record owner and expiration:

```python
return cached  # prufgate-ignore: rule-id -- Safe immutable fallback [owner=owning-team; expires=2027-12-31]
```

Metadata is not a substitute for a reason. Invalid or expired metadata is refused and the finding remains active. Honoured and refused inline decisions are included in `governance.inline_audit`, with their reason and observation time. The versioned ledger supplies the permanent reviewed history. Agent shell hooks refuse mutating `prufgate dismiss` commands and protect `.prufgate/`; an operator must perform the review. Shell filtering is not authentication or a sandbox.

## Gradual enforcement

Add `enforcement` to the normal PrufGate configuration:

```yaml
enforcement:
  mode: advisory
```

This reports findings with their original P0–P3 severity but makes ordinary findings advisory. After validating precision, select specific rules:

```yaml
enforcement:
  mode: selected
  blocking_rules:
    - unimplemented-production-stub
  minimum_confidence: high
```

`strict` is the default: P0/P1 findings block. `selected` blocks only named P0/P1 rules meeting the confidence cutoff; its default cutoff is `high`. `advisory` blocks no ordinary finding. Exact aliases are accepted; wildcards and unknown policy fields are rejected. A confidence label is the scanner's declared confidence, not proof of precision on your repository: use the benchmark corpus and reviewed findings before promoting a rule.

Results keep original `severity` and add `blocking` plus an enforcement reason. The common summary, CLI/Action exit code, API/MCP result, editor, JUnit failures and Checks conclusion use the effective blocking decision. The editor renders nonblocking P0/P1 findings as warnings while retaining their original severity in the message. Raw engine entry points still describe detector findings; the unified CLI and battery decide project enforcement.

**Execution errors and incomplete verification always exit 2.** Protected gate-integrity findings also remain blocking in every adoption mode. A PR cannot weaken itself by editing enforcement: the trusted base policy applies, and a policy change is a protected finding requiring maintainer review. In non-Git directory scans the supplied local configuration is authoritative.

## Actionable PR summaries

The existing `prufgate pr-summary` and Action job summary/comment now add:

- the canonical scan status and effective enforcement mode;
- baseline matches, registered known-debt entries and numeric debt allowances, distinguishing allowances from measured counts;
- applied reviewed dismissals and pending/expired requests with owning labels;
- measured input coverage, failed/incomplete checks, skipped engines and their reasons;
- recommended next actions for verification failures, blockers, advisory triage and debt reduction.

Compare with a saved previous report when available:

```sh
prufgate pr-summary --previous-sarif reports/previous.sarif
```

Only matching scan profiles/scopes with stable finding fingerprints receive new/existing comparisons. Missing fingerprints or mismatched coverage produce an explicit unknown classification. Without a previous report, the summary does not invent a new-finding count. “No longer reported” is a fingerprint set difference, not proof that a vulnerability was fixed; confidence, suppression and baseline changes can affect it. Compare runs with equivalent configuration as well as equivalent profiles. Reading a previous report never checks out, runs or modifies its source repository.

Reports without versioned workflow metadata still receive recommendations, with unknown coverage/debt marked as unknown. Text copied from a repository is redacted and escaped before it enters a PR summary. Source snippets and raw secret matches are not included. Publishing a summary comment still requires the existing explicit `--post-comment` or Action `pr_comment` option; neither is enabled by these features.
