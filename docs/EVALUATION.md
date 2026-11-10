# Measuring detection quality

PrufGate exposes a regression benchmark and an evaluation dashboard. Neither is a promise that unflagged code is correct or secure. Precision and recall depend on the rules enabled, language, framework, change scope and label quality.

## Reproduce a local dashboard

```sh
python3 prufgate/cli.py evaluate --cases bench/cases --format json --output reports/evaluation.json
python3 prufgate/cli.py evaluate --cases bench/evaluation --format html --output reports/accuracy.html
python3 prufgate/cli.py evaluate --cases bench/evaluation --format markdown
python3 prufgate/cli.py evaluate --cases PATH_TO_REVIEWED_CORPUS --independent-only
python3 prufgate/cli.py evaluate --cases bench/testdata/independent --independent-only --format html --output reports/independent-accuracy.html
```

HTML is standalone, searchable by rule/language/framework and uses no remote assets or network calls. Commands never publish. Review the artifact before sharing it through your normal release process. Reports export aggregate counts, case IDs, declared provenance and content hashes, not source trees, snippets or local workspace paths. Do not put personal data or credentials in labels. Redaction is best effort.

The existing `bench` format remains compatible. The evaluator uses the offline core scanner by default; externally labeled TLS cases explicitly select the deterministic `review` profile. Mixed runs have separate profile groups. Safe Git settings and case-rule scoring apply to both. Input code is not executed and AI is disabled. A failed engine or malformed corpus exits 2 and produces no new accuracy report. An old output file may remain after failure: consumers must check the command's exit code. Exit 0 means measurement completed, not that every case passed.

TP, FP and FN retain the existing benchmark meanings for complete labels: every unexpected rule is an FP. Reproducible upstream cases can use **explicit partial labels**: only the named rules are scored, while unrelated findings are exported as unscored. An upstream test of one rule is not exhaustive ground truth for every other rule. FPR has a **different denominator**: only explicit `must_not_fire` opportunities for that rule. TN is the number of those opportunities without a hit. A zero denominator is `null`/`n/a`, never perfect accuracy. Rules with only negative examples remain visible. Corpus coverage lists rules with positive/negative labels and untested catalog rules, including rules not enabled in this profile. Group case counts are not per-rule denominators. Multi-language case labels combine languages; do not sum overlapping slices as independent evidence. Frameworks are declared, never inferred from a filename.

JSON reports include tool version, implementation fingerprint, profile, case content hashes, label provenance and separate language, framework, project, origin, split, label-basis and independent-review groups. The implementation fingerprint hashes the installed package's Python source so unreleased local changes are distinguishable from a release with the same version. This is descriptive corpus agreement: no statistical confidence or representative population coverage is claimed. Compare equivalent settings and corpus versions. The regression benchmark includes defaults, opt-in packs and intentionally adversarial project configuration; it is not an unconfigured production sample.

## Independent labels and permitted open-source input

`bench/evaluation/` contains 12 synthetic syntax/control-flow cases across Python, JavaScript and TypeScript, including asyncio. They are regression examples, **not independently labeled evidence**. Existing maintainer cases remain a separate origin.

`bench/testdata/independent/` adds **58 cases derived from permitted Bandit, ESLint and PMD sources**, covering Python, JavaScript, Java, requests and httpx patterns. Labels come from upstream fixture expectations or Bandit's retained TLS specification, independent of PrufGate detector authorship. Their extraction, mapping, original source hashes, project revisions, license evidence and modifications are reproducible offline. The corpus requires byte-for-byte source derivation before admitting those labels; it does not invent reviewer identities. See the [external corpus](../bench/testdata/independent/README.md) and its [first baseline](../bench/testdata/independent/BASELINE.md). This evaluates two rule families, not every PrufGate check, and is not a new human-adjudicated production dataset.

Additional txtar cases can put this mapping in `label.yaml`:

```yaml
evaluation:
  language: python
  framework: fastapi
  origin: open-source
  author: case-author-role
  reviewers: [independent-reviewer-role]
  split: holdout
  source:
    url: https://example.com/project
    revision: FULL_40_OR_64_CHARACTER_GIT_HASH
    path: src/handler.py
    license: SPDX_LICENSE_ID
    permission: Link to license/permission evidence and retained attribution
```

Open-source cases require all source fields, HTTPS and a full pinned revision; the illustrative placeholders above will be rejected. This metadata records a permission claim, not an automated license determination. A maintainer must verify redistribution permission, retain the required license/notice alongside the corpus, remove secrets/personal data and document modifications before adding code. Never import a private project or assume that public visibility grants redistribution rights. The evaluator downloads nothing and runs no build/install commands.

Have someone other than the detector/case author label expected rules **before examining scanner output**. Record adjudication and the reason for each positive/negative in the case description and repository review. Use project-disjoint training and holdout sets, deduplicate near-identical cases, freeze holdout labels, record sampling criteria and preserve disagreements. Do not tune detectors against the holdout repeatedly. Reviewer labels are declarations, not identity authentication; protected review supplies verification. `--independent-only` requires a holdout and a reviewer label different from the author (case/whitespace normalized). It refuses an empty eligible set. Do not invent reviewers merely to satisfy this gate.

For upstream evidence, `label_basis: upstream-fixture` or `upstream-specification` requires a frozen local manifest, pinned sources/licenses and reproducible case derivation. Reviewer arrays remain empty for that evidence because no new human review is claimed. `label_scope: explicit` scores only named expectations. These reserved forms are verified by the corpus adapter, not accepted based on the label string alone.

**Current coverage:** two rule families across three upstream projects, reproducible provenance/permission checks, and a first measurement with disagreements preserved. The dataset is exposed; it is not a blind holdout for subsequent tuning. It does not measure deployment-wide precision/recall, representative production PRs or fresh human-adjudicated mappings. Fixture agreement must not be presented as production accuracy.

## Language-aware exception analysis

The Python `canned-error-fallback` path now parses `ast` rather than scanning a short text window. It detects literal success/approval dictionaries in reachable exception-handler returns, including multiline and async code. Returns inside nested helpers, strings and statements after a return/raise or an always-false branch do not count. Both terminating branches end the containing flow.

This is bounded intraprocedural analysis, not a general CFG or dataflow engine. Loops, nested try/finally, indirect return values, aliases, side effects and interprocedural exception propagation are not modeled. Unsupported Python syntax retains the existing textual fallback and therefore its uncertainty; this rule remains medium confidence. Other languages retain their existing heuristics. See the new positive/negative cases and `test_quality_evaluation.py`.

## Cross-file review leads

```sh
python3 prufgate/cli.py impact --workspace . --base origin/main
```

Run at a Git repository root. The read-only command maps Python imports and calls (including aliases and relative imports), schema classes connected through imports, literal route/client paths, and literal `open` calls for workspace configuration files. It follows reverse dependencies transitively from modified, deleted and new files to callers and tests. It emits relationships and affected paths as review leads, **not automatic blocking findings**. Inspect affected tests and callers when reviewing a signature/schema/configuration change.

The analysis caps Python files at 500 and file contents at 1 MB. Symlinks, unreadable files, unsupported syntax and truncation are disclosed and exit 2. A complete graph means the bounded supported pass completed; it does not mean all dependencies were resolved. Dynamic imports, monkey-patching, binding shadowing, generated code, non-Python clients, HTTP methods, route templates and arbitrary configuration readers remain unsupported. Source is never imported or executed. No external network or AI is used.
