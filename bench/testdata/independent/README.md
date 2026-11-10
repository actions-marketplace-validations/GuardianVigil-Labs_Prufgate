# External evaluation corpus

This corpus contains **58 externally derived labeled examples** from three permitted public projects: Bandit (Python), ESLint (JavaScript) and PMD (Java). It evaluates two rule families: empty exception handlers in the core profile, and disabled TLS verification in the deterministic review profile. It includes requests and httpx client patterns.

Labels existed upstream before this PrufGate evaluation. They come from upstream fixture annotations, valid/invalid test lists, expected-problem assertions, or the independently authored Bandit B501 specification. The PrufGate adapter maps those concepts to named PrufGate rules. No additional human reviewers are claimed or invented. Mapping decisions remain reviewable and can disagree with project-specific policy.

## Reproduce offline

From the repository root:

```sh
python3 scripts/build_evaluation_corpus.py
python3 prufgate/cli.py evaluate --cases bench/testdata/independent --independent-only --format json --output reports/independent-evaluation.json
python3 prufgate/cli.py evaluate --cases bench/testdata/independent --independent-only --format html --output reports/independent-accuracy.html
```

The first command checks the frozen derivation; `--write` deliberately regenerates case files. It reads archived text, parses Python/JavaScript literals and XML, and executes none of the upstream source. Evaluation runs offline on throwaway Git repositories, with hooks/transports disabled and no AI delegation. Nothing is downloaded, installed, posted or published by these commands.

The corpus lives under the existing `testdata` convention so self-review does not mistake deliberately insecure examples for product code. Evaluation materializes every sample under `src/example.py`, `.js` or `.java` in its temporary repository: those examples are scanned as production files, not skipped as test data. Public-repository leak checks still inspect all tracked corpus files.

`manifest.json` pins project revisions, paths, original content hashes, archived evidence hashes, license hashes and source modifications. `upstream/` retains the relevant evidence, and `licenses/` retains upstream license texts. Cases are checked byte-for-byte against their source derivation before being treated as upstream-labeled. A changed label, code sample or profile invalidates that status. Hashes provide reproducibility within a trusted checkout, not signatures or authenticated human review; compare original hashes to the pinned public URLs when auditing the import.

## Selection and labels

The selection was declared before the first PrufGate scan, without examining which cases pass:

| Source | Cases | Selection and expected labels |
|---|---:|---|
| Bandit B110 | 5 | All `try_except_pass.py` good/bad blocks; typed exceptions follow the upstream `check_typed_exception=True` interpretation |
| Bandit B501 | 36 | Every requests/httpx call in `requests-ssl-verify-disabled.py`; literal `verify=False` is positive, enabled/default verification negative, according to the retained B501 predicate |
| ESLint `no-empty` | 6 | Default-option standalone valid catch strings and invalid default cases with an empty catch; other no-empty constructs and custom options are excluded |
| PMD `EmptyCatchBlock` | 11 | All default-property tests, resolving shared code fragments; positive when upstream expected-problems is nonzero |

Exact duplicate code within a rule/profile is deduplicated, conflicting duplicate labels are rejected. Cases measure rule presence, not the number or precise locations of findings. Parent fixture comments such as Bandit's “Okay” group do not label TLS calls: the published B501 predicate does. Source evidence and extraction code identify that distinction.

The cases are **partially labeled**. `must_fire` and `must_not_fire` supply expectations only for their named rule. Findings for other rules are recorded as unscored, not assumed to be false positives. The original maintainer benchmark keeps its complete-label accounting. Core and review profile groups must be interpreted separately; a pooled number is descriptive case-rule agreement, not an integration-equivalence or production-accuracy claim.

This import was selected before its first PrufGate scan, and no detectors were tuned during the import. No claim is made that earlier detector development never encountered similar public examples. Its first evaluation is recorded in `BASELINE.md` and `baseline.json`, without detector tuning. It is now an **exposed external validation set**, not a blind holdout for future work. Keep new projects/labels reserved if a later blind evaluation is needed.

## Permission, attribution and changes

- **Bandit**: Apache-2.0, upstream `PyCQA/bandit`, pinned in the manifest. The retained B501 specification includes its Hewlett-Packard Development Company, L.P. copyright and SPDX notice. Its full Apache license is retained in `licenses/bandit_license.txt`. Original fixture blocks are excerpted into added-file diffs. TLS destination URLs were replaced with `https://example.com`; verification flags, call names and labels were preserved. Both modified upstream text files carry a prominent modification notice.
- **ESLint**: MIT, copyright OpenJS Foundation and other contributors. The unmodified upstream test evidence retains its author attribution; the complete permission/copyright notice is retained in `licenses/eslint_license.txt`. Case strings are extracted from the independently authored valid/invalid lists and placed in `.txt` fixtures. No ESLint runtime is bundled or executed.
- **PMD**: the exact upstream combined BSD-style/Apache license is retained in `licenses/pmd_license.txt`; it must not be simplified to a generic BSD-3-Clause claim. It includes copyright (c) 2003–2009 InfoEther, LLC. Case code is excerpted from XML tests without changing its logic. Required acknowledgement: **This product includes software developed in part by support from the Defense Advanced Research Project Agency (DARPA).**

All source revisions and license grants were read from the public upstream repositories during import. Public availability alone was not treated as reuse permission. Retain the README, manifest, evidence and license files together when redistributing this corpus. The root project license does not replace upstream terms. The runtime package does not need this optional corpus.

## Limits

These are upstream test examples, not a random sample of production PRs. Three languages, two HTTP client libraries and two rule families do not establish quality for every PrufGate check or framework. Rule semantics differ: ESLint accepts comments in empty catches; PMD has naming/comment conventions; Bandit B110 can be configured to inspect typed exceptions. An apparent miss/disagreement needs scope and policy review before classification as a product defect. No fresh independent human adjudication or comprehensive inter-rater agreement is claimed.

Representative production-project changes, more rule families and independently adjudicated mappings remain expansion work. Preserve disagreements and false negatives; do not prune cases to improve the displayed score. Source snippets are public, destination values are sanitized and no personal credentials, private repositories or local workspace paths are included. Evaluation exports metrics/provenance rather than the source trees.
