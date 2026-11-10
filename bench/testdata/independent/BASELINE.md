# First external baseline

This is the first untuned measurement of the frozen external corpus. The selected examples and upstream-derived labels were fixed before PrufGate was run on them. No detector rules were changed to improve these results. `baseline.json` records the implementation fingerprint, evidence-manifest fingerprint, profile slices, scores and individual disagreements. Reproduce with the commands in README.md; implementation fingerprints will change when package source changes.

| Rule and profile | Cases | TP | FP | FN | Explicit TN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| Empty catch, core | 22 | 4 | 3 | 9 | 6 | 0.571 | 0.308 |
| Disabled TLS verification, review | 36 | 9 | 0 | 9 | 18 | 1.000 | 0.500 |
| Pooled case-rule agreement | 58 | 13 | 3 | 18 | 24 | 0.812 | 0.419 |

These numbers describe agreement with these specific upstream expectations. They are not global PrufGate accuracy. The nine explicit negative empty-catch examples yield FPR 3/9 = 0.333; the eighteen TLS negatives yield FPR 0/18 = 0. Unlabeled rules are not counted against precision. No unscored findings occurred in this first run.

## Findings and interpretation

- **Python B110 typed exception:** one upstream-positive typed `ZeroDivisionError` case is missed by PrufGate's broad-exception heuristic. Bandit can be configured either way; this corpus explicitly follows its typed-exception inspection interpretation. This needs scope/policy review before being treated as a detector defect.
- **Java empty catch:** all eight upstream-positive PMD cases are missed. Inspection confirms that PrufGate's current Java catch branch recognizes canned success returns but does not emit empty-catch findings. This identifies an unsupported check for that language, not a completed Java semantic analysis.
- **JavaScript comment-only catches:** three cases are flagged by PrufGate but accepted by ESLint's default `no-empty` convention. An explanatory comment is sufficient for ESLint; PrufGate's exception heuristic is stricter. Preserve and adjudicate this policy difference rather than silently relabeling it.
- **TLS HTTP method/client coverage:** nine positive cases are missed. Inspection of the deterministic TLS matcher shows that `patch`, `options`, `head`, `stream`, `Client` and `AsyncClient` forms are absent from the recognized alternatives. These are concrete review-coverage gaps for requests/httpx patterns. No network probe or example code was executed to establish them.

There were no evaluation-environment failures in this measurement. Low recall is preserved as evidence. The integrity/reproduction tests are expected to pass even when the detector misses a labeled case: measurement success is distinct from detection success.

This now-exposed set is suitable for regression/validation, not a subsequent blind evaluation. Its two rule families and fixture labels do not establish deployment-wide quality or fresh independent human adjudication.
