# Product scope and support

PrufGate reviews code for fabricated behavior, ineffective tests, weakened guardrails and selected contract/authorization risks. It supplements human review and established development tools. A clean result establishes only that the selected checks completed without active policy blockers in the measured scope.

| Area | Implemented support | Practical limits |
|---|---|---|
| Production fabrication | Built-in Python, JS/TS and selected Go/Rust/Java/C#/Ruby/PHP patterns | Heuristics vary by rule; not complete semantic verification |
| Python exception returns | AST and bounded reachable-return analysis | No whole-program dataflow, loop or nested-finally reasoning |
| Test integrity and change tampering | Selected test frameworks, Git diff rules, threshold/suppression edits | Legitimate edits need review; coverage is not assertion correctness |
| Contracts and dependencies | Manifest/import, environment and literal API checks | Dynamic paths, generated clients and custom build systems can be unresolved |
| Static authorization | Selected route/query patterns; see engine documentation | External middleware and ownership models need human verification |
| Live BOLA | Explicit target and test identities | Only tested identities/resources; operator must authorize target access |
| Cross-file impact | Python imports/calls, schema imports, literal routes and config opens | Standalone review leads; other languages and runtime dispatch unsupported |
| Accuracy evaluation | Offline case-rule metrics, explicit negative denominators, language/framework/project strata, 58 upstream-derived cases | Two rule families; fixture agreement is not production accuracy or new human adjudication |
| CLI, API, MCP, VS Code | Common versioned result for equivalent core scans | Different profiles/scope/external scanners have different coverage |
| GitHub Action and Checks | Native/container execution; opt-in annotations and summary publishing | Matching trusted implementation required; write permissions/fork restrictions apply |
| Enforcement and dismissal | Strict/advisory/selected rules; reviewed ledger with reason/owner/expiry | Declared actors need CODEOWNERS/branch protection; no authenticated review service |
| AI review | Explicit opt-in providers; privacy metadata and redaction | Sensitive content can remain after best-effort redaction; model output is untrusted |

## Deployment guidance

Use Python 3.9+ and dependencies from the pinned requirements for CLI/core scans; install from a trusted release or isolated environment. Git is needed for changed scans, benchmarks and impact analysis. Full shell batteries also need the external scanners documented in [CI integration](CI_INTEGRATION.md). Select native/container execution explicitly when reproducibility matters, and keep the Action, CLI and image versions aligned. A released older image does not contain unreleased local changes.

Use Linux CI for the complete battery. Deterministic unit tests and core checks can run on macOS; tool availability varies. Windows repository-test execution is deliberately refused where POSIX containment is unavailable. VS Code requires the declared editor version and a trusted installed CLI. See its README for supported settings.

Start in advisory mode and review findings against your codebase before promoting selected rules. Keep guardrail changes and exception ledgers under protected maintainer review. Fetch the intended comparison base; shallow clones or unknown refs cannot establish a changed-scan pass. Preserve scan artifacts/status together and treat exit 2 as incomplete/error regardless of adoption policy. For API deployments bind loopback or a controlled private interface, require authentication, configure retention/concurrency/timeouts and put authenticated TLS ingress in front of remote access. Never expose the API directly to the internet by default.

Scans read source; repository tests/hooks are disabled unless explicitly authorized. Optional differential/mutation verification executes repository code: use disposable isolated CI with minimum credentials and no access to production systems. On Linux process cleanup uses subreaper adoption and procfs parent information; environments must expose enough process metadata. Alternate procfs implementations can omit per-thread children files, so the runner falls back to parent IDs from process status files. These controls are not an operating-system sandbox.

## Complementary tools

Continue using compiler/typechecker checks, framework test suites, linters, dependency/SCA and license analysis, secret scanning, security SAST, API integration tests and dynamic authorization testing. Gitleaks and other optional battery tools retain their own scope and licenses. PrufGate does not replace penetration testing, supply-chain review, deployment monitoring or a qualified security review.

See [engine checks](ENGINES.md), [evaluation methodology](EVALUATION.md), [scan results and privacy](SCAN_RESULTS.md), [configuration](CONFIGURATION.md) and [developer workflow](REVIEW_WORKFLOW.md) for exact contracts. Unsupported or unmeasured coverage must not be presented as verified safety.
