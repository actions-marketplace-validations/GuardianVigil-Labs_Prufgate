# PrufGate documentation

PrufGate checks production behavior, test integrity, review guardrails and selected contract and authorization patterns. Results describe the scope that completed; a clean scan is not proof that a change is correct or secure.

This documentation describes the current checkout. Options in the **Unreleased** changelog may not exist in the published 1.4.0 package or image. Follow [installation and upgrades](UPGRADING.md) when using the checkout's features, and keep CLI, Action and container implementations aligned.

## Start here

| Task | Guide |
|---|---|
| Install and run your first scan | [Getting started](GETTING_STARTED.md) |
| Follow a local-to-PR review workflow | [User guide](USER_GUIDE.md) |
| Interpret status, coverage, evidence and privacy | [Scan result contract](SCAN_RESULTS.md) |
| Configure scope, confidence, debt and suppressions | [Configuration reference](CONFIGURATION.md) |
| Adopt advisory or selected-rule enforcement and review dismissals | [Developer and PR workflow](REVIEW_WORKFLOW.md) |
| Choose supported checks and understand limitations | [Support matrix](SUPPORT_MATRIX.md) and [engine reference](ENGINES.md) |

## Integrations and operation

- [CI integration](CI_INTEGRATION.md): Action inputs/outputs, execution modes, summaries, SARIF and opt-in Checks.
- [REST API](API.md): authentication, asynchronous scans, cancellation, webhooks, limits and retention.
- [MCP](MCP.md): client setup, tool scope, result semantics and execution boundaries.
- [VS Code](../editors/vscode/README.md): installation, configuration, diagnostics and stale/error states.
- [Agent hooks](AGENT_HOOKS.md): supported event protocols and shell-command guards.
- [Troubleshooting](TROUBLESHOOTING.md): unknown bases, failed checks, missing tools and integration differences.
- [Upgrading](UPGRADING.md): compatibility, behavior changes and installation choices.

## Extending and evaluating

- [Developer guide](DEVELOPMENT.md): repository layout, local checks and contribution workflow.
- [Architecture](ARCHITECTURE.md): shared scan/result pipeline and trust boundaries.
- [Custom rules](CUSTOM_RULES.md): declarative rules and explicitly enabled hooks.
- [Regression benchmark](BENCHMARK.md): maintainer cases and score definitions.
- [Detection evaluation](EVALUATION.md): external-label provenance, accuracy dashboards and Python change impact.
- [External corpus](../bench/testdata/independent/README.md): retained permissions, extraction method and first measurement.
- [Changelog](../CHANGELOG.md), [contribution guide](../CONTRIBUTING.md) and [security policy](../SECURITY.md).

Examples use standard loopback addresses and reserved example destinations. Supply credentials through your own environment or secret manager. Review generated reports before sharing: source identifiers and names can remain after redaction.
