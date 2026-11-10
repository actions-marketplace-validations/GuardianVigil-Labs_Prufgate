# MCP integration

PrufGate exposes ten tools over stdio. Install a trusted CLI from the implementation you intend to run; do not point a client at a command supplied by an untrusted repository.

## Configure a client

Add this to the client's MCP server configuration:

```json
{
  "mcpServers": {
    "prufgate": {"command": "prufgate", "args": ["mcp"]}
  }
}
```

The client starts `prufgate mcp` and communicates over stdin/stdout. Keep server diagnostics on stderr; application text on stdout can corrupt the protocol. A pip/checkout install supports MCP; the standalone zipapp does not include the MCP server. See [installation](UPGRADING.md).

## Tools and scope

| Tool | Scope |
|---|---|
| `prufgate_fast_scan` | Core engines on changed files, using the resolved base |
| `prufgate_full_scan` | Whole-workspace core checks plus diff review; optional explicit live target |
| `prufgate_anti_fabrication` | Production-fabrication checks |
| `prufgate_test_audit` | Test-integrity checks |
| `prufgate_diff_guard` | Guardrail changes in a diff |
| `prufgate_contract_check` | Dependency, environment and route contracts |
| `prufgate_bola_check` | Static authorization patterns; live checks only with `target_url` |
| `prufgate_review` | Deterministic diff-review rules |
| `prufgate_summary` | Read the last stored report |
| `prufgate_explain` | Offline rule explanation |

Discover exact arguments through MCP `tools/list`. Scan tools use `workspace_path`; applicable tools also expose `base_ref`, `changed_only` or `target_url`. `prufgate_explain` takes `rule`. Supply a known comparison ref explicitly when reproducibility matters.

A representative fast scan uses:

```json
{"workspace_path":".","base_ref":"origin/main"}
```

The tools do not edit project source or execute its application/tests. Engine artifacts are directed to temporary storage. The summary tool reads an existing report and does not establish that it matches current edits; run a new scan to verify current source.

## Results and errors

MCP compatibility `status: ok|error` is separate from common `scan_status`. A tool can complete successfully and return blocking findings. Incomplete verification and execution errors set MCP `isError` and cannot be presented as a pass. Use `scan_status`, `exit_code`, `passed`, `summary`, `findings`, `coverage`, `errors` and `incomplete_reasons` together.

Core equivalence requires the same checkout, base, scope, configuration, baseline, confidence and enforcement. The full tool is `core+review`, not the shell battery with external scanners. Do not compare different profiles as equivalent coverage. See [scan results](SCAN_RESULTS.md).

External AI adjudication is disabled in MCP even when enabled in the parent environment. An explicit live target still authorizes network probing; supply only a service the operator is authorized to test. The tool does not install dependencies, run mutation/differential verification or turn repository hooks on.

When a tool reports an unknown base, unreadable result or engine timeout, repair the input/dependency and rerun. Keep the failure visible to the calling client. If the CLI is not found, install it where that client process can resolve it, or configure an absolute path to a trusted executable. See [troubleshooting](TROUBLESHOOTING.md).
