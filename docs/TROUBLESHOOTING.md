# Troubleshooting

Read `scan_status`, `exit_code`, `coverage`, `errors` and `incomplete_reasons` together. Exit 2 means the result cannot establish a pass. Preserve diagnostics while removing credentials and private names before sharing them.

| Symptom | Check |
|---|---|
| Unknown base or no usable comparison | Fetch the intended ref and retry with `--base origin/main`. Use full history in CI. Do not substitute an empty diff for an unavailable base. |
| CLI clean, battery has more findings | Compare profiles. The battery adds diff review/external scanners; core CLI/API/MCP/editor scans can be equivalent only with matching settings and scope. |
| No findings but scan is incomplete/error | Repair the failed engine, probe or input. No confirmed findings is not proof of a completed scan. |
| Tool is marked skipped | Read its coverage reason. Install/enable it if required for your intended profile. A skipped optional scanner is not verified coverage. |
| Missing or malformed report | Check the engine's status/log and output location. Do not reuse an old report as evidence of a new pass. |
| Files cannot be read or a symlink is refused | Fix access or move the intended file inside the permitted workspace. The scanner does not silently treat unreadable input as clean. |
| P0/P1 finding does not fail adoption policy | Inspect `blocking` and effective enforcement. Advisory/selected modes retain original risk severity; protected guardrail findings still block. |
| PR policy or dismissal does not take effect | Trusted base settings apply. Have a maintainer review/merge the change before expecting it to suppress or weaken its own findings. |
| Dismissal unexpectedly stops applying | Check expiry, revocation and exact file/rule/fingerprint. Changed finding-line content can invalidate the match. |
| Check publishing is refused | Regenerate the scan from the same clean committed checkout, inspect provenance, token `checks: write`, fork restrictions and the requested repository. |
| Check annotations are missing | Only changed lines are annotated; unchanged/outside paths and capped entries are counted as omitted. Read the complete artifact and comparison-base status. |
| API returns 401/403 | Check bearer credentials, webhook signature mode and workspace confinement. Never solve access errors by disabling authentication. |
| API returns 503 | Review connection/scan capacity, active jobs and webhook configuration. Retry within deployment limits. |
| HTTP connection closes during a synchronous scan | Use asynchronous submission and poll the returned ID, or set a suitable total connection deadline. |
| Historical artifact is gone | Retention or explicit deletion may have removed it. Keep required artifacts through your own approved storage policy. |
| Editor shows an error or stale diagnostics | Restore the trusted CLI, fix the scan failure and rerun. Old counts stay stale until a successful scan verifies current edits. |
| MCP client cannot start the server | Confirm its executable path and environment. Use a trusted pip/checkout install; MCP is not included in the zipapp. |
| Evaluation reports low recall or disagreement | Inspect case IDs, upstream labels, profiles and policy differences. Measurement success does not mean every detector case passed. |

`prufgate explain RULE` supplies rule-specific guidance. `prufgate check --no-code --format result` omits source evidence/detail fields but may still expose names in messages. Inspect any diagnostic artifact before attaching it to a public issue.

For suspected vulnerabilities, follow [private security reporting](../SECURITY.md). Include a minimal invented reproduction and relevant versions; omit real credentials, private repository names, machine addresses and infrastructure hostnames.
