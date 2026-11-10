# REST API

The API runs scans on a local, existing checkout. It does not clone a repository or install/run its application. Prefer asynchronous scans for jobs that may outlast the HTTP deadline.

## Start and authenticate

Install from a matching checkout as described in [Upgrading](UPGRADING.md). Set `PRUFGATE_API_TOKEN` through your environment or secret manager, then start from the permitted workspace root:

```sh
PRUFGATE_WORKSPACE_ROOT="$PWD" prufgate api --host 127.0.0.1 --port 8000
```

The service defaults to loopback. Non-loopback binding requires an explicitly configured token. For remote access, use authenticated TLS ingress and network restrictions; do not expose an unauthenticated service. If no token is configured, local startup generates one: keep terminal output private.

| Endpoint | Authentication |
|---|---|
| `/health`, `/api/v1/health`, `/docs`, `/api`, `/openapi.json` | Public service/schema information |
| Scan submission, status, list, cancellation and artifacts | Bearer token |
| `/api/v1/webhook` | Its own configured webhook secret/signature check |

Interactive schema documentation is at `/docs`; the machine-readable schema is `/openapi.json`. Neither endpoint grants scan access. No CORS access is granted for arbitrary browser origins.

## Submit, poll and retrieve

```sh
curl --fail-with-body -sS http://127.0.0.1:8000/api/v1/scan \
  -H "Authorization: Bearer $PRUFGATE_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"workspace":".","battery":"fast","profile":"core","async":true}'
```

A successful asynchronous submission returns HTTP 202 with `scan_id` and relative URLs for status, SARIF and Markdown. Replace `SCAN_ID` below with that returned ID:

```sh
curl --fail-with-body -sS -H "Authorization: Bearer $PRUFGATE_API_TOKEN" http://127.0.0.1:8000/api/v1/scans/SCAN_ID
curl --fail-with-body -sS -H "Authorization: Bearer $PRUFGATE_API_TOKEN" http://127.0.0.1:8000/api/v1/scans/SCAN_ID/sarif
curl --fail-with-body -sS -H "Authorization: Bearer $PRUFGATE_API_TOKEN" http://127.0.0.1:8000/api/v1/scans/SCAN_ID/report
```

Job `status` (`queued`, `running`, `completed`) is separate from the finished `scan_status` (`clean`, `findings`, `incomplete`, `error`). A completed job can be an error or contain blockers. Use the common result, exit code, coverage and error reasons to decide whether verification passed. An artifact request while the job is active returns 202.

`GET /api/v1/scans` lists retained records. `DELETE /api/v1/scans/SCAN_ID` cancels an active job or removes a finished record and its per-scan artifacts. Cancellation/timeout stops the scan process and reaps it before removal; platform process-containment limitations still apply. Repeated deletion of a missing record returns 404.

## Request fields

| Field | Default | Meaning |
|---|---|---|
| `workspace` | `.` | Path confined to `PRUFGATE_WORKSPACE_ROOT` |
| `battery` | `review` | `fast`, `check`, `review` or `full`; choose explicitly for reproducibility |
| `profile` | `battery` | `core` runs equivalent core checks; `battery` uses the checkout battery when available |
| `async` | `true` | Use `false` only for scans shorter than the connection deadline |
| `dry_run` | `false` | Validate parameters without starting a scan; not a scan result |
| `target_url` | omitted | Explicit live-probe target with the battery profile; the operator must authorize the target |

The core profile is static and rejects `target_url`. The API disables external AI adjudication. An inherited `TARGET_URL` does not enable probes. Installed-package battery fallbacks can have different coverage from a checkout/container; inspect the returned profile/coverage and use `core` for equivalence. See [scan results](SCAN_RESULTS.md).

## Limits, retention and failures

| Environment variable | Default | Purpose |
|---|---:|---|
| `PRUFGATE_API_MAX_SCANS` | 2 | Concurrent scan jobs |
| `PRUFGATE_API_SCAN_TIMEOUT` | 600 | Scan process timeout in seconds |
| `PRUFGATE_API_HTTP_TIMEOUT` | 30 | Total HTTP connection deadline in seconds |
| `PRUFGATE_API_MAX_CONNECTIONS` | 16 | Concurrent HTTP connections |
| `PRUFGATE_API_MAX_HISTORY` | 200 | Retained finished records |
| `PRUFGATE_API_RETENTION_SECONDS` | 86400 | Finished-record/artifact retention |

Set variables before server startup. Active jobs are not removed by retention. The server periodically cleans finished records and eligible orphaned per-scan directories. The shared latest validated report is separate; retention is not a guarantee that every copy of an artifact is deleted.

Expect 400/415 for malformed requests, 401 for invalid credentials/signatures, 403 for a forbidden workspace, 404 for missing records/artifacts, 413 for oversized bodies and 503 when capacity is unavailable. Supply one `Content-Length`, no transfer encoding, and complete the request within its deadline. A timeout, missing engine output or invalid artifact cannot produce a passing scan.

## Webhooks

Set `PRUFGATE_WEBHOOK_SECRET` to enable `/api/v1/webhook`. GitHub uses a SHA-256 HMAC body signature (`X-Hub-Signature-256`); GitLab uses its configured token header. Configure the provider to send only intended events. Requests are rejected when the secret is missing or invalid. Webhook scans use the configured local default workspace; payload repository names do not authorize arbitrary filesystem access or fetch application code. Keep that checkout synchronized through your own trusted deployment workflow.

Reports can contain source identifiers and infrastructure names from the repository being scanned. Keep API access and stored artifacts private as appropriate, and review them before sharing. See [security guidance](../SECURITY.md#running-prufgate-safely).
