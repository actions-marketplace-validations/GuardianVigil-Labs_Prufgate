# Installation and upgrading

Documentation in this checkout includes unreleased behavior. The published package/image tagged `1.4.0` remains that release's implementation. An unchanged version string in a development checkout does not make it equivalent to a published artifact.

## Choose an implementation

| Installation | Use |
|---|---|
| `pipx install prufgate` | Isolated published CLI/MCP/API release |
| `pip install .` from a reviewed checkout | This checkout's Python commands |
| Built zipapp | Standalone Python CLI; no MCP server or shell battery |
| Checkout shell gate | Core/review engines plus configured external scanners |
| Matching container built from the checkout | Reproducible battery dependencies and the checkout's commands |

For development features, use a reviewed commit and install/build it explicitly:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
python -m pip install --no-deps .
python -m prufgate.cli --self-check
```

Build the checkout's container through its Dockerfile or documented build command. Keep Action code and image from the same implementation; the Action's default released image cannot acquire unreleased options merely because the Action reference changes. Set `execution: container` and `image` explicitly when selecting a custom matching image, or choose validated native execution.

Pin CI actions to reviewed commit SHAs. Retain the intended Git base (`fetch-depth: 0`) and use explicit profiles for comparable results. Verify signed published releases as described in [SECURITY.md](../SECURITY.md#verify-a-release).

## Compatibility and stricter failures

- Legacy JSON arrays and SARIF remain available. Use `--format result` or `--result-out` for the common envelope with status, coverage, explanations and privacy.
- Job lifecycle and scan outcome are separate in API/MCP integrations. Completed does not mean passed. Preserve `incomplete` and `error` states; an empty or malformed artifact is not a clean scan.
- Missing/invalid engine output and unreadable scan input fail closed. Action `fail_on_blocker: false` does not suppress execution errors.
- Severity is retained independently from `blocking`. Strict enforcement is the default; advisory and selected-rule modes require reviewed configuration. Protected guardrail findings remain blocking.
- Trusted base configuration/baselines/dismissals apply to a PR. New approvals and weakened settings do not apply to the same change that introduces them.
- External AI needs explicit consent in addition to trusted configuration. AI adjudication remains disabled in API, MCP, hooks and editor integrations.
- Optional GitHub Checks publication is off by default. Explicit publishing requires the correct token permissions and matching clean scan provenance; fork PR restrictions apply.
- API cancellation, timeout, request/scan concurrency and artifact retention have explicit limits. Review deployment variables rather than relying on unbounded history or long-held HTTP connections.

## Upgrade checklist

1. Review the [changelog](../CHANGELOG.md) and [supported scope](SUPPORT_MATRIX.md).
2. Pin matching CLI/Action/image versions or source commits and install their dependencies.
3. Run a core scan with an explicit base and save its versioned result.
4. Inspect coverage, disabled/skipped engines and status before comparing findings.
5. Review any policy/configuration changes through the normal maintainer process.
6. Exercise the API/MCP/editor integration you actually deploy; compare equivalent profiles.
7. Keep generated reports private as appropriate and review them before sharing.

Existing reviewed exceptions do not authenticate their declared identities. Repository ownership and branch protection remain necessary. See [review workflows](REVIEW_WORKFLOW.md) and [API operation](API.md).
