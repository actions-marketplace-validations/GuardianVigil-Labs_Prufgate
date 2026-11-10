# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes |

Security fixes go into the latest 1.x release. There are no releases before 1.0.0.

## Reporting a vulnerability

Please report vulnerabilities privately, never in a public issue:

- through GitHub's private vulnerability reporting: the **Security** tab of this repository, then **Report a vulnerability**; or
- by email to prufgate@guardianvigil.io.

Include the version or commit, what you ran, what happened and its impact. We aim to acknowledge a report within five working days, keep you informed until it is fixed, and credit you in the release notes if you wish.

## Scope

Especially in scope:

- a way for the repository being scanned to run code on the machine running PrufGate (PrufGate reads untrusted code; it must never execute it unless the operator opts in, see `PRUFGATE_ALLOW_REPO_HOOKS`);
- a scan that reports success when an engine crashed or could not read its input (PrufGate must fail closed);
- the REST API: a request that scans outside `PRUFGATE_WORKSPACE_ROOT`, works without the bearer token, or a webhook accepted without a valid signature;
- a secret (an API key, a bearer token used for live BOLA probes) written to a report, log or SARIF file;
- the MCP server or the agent hooks doing something other than what the tool call asked for;
- a branch that switches PrufGate off, or hides findings, without a blocking finding;
- the release pipeline: a way to publish a package, image or release that the maintainers did not tag.

Out of scope:

- a rule that misses a pattern or flags a false positive (open a normal issue);
- findings in third-party tools PrufGate can call (ast-grep, gitleaks, zizmor) or in an AI provider you choose;
- problems that need an already compromised machine.

## Running PrufGate safely

- **Only probe systems you own or are authorised to test.** Live BOLA probing sends requests to the target URL you give it, with the tokens you give it.
- **The REST API binds to `127.0.0.1` by default** and needs a bearer token (`PRUFGATE_API_TOKEN`) on every scan and report route. It refuses to bind a non-loopback address without one. Put it behind TLS if it leaves the host.
- **Scans through the API are confined to `PRUFGATE_WORKSPACE_ROOT`.** A workspace that resolves outside it, including through a symlink, is refused.
- **Webhooks are off until `PRUFGATE_WEBHOOK_SECRET` is set**, and every delivery must carry a valid GitHub `X-Hub-Signature-256` or GitLab `X-Gitlab-Token`.
- **Repository hook scripts (`.prufgate/hooks/`) never run unless `PRUFGATE_ALLOW_REPO_HOOKS=1`.** Leave it unset in CI jobs that scan pull requests from forks.
- **`prufgate verify --differential` and `prufgate verify --mutation` execute the repository's tests** (`--mutation` through a mutation tool already installed; PrufGate never installs one) and refuse to start without `--allow-run-tests` or `PRUFGATE_ALLOW_RUN_TESTS=1`. No other command, battery, hook, MCP tool or API route runs them. They run in a temporary worktree with a reduced environment and a timeout, but that is not isolation: use them only in a sandbox or disposable CI job.

### Scanner isolation and report privacy

Internal Python subprocesses use isolated mode (`-I`) and trusted installation
paths. Generated agent hooks use an isolated installed-module fallback: a source
checkout exposed only through `PYTHONPATH` is not an installation. Install PrufGate
or use its trusted launcher on `PATH`, and regenerate existing hook configuration
with `prufgate init --hooks` after upgrading. Git helpers disable repository hooks
and filesystem-monitor commands for every operation.

Source and report readers reject symbolic links by default, including links in
parent directories. Automatically discovered PrufGate configuration may link to
another file inside the same workspace; links outside it are refused. Report
writes use private temporary files and atomic replacement, preserving the targets
of planted file links and hard links. Directory links are refused. POSIX file
access uses directory descriptors; platforms without that support validate paths
and opened file identities but do not offer the same directory-race protection.

Gitleaks runs with full value redaction, and its matches are omitted from final
reports. Live BOLA findings omit response bodies. Provider prompts, provider
findings and report text share credential redaction for known environment values,
common token formats and credential assignments. These rules cannot recognize
every application-specific secret: use disposable jobs with minimal credentials,
review reports before sharing, and enable AI only when sending the redacted diff
to the selected provider is acceptable. AI review still transmits source code.

External AI also requires explicit invocation consent: `review --ai`, `check --ai-adjudicate`, or `PRUFGATE_ALLOW_EXTERNAL_AI=1` together with trusted enabled configuration. The Action defaults `allow_external_ai` to false; API, MCP, editor and hook scans disable adjudication. Provider destinations, transmitted content, redaction limits and result metadata are documented in [SCAN_RESULTS.md](docs/SCAN_RESULTS.md#external-ai-consent-and-destinations). Configuration alone does not authorize transmitting code.

## Verify a release

Every release is built by `.github/workflows/release.yml` from a `v*` tag. The only stored credential is the Visual Studio Marketplace token (`VSCE_PAT`, held in an approval environment); PyPI receives the packages through Trusted Publishing, and the container image is signed keyless with Sigstore. The wheel, the sdist, the zipapp, the VS Code extension and the image carry SLSA build provenance; the wheel and the image carry an SBOM. Replace `1.0.0` with the version you install.

**The wheel and sdist.** The files on PyPI are the same files as on the GitHub release, so their SHA-256 matches `SHA256SUMS` (pip checks it when you pin `--hash=sha256:...` in a requirements file used with `--require-hashes`).

```sh
# Download the release files, check them against SHA256SUMS and their provenance, then install the checked wheel:
gh release download v1.4.0 --repo GuardianVigil-Labs/Prufgate
sha256sum -c SHA256SUMS
gh attestation verify prufgate-1.4.0-py3-none-any.whl --repo GuardianVigil-Labs/Prufgate
# Or offline, with the attestations attached to the release:
gh attestation verify prufgate-1.4.0-py3-none-any.whl --repo GuardianVigil-Labs/Prufgate --bundle prufgate-1.4.0-py3-none-any.whl.intoto.jsonl
pip install ./prufgate-1.4.0-py3-none-any.whl
```

**The zipapp** (`prufgate.pyz`, one file that needs only Python 3.9+; releases after 1.0.0) is on the GitHub release, listed in `SHA256SUMS` and attested like the wheel. It is reproducible: `SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" python3 scripts/build_pyz.py` on the tagged commit gives the same SHA-256 (the build downloads the PyYAML sdist pinned and hash-checked in `requirements.txt`; the same zlib is assumed).

```sh
gh release download v1.4.0 --repo GuardianVigil-Labs/Prufgate --pattern prufgate.pyz --pattern 'prufgate.pyz.intoto.jsonl' --pattern SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
gh attestation verify prufgate.pyz --repo GuardianVigil-Labs/Prufgate
gh attestation verify prufgate.pyz --repo GuardianVigil-Labs/Prufgate --bundle prufgate.pyz.intoto.jsonl   # offline
python3 prufgate.pyz --version
```

**The VS Code extension** (releases after 1.3.0): `prufgate-<version>.vsix` on the GitHub release is the file published to the Visual Studio Marketplace, listed in `SHA256SUMS` and attested like the wheel: `gh attestation verify prufgate-<version>.vsix --repo GuardianVigil-Labs/Prufgate`, then `code --install-extension prufgate-<version>.vsix`.

PyPI also shows the Trusted Publishing provenance of each file (the "Verified details" and "Provenance" sections of the project page).

**The container image** (cosign v3 or newer; older versions do not read the signature format):

```sh
cosign verify ghcr.io/guardianvigil-labs/prufgate:1.4.0 \
  --certificate-identity "https://github.com/GuardianVigil-Labs/Prufgate/.github/workflows/release.yml@refs/tags/v1.4.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/guardianvigil-labs/prufgate:1.4.0 --repo GuardianVigil-Labs/Prufgate
```

Pin the image by the digest that `cosign verify` prints (`ghcr.io/guardianvigil-labs/prufgate@sha256:...`). The image SBOM is stored with the image in the registry (`docker buildx imagetools inspect ghcr.io/guardianvigil-labs/prufgate:1.4.0 --format '{{ json .SBOM }}'`); the wheel SBOM is `prufgate-wheel.cdx.json` on the GitHub release.

A file, image or signature that does not verify is not a PrufGate release: do not use it, and report it as described above.
