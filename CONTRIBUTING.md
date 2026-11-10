# Contributing

Thank you for helping. The most useful contributions are new rules with good fixtures, fixes for false positives, and support for more languages and frameworks.

1. Read the maintainer guide, [AGENTS.md](AGENTS.md) (for people and AI tools alike).
2. Branch from `main` and open a pull request. Direct pushes to `main` are not accepted; every change needs a code owner's review.
3. Before pushing, run:
   ```sh
   python3 prufgate/cli.py --self-check
   python3 -m unittest discover -s tests
   ruff check --config configs/ruff.toml prufgate/ tests/
   ```
4. A new or changed rule comes with at least one invented sample it must flag and one near miss it must not. A bug fix comes with a test that fails without it.
5. Fixtures use invented code, `example.com` domains and documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Never paste private code into a test, an issue or a pull request.

## Reporting a problem

- A bug: open a **Bug report** issue.
- A false positive or a missed pattern: open a **False positive or false negative** issue with a minimal invented sample.
- A new rule, pack, language or integration: open a **Rule, pack or feature request**.
- A security issue: report it privately, see [SECURITY.md](SECURITY.md).

## Licence of contributions

By opening a pull request you agree that your contribution is licensed under the [Apache License 2.0](LICENSE), like the rest of the project (section 5 of the licence).

## Maintainers

PrufGate is maintained by the GuardianVigil team, listed as the `@GuardianVigil-Labs/prufgate-maintainers` code owners. Maintainers review and merge pull requests, triage issues, and cut releases by pushing a `v*` tag, which only admins can create (`SECURITY.md` says how releases are built and verified). Decisions are made in public issues and pull requests; security reports stay private until fixed.

### Releasing the VS Code extension

The same `v*` tag publishes the VS Code extension (`editors/vscode`): the release workflow builds and tests it, refuses a tag that differs from the version in `editors/vscode/package.json` (kept equal to `prufgate.__version__` by `tests/test_vscode_extension.py`), attaches the `.vsix` to the GitHub release with its provenance, and publishes that same file to the Visual Studio Marketplace. Pre-release tags (`1.4.0-rc.1`) are not published to the Marketplace, which does not accept them. Bump `package.json` and `package-lock.json` with the other version files.

One-time setup, done by an admin:

1. In Azure DevOps, signed in with an account that manages the `GuardianVigil` Marketplace publisher, create a personal access token with organization **All accessible organizations** and the scope **Marketplace > Manage**. Give it the shortest expiry you are willing to renew.
2. In the repository settings, **Environments > New environment**, create `vscode-marketplace`. Add required reviewers (recommended) and limit deployment to `v*` tags.
3. In that environment, add the secret `VSCE_PAT` with the token. Store it nowhere else.

If the secret is missing or expired, the Marketplace job fails with a message and nothing is published; the GitHub release still carries the `.vsix`. Fix the secret and re-run the failed job.
