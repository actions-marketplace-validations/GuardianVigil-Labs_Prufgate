# PrufGate for VS Code

Shows [PrufGate](https://github.com/GuardianVigil-Labs/Prufgate) findings inline: production code that fakes its result, tests that cannot fail, and checks weakened in a diff. Each finding is a diagnostic in the editor and the Problems panel, with its rule ID (linked to [the engine reference](https://github.com/GuardianVigil-Labs/Prufgate/blob/main/docs/ENGINES.md)) and its confidence.

| Severity | Shown as |
|---|---|
| P0, P1 (blocking) | Error |
| P2 | Warning |
| P3 | Information |

## Install

The extension runs the `prufgate` command you install; it does not bundle it.

1. Install the CLI: `pipx install prufgate`
2. Install the extension from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=GuardianVigil.prufgate): search **PrufGate** in VS Code's **Extensions** view, or run `code --install-extension GuardianVigil.prufgate`.

To build it from source instead (Node.js 22 or later), from this folder:

```sh
npm ci
npm run package
code --install-extension prufgate-<version>.vsix
```

Releases are published from version tags by the release workflow; `CONTRIBUTING.md` has the one-time setup.

## Use

- Saving a file checks again after a short pause.
- **PrufGate: Check workspace** in the Command Palette checks every folder of the workspace.
- The status bar shows the error, warning and information counts; click it to check again.
- A failed scan stays visible as **scan error** until a successful retry. Its tooltip gives the reason for each workspace folder. Previous diagnostics remain labelled **PrufGate (stale)**, so they cannot appear current after a timeout or CLI failure.
- The editor consumes the common `clean`, `findings`, `incomplete` and `error` states. Incomplete scans remain visibly incomplete while retaining confirmed findings. Tooltips include measured file/line coverage, and diagnostics include reasoning, confidence, suggested corrections and caveats.
- Editing a document marks existing results stale. A scan finishing after an edit cannot replace them with a result for the previous document version. Counts are current only after a successful scan of that version.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `prufgate.path` | `prufgate` | The program to run: a command name looked up on `PATH`, or an absolute path. Read from user or remote settings only. |
| `prufgate.scope` | `changed` | `changed` runs `prufgate check --changed --format result`; `workspace` runs `prufgate check --format result` on the whole folder. Read from user or remote settings only. |
| `prufgate.runOnSave` | `true` | Check again after a save. Read from user or remote settings only, so a repository cannot switch it off. |

## Safety

- **Trusted workspaces only.** In Restricted Mode the extension is not activated and runs nothing.
- **A workspace cannot choose the program.** `prufgate.path` is a machine-scoped setting, so a `.vscode/settings.json` in a repository cannot point it at another binary. A command name is looked up in the absolute `PATH` entries only, never in the workspace folder; relative paths are refused.
- **No shell.** The CLI is started with an argument list, from the workspace folder, and stopped after two minutes.
- **No secrets.** The CLI gets a minimal environment (`PATH`, home and temporary directories, locale) and AI adjudication is switched off (`PRUFGATE_NO_AI_ADJUDICATE=1`), so the editor's API keys and tokens never reach it.
- **Missing CLI.** The status bar keeps the error and install instructions visible. A later save, check command or settings change retries the lookup.

## Development

```sh
npm ci
npm run build
npm run typecheck
npm test          # mapping, CLI lookup, lifecycle, and extension host callback tests
npm run test:integration  # compare editor parsing with real CLI output (Python + PyYAML required)
```

The extension's version always equals the PrufGate package version (`tests/test_vscode_extension.py`).
CI runs compilation, typechecking and tests on Linux and Windows with Node.js 24 and the committed dependency lockfile.
Use a CLI that supports result schema 1.0; older JSON-only CLI output is reported as an error, never a clean scan. [Result format and privacy](../../docs/SCAN_RESULTS.md) describes profiles and AI controls. Editor scans always disable AI adjudication.
