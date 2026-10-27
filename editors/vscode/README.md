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

Maintainers publish a release with `npm run publish` (it builds the extension first).

## Use

- Saving a file checks again after a short pause.
- **PrufGate: Check workspace** in the Command Palette checks every folder of the workspace.
- The status bar shows the error, warning and information counts; click it to check again.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `prufgate.path` | `prufgate` | The program to run: a command name looked up on `PATH`, or an absolute path. Read from user or remote settings only. |
| `prufgate.scope` | `changed` | `changed` runs `prufgate check --changed --format json`; `workspace` runs `prufgate check --format json` on the whole folder. Read from user or remote settings only. |
| `prufgate.runOnSave` | `true` | Check again after a save. Read from user or remote settings only, so a repository cannot switch it off. |

## Safety

- **Trusted workspaces only.** In Restricted Mode the extension is not activated and runs nothing.
- **A workspace cannot choose the program.** `prufgate.path` is a machine-scoped setting, so a `.vscode/settings.json` in a repository cannot point it at another binary. A command name is looked up in the absolute `PATH` entries only, never in the workspace folder; relative paths are refused.
- **No shell.** The CLI is started with an argument list, from the workspace folder, and stopped after two minutes.
- **No secrets.** The CLI gets a minimal environment (`PATH`, home and temporary directories, locale) and AI adjudication is switched off (`PRUFGATE_NO_AI_ADJUDICATE=1`), so the editor's API keys and tokens never reach it.
- **Missing CLI.** If `prufgate` is not found, the extension says so once, with the install command, and does nothing else until you run the check command or change a setting.

## Development

```sh
npm ci
npx tsc --noEmit -p .
npm test          # node:test unit tests for the JSON-to-diagnostics mapping and CLI lookup
```

The extension's version always equals the PrufGate package version (`tests/test_vscode_extension.py`).
