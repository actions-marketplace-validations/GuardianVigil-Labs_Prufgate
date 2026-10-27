# Benchmark

`prufgate bench` measures how often PrufGate is right, on a labelled corpus kept in this repository (`bench/cases/`). Tools in this space rarely publish precision; this page publishes ours, misses included, and the corpus that produced it.

**Read the numbers with care.** The corpus is small, and the maintainers wrote it, cases and labels alike, alongside the engines they measure. It is a regression floor and a statement of what PrufGate is meant to catch, not an independent evaluation. Cases from other people, especially changes PrufGate gets wrong, are the most useful contribution you can make (see [Adding a case](#adding-a-case)).

## Running it

From a checkout of this repository:

```sh
prufgate bench                                  # text report for bench/cases
prufgate bench --format markdown                # tables for a pull request
prufgate bench --format json                    # machine-readable
prufgate bench --rule test-skip-smuggling       # score one rule
prufgate bench --min-precision 1.0 --min-recall 1.0     # exit 1 below either floor
```

`--cases DIR` points at another corpus. Exit codes: 0 a report, 1 below a `--min-precision` / `--min-recall` floor, 2 a malformed case or an engine error (never a score).

The corpus is not installed with the package (the wheel holds `prufgate/` only, and the sdist has no `MANIFEST.in` entry for `bench/`), so outside a checkout `prufgate bench` needs `--cases DIR`. A built-in subset would be a second copy to keep in step for little gain: anyone who wants to check the numbers wants the full corpus and its history anyway.

## Methodology

For each case `prufgate bench`:

1. creates a throwaway git repository in a temporary directory, commits the case's `base/` files, then replaces them with its `head/` files and commits again;
2. runs the same engines as `prufgate check --changed --base <base commit>` (Engines 1 to 5) in process, with default configuration unless the case carries a `.prufgate/config.yaml`;
3. compares the set of rule IDs reported with the case's label.

Nothing in a case is executed: the engines read source text and git diffs, as they do in `check`. Socket connections are refused for the duration of the run and `PRUFGATE_REGISTRY_CHECK` is unset, so the opt-in registry lookup never runs. A section path with a `.git` segment anywhere (any case) is refused, and every git call during the run, the engines' own included, gets `core.fsmonitor=false`, `core.hooksPath=/dev/null`, `diff.ignoreSubmodules=all` and `protocol.allow=never` through `GIT_CONFIG_COUNT`, so a nested repository in a case cannot run a command.

Accounting is per case and per rule, not per finding line:

- a rule in `must_fire` that was reported is a **true positive**;
- a rule in `must_fire` that was not reported is a **false negative**;
- **every other rule reported is a false positive**, whether or not the case lists it in `must_not_fire`. `must_not_fire` documents the near miss a case was written for; it does not limit what counts against precision.

Precision is TP / (TP + FP) and recall is TP / (TP + FN), summed over all cases (micro-averaged), and also given per rule. Rule aliases (old and new IDs of one rule, listed in `prufgate/config.py`) count as one rule, shown under the name the labels use.

The corpus has two kinds of case. Cheat cases are changes an agent might make to get a check to pass without doing the work; each names the rule that should catch it. Clean cases are ordinary changes (refactors, real fixes, parametrised test merges, legitimate test removals and moves, stricter configuration, scoped routes, documented environment variables, suppressions with reasons) where nothing should fire. Clean cases are what make precision mean something: a tool that flags everything has perfect recall.

Labels state what *should* happen. When the engines disagree with a label, the miss is reported; the label is changed only if the label was wrong (for example a weakened test that also ends up with no assertions at all, where `zero-assertion-test` is correct too).

## Current results

Measured on this commit's corpus (122 cases), `prufgate bench`:

```text
122 cases; precision 1.000, recall 1.000 (TP 70, FP 0, FN 0)

  always-current-fake-timestamp              TP   1  FP   0  FN   0  P 1.000  R 1.000
  always-true-equality                       TP   1  FP   0  FN   0  P 1.000  R 1.000
  canned-error-fallback                      TP   6  FP   0  FN   0  P 1.000  R 1.000
  caught-and-ignored-test-exception          TP   1  FP   0  FN   0  P 1.000  R 1.000
  coverage-threshold-lowering                TP   1  FP   0  FN   0  P 1.000  R 1.000
  diff-assertion-weakening                   TP   2  FP   0  FN   0  P 1.000  R 1.000
  diff-test-count-drop                       TP   3  FP   0  FN   0  P 1.000  R 1.000
  diff-test-file-deleted                     TP   8  FP   0  FN   0  P 1.000  R 1.000
  disconnected-form-submit                   TP   2  FP   0  FN   0  P 1.000  R 1.000
  documentation-ip-or-domain                 TP   1  FP   0  FN   0  P 1.000  R 1.000
  frontend-backend-route-mismatch            TP   1  FP   0  FN   0  P 1.000  R 1.000
  linter-or-ci-config-weakening              TP   2  FP   0  FN   0  P 1.000  R 1.000
  prompt-invents-finding                     TP   1  FP   0  FN   0  P 1.000  R 1.000
  prufgate-config-not-applied                TP   1  FP   0  FN   0  P 1.000  R 1.000
  prufgate-config-self-exemption             TP   1  FP   0  FN   0  P 1.000  R 1.000
  pytest-collection-deselect                 TP   1  FP   0  FN   0  P 1.000  R 1.000
  pytest-result-rewrite                      TP   1  FP   0  FN   0  P 1.000  R 1.000
  self-mocked-unit-under-test                TP   1  FP   0  FN   0  P 1.000  R 1.000
  simulated-return-value                     TP   1  FP   0  FN   0  P 1.000  R 1.000
  snapshot-blind-update-or-empty             TP   1  FP   0  FN   0  P 1.000  R 1.000
  static-bola-unscoped-access                TP   3  FP   0  FN   0  P 1.000  R 1.000
  suppression-comment-smuggling              TP   3  FP   0  FN   0  P 1.000  R 1.000
  synthetic-delay-mock                       TP   2  FP   0  FN   0  P 1.000  R 1.000
  tautological-assertion                     TP   2  FP   0  FN   0  P 1.000  R 1.000
  test-config-weakening                      TP   1  FP   0  FN   0  P 1.000  R 1.000
  test-fake-exit                             TP   3  FP   0  FN   0  P 1.000  R 1.000
  test-input-special-casing                  TP   3  FP   0  FN   0  P 1.000  R 1.000
  test-runner-monkeypatch                    TP   1  FP   0  FN   0  P 1.000  R 1.000
  test-script-neutered                       TP   1  FP   0  FN   0  P 1.000  R 1.000
  test-skip-smuggling                        TP   3  FP   0  FN   0  P 1.000  R 1.000
  undeclared-or-hallucinated-import          TP   2  FP   0  FN   0  P 1.000  R 1.000
  undocumented-env-var-drift                 TP   1  FP   0  FN   0  P 1.000  R 1.000
  unimplemented-production-stub              TP   3  FP   0  FN   0  P 1.000  R 1.000
  unsafe-type-cast-cascade                   TP   1  FP   0  FN   0  P 1.000  R 1.000
  zero-assertion-test                        TP   4  FP   0  FN   0  P 1.000  R 1.000
```

Corpus by category: 54 clean, 17 fabrication, 11 deleted test, 8 hollow test, 6 configuration weakening, 4 harness edit, 4 suppression, 4 contract, 3 BOLA, 3 fake exit, 3 skipped test, 5 weakened test. By language (cases touching at least one such file): Python 49, TypeScript/TSX 43, Go 18, JavaScript 1, plus configuration files (JSON, TOML, INI).

No misses on this corpus. That says the corpus is small and written by the people who wrote the engines, not that PrufGate catches everything; send the cases it gets wrong.

What the last round of fixes changed (the previous measurement was precision 0.961, recall 0.831 on 90 cases):

- **Parametrised tests count per case.** `diff-test-count-drop` counts `@pytest.mark.parametrize` with a literal list (stacked decorators multiply), `it.each([...])` / `test.each([...])` with an array, and a Go test that runs a literal `[]struct{...}` or map table with `t.Run`, once per case. Merging copy-pasted tests into one parametrised test with as many cases is no drop; cutting cases from a parametrised test whose `def` line is unchanged is one. Copies of one case count once, and cases whose parameters the test body never uses count as one. A modified test file still in the working tree is counted whole on both sides, so cases cut far from the test's definition line count too. A case list held in a variable counts as one case.
- **A test retired with its feature is not reported.** When a deleted test file's first-party imports are all deleted by the same diff (Python `import` / `from ... import`, relative JavaScript or TypeScript imports, or for Go every non-test file of its package), `diff-test-file-deleted` stays silent and its tests do not count as a drop. Deleting the feature is the decision under review, not a hidden failure. A test is still reported when any module it imports stays (deleting a helper, a fixtures file, a package `__init__.py` or a Go `doc.go` beside it is not enough), or when a name the deleted module defined and the test uses is defined again in an added line elsewhere (the feature moved, it was not retired).
- **Error paths answering with a hard-coded success.** `canned-error-fallback` covers a Python or JavaScript handler returning a decision field set to true (`approved`, `valid`, `verified`, `authorized`, `allowed`, `passed`) and a Go `if err != nil { return true, nil }`. A Python handler now ends at its dedent, so code after it is not read as part of it.
- **`except: pass`.** `unhandled-empty-catch` covers a Python `except:`, `except Exception:` or `except BaseException:` whose body is only `pass` or `...`. A narrow `except FileNotFoundError: pass` is not reported.
- **Other shapes:** a one-line dict with a literal number or boolean under a "simulated" comment (`simulated-return-value`), a sleep before `{"status": "complete"}` (`synthetic-delay-mock`), a judgement asked for in prose inside a prompt string (`"Give a risk_score from 0 to 100"`, `prompt-invents-finding`), `with patch("pkg.mod.func")` of the function under test (`self-mocked-unit-under-test`), an unfilled `toMatchInlineSnapshot()` (`snapshot-blind-update-or-empty`), and a `"test"` script inside a one-line `"scripts": {...}` object (`test-script-neutered`).
- **Hunks cut off by the diff context.** A Python hunk whose trailing context opens a block with no body (`@pytest.fixture` / `def user():`) now parses with those context lines dropped, so `test-runner-monkeypatch` sees a `unittest.TestCase.assertEqual = ...` above it. Added lines are never dropped.

The unit test `tests/test_bench.py` runs the corpus with `--min-precision 1.0 --min-recall 1.0`: a change that lowers either fails the build. A new case PrufGate gets wrong lowers them; lower the floor to the new measurement in the same pull request and say why.

## Adding a case

A case is one file, `bench/cases/<case-id>.txt`, in a txtar-like format: a `-- name --` line starts each section.

```text
-- label.yaml --
category: skipped-test
description: "A failing test silenced with pytest.mark.skip and no issue."
must_fire: [test-skip-smuggling]
must_not_fire: []
-- base/tests/test_parse.py --
def test_parse():
    assert parse(" 4 ") == 4
-- head/tests/test_parse.py --
import pytest


@pytest.mark.skip(reason="fails")
def test_parse():
    assert parse(" 4 ") == 4
```

- `category` is one of `fabrication`, `hollow-test`, `weakened-test`, `fake-exit`, `deleted-test`, `skipped-test`, `harness-edit`, `config-weakening`, `suppression`, `contract`, `bola`, `clean`. `description` is one line (quote it if it contains a colon).
- `must_fire` lists the rules that must be reported; leave it empty for a clean case. `must_not_fire` names the rule a near miss is aimed at.
- `base/<path>` and `head/<path>` sections are the files before and after the change. A file only in `base/` is deleted by the change, one only in `head/` is added. Unchanged files the scan needs (a `requirements.txt`, a `.env.example`) go in both.
- Name the file `<category-prefix>-<language>-<what>.txt`, for example `skip-py-mark-skip.txt` or `clean-go-wrap-error.txt`.
- Invent everything: no code copied from other projects, no real company or product names, `example.com` addresses only, no secrets, not even fake-looking ones.
- Label what *should* happen, run `prufgate bench`, and send the case even when PrufGate gets it wrong; say so in the pull request. If your case changes the measured numbers, update this page and the floors in `tests/test_bench.py` in the same pull request.

## Why the corpus does not trip PrufGate's own gate

The corpus is full of the very cheats PrufGate blocks, and this repository runs PrufGate on its own pull requests. Each case is a single `.txt` file: text, not source. The engines that read source select files by language (`.py`, `.ts`, `.go` and so on), and the diff guard skips `.md`, `.rst` and `.txt` hunks, so the cases never reach a rule. No exclusion is needed, which matters for two reasons:

- an `exclude` entry in `.prufgate/config.yaml` takes effect only after it is merged (a changed-files run applies the base's configuration), and the diff guard reports any new exclusion as `prufgate-config-self-exemption`, by design;
- the hard-coded `INTERNAL_SCANNER_PATHS` lists that cover PrufGate's own fixture-bearing tests are per engine and apply only inside this repository; adding a directory to five of them would be a wider hole than a file format.

Inside `prufgate bench` the files are written out under their real names in a temporary repository, so the engines see them exactly as they would in a project.
