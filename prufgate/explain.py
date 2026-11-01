"""`prufgate explain RULE`: what a rule catches, how to fix it, and how to record a
false positive. `prufgate explain --list` lists every rule.

The text here is the short form of docs/ENGINES.md, kept in the package so it works
offline and from a pip install. Every rule in `prufgate.rules.CONFIDENCE` has an
entry (tests/test_explain.py checks both ways, and that ENGINES.md names each one).
"""
from __future__ import annotations

import difflib
import json
import sys
import textwrap
from dataclasses import dataclass
from typing import Dict, List, Optional

from prufgate import PROJECT_URL
from prufgate.config import expand_rule_aliases
from prufgate.rules import CONFIDENCE, LOW

DOCS = f"{PROJECT_URL}/blob/main/docs/ENGINES.md"


@dataclass(frozen=True)
class Engine:
    name: str
    anchor: str


E1 = Engine("engine 1: anti-fabrication", "engine-1-anti-fabrication")
E1_CTI = Engine("engine 1: anti-fabrication, opt-in pack cti", "engine-1-anti-fabrication")
E2 = Engine("engine 2: test integrity", "engine-2-test-integrity")
E3 = Engine("engine 3: diff guard", "engine-3-diff-guard")
E4 = Engine("engine 4: contract guard", "engine-4-contract-guard")
E4_REG = Engine("engine 4: registry check (opt-in)", "registry-check-for-new-dependencies-opt-in")
E5 = Engine("engine 5: BOLA / IDOR", "engine-5-bola--idor")
E6 = Engine("engine 6: diff reviewer", "engine-6-diff-reviewer")
DIFF = Engine("prufgate verify --differential", "differential-test-verification-opt-in-runs-repository-code")
MUT = Engine("prufgate verify --mutation", "mutation-smoke-test-opt-in-runs-repository-code")
TRANS = Engine("prufgate transcript", "agent-transcripts")
GATE = Engine("the gate", "the-gates-extra-tools")


@dataclass(frozen=True)
class Rule:
    engine: Engine
    what: str
    fix: str
    example: str = ""


RULES: Dict[str, Rule] = {
    # Engine 1
    "canned-error-fallback": Rule(
        E1,
        "An error path (`catch`, `except`, `rescue`, `if err != nil`) that returns a hard-coded success value, "
        "so a failure reaches the caller looking like a result.",
        "Let the error propagate, or return a value that says it failed (`{ ok: false, error }`, `None`, a typed "
        "error) and handle that where it is used.",
        "} catch (e) {\n  return { ok: true };\n}",
    ),
    "route-canned-fallback": Rule(
        E1,
        "An API route that answers a failed upstream call with canned data, so clients cannot tell an outage from "
        "a real answer.",
        "Return an error status (502/503) or a response that marks the data unavailable.",
        "catch (err) {\n  return res.json(SAMPLE_PRICES);\n}",
    ),
    "unhandled-empty-catch": Rule(
        E1,
        "An error swallowed with nothing done about it: an empty `catch`, or `except:` / `except Exception:` whose "
        "body is only `pass`.",
        "Handle the error, log it with context, or re-raise it. A catch that returns the function's 'no value' "
        "answer, or carries a comment giving the reason, is not reported.",
        "try:\n    sync_orders()\nexcept Exception:\n    pass",
    ),
    "verdict-on-error-path": Rule(
        E1,
        "A decision (allowed, safe, verified, approved) produced on an error path, so a failure yields a verdict.",
        "On failure, return 'unknown' or an error; never a verdict nobody computed.",
        "except TimeoutError:\n    return {\"verdict\": \"clean\"}",
    ),
    "score-on-error-path": Rule(
        E1,
        "A score or rating produced on an error path, so a failure yields a number that looks measured.",
        "Return no score (`None`, an error) when the inputs could not be computed.",
        "} catch {\n  return { riskScore: 0 };\n}",
    ),
    "score-outside-scoring": Rule(
        E1,
        "A score computed outside the files listed in `score_owners`, where nobody reviews how it is derived.",
        "Move the computation into a scoring module listed in `score_owners`, or add the file there.",
    ),
    "simulated-return-value": Rule(
        E1,
        "A literal returned under a comment admitting it is simulated, a placeholder or for now.",
        "Implement the call, or raise until it is implemented, so the gap is visible.",
        "// simulate the API response for now\nreturn { status: \"delivered\" };",
    ),
    "fake-named-data": Rule(
        E1,
        "`MOCK_*`, `FAKE_*`, `DUMMY_*`, `SAMPLE_*`, `fallbackData` and similar served from production code. "
        "Low confidence: off unless `enable_low_confidence: true`.",
        "Load real data, or move the sample into tests or fixtures.",
        "export const MOCK_USERS = [{ id: 1, name: \"Ada\" }];",
    ),
    "synthetic-delay-mock": Rule(
        E1,
        "A sleep or timer paired with a hard-coded result, faking asynchronous work.",
        "Call the real service, or move the fake into a test double.",
        "await sleep(800);\nreturn { approved: true };",
    ),
    "stub-click-handler": Rule(
        E1,
        "A UI handler that does nothing (an empty arrow, a `console.log`, a TODO), so the button looks wired up "
        "and is not. Pack `web-ui`.",
        "Wire the handler to the action it names, or remove or disable the control.",
        "<button onClick={() => {}}>Save</button>",
    ),
    "disconnected-form-submit": Rule(
        E1,
        "A submit handler that only calls `preventDefault()`, logs or alerts: the form submits nowhere. Pack `web-ui`.",
        "Send the form data to the backend, or disable the form until it is implemented.",
        "onSubmit={(e) => { e.preventDefault(); console.log(\"sent\"); }}",
    ),
    "always-current-fake-timestamp": Rule(
        E1,
        "'Now minus a fixed offset' computed at read time, so static data always looks fresh.",
        "Store and return the real time the event happened.",
        "lastSeen: new Date(Date.now() - 5 * 60 * 1000)",
    ),
    "asserted-state": Rule(
        E1,
        "A status literal asserted rather than derived from anything. Low confidence: off unless "
        "`enable_low_confidence: true`.",
        "Compute the state from the data it describes.",
        "return { health: \"healthy\" };",
    ),
    "unimplemented-production-stub": Rule(
        E1,
        "`NotImplementedError`, `todo!()`, `panic(\"not implemented\")` or `throw new Error(\"TODO\")` in "
        "reachable production code.",
        "Implement it, or remove the code path that reaches it.",
        "def refund(order):\n    raise NotImplementedError",
    ),
    "prompt-invents-finding": Rule(
        E1,
        "An LLM asked for a structured decision (score, verdict, severity) with no runtime evidence in the prompt, "
        "so the model can only invent it. Pack `ai-safety`.",
        "Pass the evidence the decision should rest on (the scan output, the document, the record) in the prompt.",
        "prompt = \"Rate this vendor's security from 1 to 10.\"",
    ),
    "documentation-ip-or-domain": Rule(
        E1,
        "A documentation address (RFC 5737 / RFC 3849 ranges, `example.com`) served from production code: a "
        "placeholder that was never replaced.",
        "Use the real endpoint from configuration. Placeholders in UI `placeholder` text and examples are not reported.",
        "const API = \"https://api.example.com/v1\";",
    ),
    "stale-exemption": Rule(
        E1,
        "An exemption in `.prufgate/config.yaml` that matches no finding any more.",
        "Delete the exemption: the code it excused is gone or fixed.",
    ),
    "debt-ceiling-breached": Rule(
        E1,
        "More findings of a rule than its `known_debt` ceiling allows: the debt grew. A baseline never hides it.",
        "Fix the new findings, or lower them below the ceiling. Ceilings only go down.",
    ),
    # Engine 1, pack cti
    "hardcoded-cve": Rule(E1_CTI, "A CVE identifier written into product logic instead of read from data.",
                          "Read vulnerabilities from the feed or database the product serves."),
    "hardcoded-attribution": Rule(E1_CTI, "A threat actor or campaign name hard-coded as a result.",
                                  "Derive attribution from evidence, with its source."),
    "keyword-selected-attribution": Rule(
        E1_CTI, "Attribution chosen by matching a keyword. Low confidence: off unless `enable_low_confidence: true`.",
        "Attribute from evidence, not from a word in the input."),
    "ui-verdict-literal": Rule(E1_CTI, "A verdict (malicious, clean) written as a literal in the UI.",
                               "Show the verdict the backend computed."),
    "substring-decides-verdict": Rule(E1_CTI, "A verdict decided by whether a string contains a word.",
                                      "Decide from the analysis result, not from text matching."),
    "zero-jarm-as-fingerprint": Rule(E1_CTI, "An all-zero JARM hash (no TLS answer) treated as a fingerprint.",
                                     "Treat the all-zero JARM as 'no data'."),
    "empty-input-digest-as-sample": Rule(E1_CTI, "The hash of empty input reported as a sample.",
                                         "Reject empty input before hashing it."),
    "llm-generated-intel": Rule(E1_CTI, "Threat intelligence produced by an LLM and served as fact.",
                                "Label it as generated, or back it with sourced data."),
    # Engine 2
    "zero-assertion-test": Rule(
        E2,
        "A test that runs code and asserts nothing, so it passes whatever the code does.",
        "Assert on the result or the effect the test is about.",
        "def test_checkout():\n    checkout(cart)",
    ),
    "tautological-assertion": Rule(
        E2,
        "An assertion that cannot fail: `assert True`, `expect(true).toBe(true)`, `assertEqual(x, x)`, or an "
        "existence check as the only assertion.",
        "Assert the expected value of the thing under test.",
        "expect(true).toBe(true);",
    ),
    "self-mocked-unit-under-test": Rule(
        E2,
        "A test that mocks the module it is testing, or asserts a mock's own return value: it tests the mock.",
        "Mock the unit's dependencies, never the unit, and assert on what the real code returns.",
        "jest.mock(\"./pricing\");\nimport { total } from \"./pricing\";",
    ),
    "caught-and-ignored-test-exception": Rule(
        E2,
        "A test that catches the failure it should report.",
        "Let the exception fail the test, or assert it with `pytest.raises` / `expect(...).toThrow()`.",
        "try:\n    charge(card)\nexcept Exception:\n    pass",
    ),
    "snapshot-blind-update-or-empty": Rule(
        E2,
        "An empty or unfilled inline snapshot (`toMatchInlineSnapshot()`), or snapshots updated without review.",
        "Write the expected snapshot, and review snapshot updates like code.",
        "expect(render(<Cart />)).toMatchInlineSnapshot();",
    ),
    "diff-assertion-weakening": Rule(
        E2,
        "A change that deletes assertions or widens what they accept, for example `== 200` becoming "
        "`in (200, 500)`.",
        "Keep the assertion and fix the code; if the behaviour really changed, assert the new behaviour exactly.",
        "-    assert resp.status_code == 200\n+    assert resp.status_code in (200, 500)",
    ),
    "test-input-special-casing": Rule(
        E2,
        "Production code gains a branch for the exact literal a test passes in: the code is shaped to the test.",
        "Implement the general behaviour the test describes.",
        "if (email === \"test@example.com\") return true;",
    ),
    "diff-test-file-deleted": Rule(
        E2,
        "A test file deleted with its tests not added back anywhere. Renames, moved tests and tests retired with "
        "their feature are not reported. P1.",
        "Restore the tests, or delete the feature they test in the same change.",
    ),
    "diff-test-count-drop": Rule(
        E2,
        "A change that removes more test cases than it adds, counted across all files. P1.",
        "Restore the removed cases, or explain in review why they are no longer needed.",
    ),
    # Engine 3
    "test-skip-smuggling": Rule(
        E3,
        "A skip or focus added without an issue reference: `.skip`, `.only`, `xit`, `pytest.mark.skip`, "
        "`t.Skip()`, `#[ignore]`, `@Disabled` and similar.",
        "Fix the failing test. If it must be skipped, reference the issue that tracks it (`#123`, `PROJ-456`) "
        "or guard the skip on a missing capability.",
        "@pytest.mark.skip\ndef test_refund():",
    ),
    "test-fake-exit": Rule(
        E3,
        "An exit with status 0 added to a test file or test setup, so the run reports success without running "
        "the tests. P0.",
        "Remove the exit.",
        "# conftest.py\nimport sys\nsys.exit(0)",
    ),
    "test-runner-monkeypatch": Rule(
        E3,
        "The test runner or its assertions replaced (`unittest.TestCase.assertEqual = ...`, `expect = ...`), so "
        "assertions check nothing. P0.",
        "Remove the patch and fix the code under test.",
        "unittest.TestCase.assertEqual = lambda *a, **k: None",
    ),
    "always-true-equality": Rule(
        E3,
        "`__eq__` returning True (or `__ne__` returning False) for any input, so every equality assertion "
        "passes. P1.",
        "Compare the fields that define equality.",
        "def __eq__(self, other):\n    return True",
    ),
    "pytest-result-rewrite": Rule(
        E3,
        "A pytest plugin that rewrites results: an outcome set to passed, the exit status forced to 0, failures "
        "dropped from the stats. P0.",
        "Remove the hook code that changes outcomes.",
        "report.outcome = \"passed\"",
    ),
    "pytest-collection-deselect": Rule(
        E3,
        "A pytest plugin that removes collected tests or marks them all skipped. P1.",
        "Remove the deselection, or select tests with markers on the command line where review can see it.",
        "def pytest_collection_modifyitems(items):\n    items.clear()",
    ),
    "test-config-weakening": Rule(
        E3,
        "A configuration change that narrows the test run: `-k`, `--deselect`, `--ignore`, fewer test paths, "
        "and the Jest/Vitest equivalents. P1.",
        "Revert the narrowing and fix the tests it hid.",
        "addopts = -k \"not payments\"",
    ),
    "test-script-neutered": Rule(
        E3,
        "A test script whose exit status cannot reflect a failure: `|| true`, `; exit 0`, `echo` only, a pipe "
        "without `pipefail`. Also Makefile, tox and nox recipes. P0.",
        "Let the test command's exit status through.",
        "\"test\": \"jest || true\"",
    ),
    "suppression-comment-smuggling": Rule(
        E3,
        "A suppression added without a justification: `@ts-ignore`, `eslint-disable`, `# noqa`, "
        "`# type: ignore`, `// nolint`, `#[allow(...)]`, `@SuppressWarnings`, `prufgate-ignore`.",
        "Fix the warning. If it is wrong, name the rule and give a reason (`-- why`) or an issue reference.",
        "// @ts-ignore\nconst total = order.amount * rate;",
    ),
    "unsafe-type-cast-cascade": Rule(
        E3,
        "Type checks switched off with a cast: `as unknown as T`, `as any`, `cast(Any, ...)`, unjustified "
        "`unsafe` blocks. A single `as unknown as T` is a P2 warning.",
        "Fix the types, or validate the value at runtime before narrowing it.",
        "const user = data as unknown as User;",
    ),
    "linter-or-ci-config-weakening": Rule(
        E3,
        "Linter, type-checker or CI configuration loosened compared with the base: new ignores or excludes, "
        "strict checks turned off, `continue-on-error: true`, `|| true` in a CI step.",
        "Revert the loosening and fix what it hid.",
        "\"strict\": false",
    ),
    "coverage-threshold-lowering": Rule(
        E3,
        "A coverage threshold lowered (`fail_under`, Jest/Vitest `coverageThreshold`).",
        "Keep the threshold and add the missing tests.",
        "-fail_under = 90\n+fail_under = 60",
    ),
    "prufgate-config-self-exemption": Rule(
        E3,
        "The PrufGate configuration or baseline loosened in this change: new exclusions, exemptions, debt, "
        "baseline entries, dropped packs. P1: a change that silences PrufGate needs a maintainer's review. "
        "A baseline never hides it.",
        "Get a maintainer's review. The change takes effect after merge.",
    ),
    "prufgate-config-not-applied": Rule(
        E3,
        "Informational (P2): this change edits the PrufGate configuration or baseline, and the run used the "
        "base branch's. Changes take effect after merge.",
        "Nothing to fix; it explains why the branch's configuration did not apply.",
    ),
    "prufgate-config-base-invalid": Rule(
        E3,
        "Informational (P2): this version rejects the configuration at the base, so the run used the branch's.",
        "Nothing to fix in the change, if the branch's configuration is valid.",
    ),
    # Engine 4
    "undeclared-or-hallucinated-import": Rule(
        E4,
        "An import of a package no manifest declares (`package.json`, `pyproject.toml`, `requirements*.txt`, "
        "`go.mod`, `Cargo.toml`). A hallucinated or typo-squatted name is how a malicious package gets installed.",
        "Add the package to the manifest if it is real and intended; otherwise use the package you meant.",
        "import { slugify } from \"slugify-pro\";",
    ),
    "ghost-symbol": Rule(
        E4,
        "A name its module does not define: an imported function, a call on an imported module, or a named "
        "export that does not exist. A hallucinated API. P1.",
        "Use a name the module defines, or add it to the module.",
        "from shop.billing import charge_card  # billing.py has no charge_card",
    ),
    "undocumented-env-var-drift": Rule(
        E4,
        "An environment variable read without a default and missing from `.env.example` (or the other documented "
        "sources), so a new deployment fails at runtime.",
        "Document the variable in `.env.example`, or give the read a default.",
        "const key = process.env.STRIPE_KEY;",
    ),
    "frontend-backend-route-mismatch": Rule(
        E4,
        "A frontend call to an API path no backend route or OpenAPI spec defines.",
        "Call the route that exists, or add the route.",
        "fetch(\"/api/v2/orders\")",
    ),
    "dependency-not-on-registry": Rule(
        E4_REG,
        "A new dependency the registry does not have. An attacker can register the name and wait for the "
        "install. P0.",
        "Use the package you meant.",
    ),
    "dependency-recently-published": Rule(
        E4_REG,
        "A new dependency whose first release is younger than `max_age_days` (default 30). P1.",
        "Check who publishes it before you depend on it.",
    ),
    "dependency-typosquat": Rule(
        E4_REG,
        "A new dependency whose name is one edit (or `-`, `_`, `.`) away from a popular package. P1.",
        "Use the popular package's exact name, if that is what you meant.",
        "\"reqeusts\": \"^2.0\"",
    ),
    # Engine 5
    "static-bola-unscoped-access": Rule(
        E5,
        "A route handler that loads a record by a client-supplied ID with no auth guard, or with no tenant or "
        "owner condition: any user can read anyone's record (BOLA / IDOR).",
        "Check the caller is signed in, and scope the lookup by owner or tenant (`where: { id, orgId: user.orgId }`). "
        "List your guards in `auth_guards` and tenant columns in `tenant_keys`.",
        "app.get(\"/api/notes/:id\", async (req, res) => {\n  res.json(await db.note.findUnique({ where: { id: req.params.id } }));\n});",
    ),
    "BOLA-UNGUARDED-SERVER-ACTION": Rule(
        E5,
        "A Next.js server action with no recognised auth guard: it is a public endpoint.",
        "Check the session at the top of the action, or name your guard in `auth_guards`.",
        "\"use server\";\nexport async function deleteNote(id) { await db.note.delete({ where: { id } }); }",
    ),
    "BOLA-TABLE-MISSING-TENANT-COLUMN": Rule(
        E5,
        "A `CREATE TABLE` in a migration with no tenant or owner column. Low confidence: off unless "
        "`enable_low_confidence: true`.",
        "Add the tenant column, or list a table every tenant shares in `bola.global_tables`.",
    ),
    "BOLA-UNAUTHENTICATED-ACCESS": Rule(
        E5,
        "Live probing: the endpoint returned data without a token.",
        "Require authentication on the route.",
    ),
    "BOLA-CROSS-TENANT-ACCESS": Rule(
        E5,
        "Live probing: tenant B's token read tenant A's record.",
        "Scope the lookup by the caller's tenant or owner.",
    ),
    "BOLA-PROBE-REDIRECT-REFUSED": Rule(
        E5,
        "Live probing: the service redirected to another origin, which the probe does not follow.",
        "Probe the final origin directly.",
    ),
    "bfla-role-allowed": Rule(
        E5,
        "Role matrix: a role the matrix denies got a 2xx answer. P0.",
        "Enforce the role check on the route.",
    ),
    "bfla-allow-denied": Rule(
        E5,
        "Role matrix: a role the matrix allows got 401/403, so the matrix may be out of date. P3, advisory.",
        "Update the matrix, or the route's permissions.",
    ),
    # Engine 6
    "pr-sql-injection-vector": Rule(
        E6,
        "A SQL query built from a template literal with `${...}` inside it.",
        "Use bind parameters (`$1`, `?`) and pass the values separately.",
        "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)",
    ),
    "pr-hardcoded-credential-in-code": Rule(
        E6,
        "A credential written into the code.",
        "Read it from the environment or a secret store, and rotate the one that was committed.",
        "const apiKey = \"sk_live_...\";",
    ),
    "pr-shell-command-injection-risk": Rule(
        E6,
        "A shell command built from input (`exec`, `os.system`, `subprocess(..., shell=True)` with interpolation).",
        "Pass arguments as a list without a shell.",
        "os.system(f\"convert {filename} out.png\")",
    ),
    "pr-disabled-tls-certificate-verification": Rule(
        E6,
        "TLS certificate verification turned off (`verify=False`, `rejectUnauthorized: false`, "
        "`InsecureSkipVerify: true`).",
        "Keep verification on; trust a private CA by configuring it.",
        "requests.get(url, verify=False)",
    ),
    "pr-unsanitized-html-injection-xss": Rule(
        E6,
        "Unsanitised HTML rendered (`dangerouslySetInnerHTML`, `innerHTML`, `v-html`).",
        "Render text, or sanitise the HTML with a vetted sanitiser first.",
        "el.innerHTML = comment.body;",
    ),
    "pr-ignored-error-return-in-go": Rule(
        E6,
        "A Go error return discarded. Low confidence: off unless `enable_low_confidence: true`.",
        "Check the error.",
        "_ = os.Remove(path)",
    ),
    "pr-unbounded-goroutine-spawn": Rule(
        E6,
        "A goroutine started per item in a loop with no limit. Low confidence.",
        "Bound the concurrency with a worker pool or a semaphore.",
    ),
    "pr-credential-logging-in-console": Rule(
        E6,
        "A credential written to a log. Low confidence.",
        "Log an identifier, never the secret.",
        "console.log(\"token\", token);",
    ),
    "pr-server-action-missing-authorization-guard": Rule(
        E6,
        "A server action added without an authorization check.",
        "Check the session and the caller's permission at the top of the action.",
    ),
    # Opt-in commands
    "differential-base-tests-fail": Rule(
        DIFF,
        "The base branch's tests fail on the head code: the change broke behaviour the old tests pinned down.",
        "Fix the code, or change the tests in review if the behaviour change is intended.",
    ),
    "mutation-survivor": Rule(
        MUT,
        "A mutant of a changed line survived: no test notices when that line is changed.",
        "Add a test that fails for the mutation shown.",
    ),
    "mutation-no-coverage": Rule(
        MUT,
        "A changed line no test runs.",
        "Add a test that runs it.",
    ),
    "transcript-history-lookup": Rule(
        TRANS,
        "An agent looked at other branches, tags or history (`git log --all`, `git reflog`, `git show "
        "origin/x:path`), for example to copy a fix instead of making it.",
        "Review whether the work was derived from history it should not have read.",
    ),
    "transcript-hook-bypass": Rule(
        TRANS,
        "An agent skipped git hooks: `--no-verify`, `git commit -n`, `core.hooksPath`, `HUSKY=0`.",
        "Rerun the hooks and fix what they report.",
    ),
    "transcript-test-tamper-command": Rule(
        TRANS,
        "An agent removed or moved tests or CI configuration, or edited CI configuration from the shell.",
        "Review and restore the tests or configuration.",
    ),
    # Gate plumbing
    "ignore-without-reason": Rule(
        GATE,
        "A `prufgate-ignore` comment with no reason. It suppresses nothing; the finding it names is still "
        "reported. P2.",
        "Add the reason: `prufgate-ignore: rule -- why`.",
        "// prufgate-ignore: canned-error-fallback",
    ),
    "action-authorization-guard": Rule(
        GATE,
        "The built-in ast-grep rule: a server action without an authorization guard.",
        "Check the caller's permission at the top of the action.",
    ),
}

_PREFIX = "anti-fabrication-"


def lookup(name: str) -> Optional[str]:
    """The documented rule `name` refers to: itself, without the gate's prefix, or an alias."""
    rule = name.strip()
    candidates = [rule, rule.lower()]
    if rule.lower().startswith(_PREFIX):
        candidates += [rule[len(_PREFIX):], rule[len(_PREFIX):].lower()]
    if rule.lower().startswith("bola-"):
        candidates.append(rule.upper())
    for cand in candidates:
        if cand in RULES:
            return cand
    for cand in candidates:
        for alias in sorted(expand_rule_aliases(cand)):
            if alias in RULES:
                return alias
    return None


def suggestions(name: str) -> List[str]:
    return difflib.get_close_matches(name.strip().lower(), [r.lower() for r in RULES], n=3, cutoff=0.6)


def describe(rule: str) -> Dict[str, object]:
    r = RULES[rule]
    aliases = sorted(a for a in expand_rule_aliases(rule) if a != rule and a not in RULES)
    return {
        "rule": rule,
        "engine": r.engine.name,
        "confidence": CONFIDENCE.get(rule, "medium"),
        "aliases": aliases,
        "what": r.what,
        "fix": r.fix,
        "example": r.example,
        "docs": f"{DOCS}#{r.engine.anchor}",
    }


def _wrap(text: str) -> str:
    return textwrap.fill(text, width=88, initial_indent="  ", subsequent_indent="  ")


def render_text(rule: str) -> str:
    d = describe(rule)
    aliases = sorted(a for a in expand_rule_aliases(rule) if a != rule and a not in RULES)
    head = f"{rule}  ({d['engine']} · confidence: {d['confidence']}"
    if aliases:
        head += " · also reported as " + ", ".join(aliases)
    out = [head + ")", "", "What it catches", _wrap(str(d["what"])), "", "How to fix it", _wrap(str(d["fix"]))]
    if d["example"]:
        out += ["", "Example", textwrap.indent(str(d["example"]), "    ")]
    out += ["", "If the finding is wrong"]
    if d["confidence"] == LOW:
        out.append(_wrap("This rule is off by default; `enable_low_confidence: true` in .prufgate/config.yaml turns it on."))
    out += [
        _wrap(f"Say why on the line: `prufgate-ignore: {rule} -- <reason>` in a comment. For a whole file, "
              "add an exemption with a reason in .prufgate/config.yaml. To accept every finding a codebase already "
              "has, run `prufgate baseline`."),
        "",
        f"More: {d['docs']}",
    ]
    return "\n".join(out) + "\n"


def render_list() -> str:
    by_engine: Dict[str, List[str]] = {}
    for rule, r in RULES.items():
        by_engine.setdefault(r.engine.name, []).append(rule)
    width = max(len(r) for r in RULES)
    out = []
    for engine, rules in by_engine.items():
        out.append(engine.capitalize() if engine[0].islower() else engine)
        for rule in rules:
            first = RULES[rule].what.split(". ")[0].rstrip(".")
            if len(first) > 70:
                first = first[:69] + "…"
            out.append(f"  {rule:<{width}}  {CONFIDENCE.get(rule, 'medium'):<6}  {first}")
        out.append("")
    out.append("`prufgate explain RULE` shows what a rule catches and how to fix it.")
    return "\n".join(out) + "\n"


def main(rule: Optional[str], list_all: bool, fmt: str) -> int:
    if list_all or not rule:
        if fmt == "json":
            print(json.dumps([describe(r) for r in RULES], indent=2))
        else:
            sys.stdout.write(render_list())
        return 0
    found = lookup(rule)
    if found is None:
        hint = suggestions(rule)
        msg = f"prufgate explain: no PrufGate rule named {rule!r}."
        if hint:
            msg += " Did you mean " + " or ".join(f"`{h}`" for h in hint) + "?"
        msg += " Rules from gitleaks, zizmor or your own ast-grep rules are explained by those tools."
        msg += " `prufgate explain --list` lists every rule."
        print(msg, file=sys.stderr)
        return 2
    if fmt == "json":
        print(json.dumps(describe(found), indent=2))
    else:
        sys.stdout.write(render_text(found))
    return 0
