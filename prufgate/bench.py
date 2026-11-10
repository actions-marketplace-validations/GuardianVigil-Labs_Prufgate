"""`prufgate bench`: precision and recall of `check --changed` on a labelled corpus.

A case is one text file in a txtar-like format (docs/BENCHMARK.md):

    -- label.yaml --
    category: fabrication
    description: one line
    must_fire: [canned-error-fallback]
    must_not_fire: []
    -- base/src/app.py --
    ...
    -- head/src/app.py --
    ...

Each case becomes a throwaway git repository with a base commit and a head
commit, and the engines of `check --changed --base <base>` run on it in
process. Nothing in a case is executed, and the network is blocked for the
run. Accounting is per case and rule: a `must_fire` rule that fired is a true
positive, one that did not is a false negative, and every other rule that fired
is a false positive (`must_not_fire` names the near miss a case targets; any
unexpected finding counts against precision, listed or not).
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Iterator

import yaml

from prufgate.config import expand_rule_aliases
from prufgate.process import git_command

CATEGORIES = (
    "fabrication",
    "hollow-test",
    "weakened-test",
    "fake-exit",
    "deleted-test",
    "skipped-test",
    "harness-edit",
    "config-weakening",
    "suppression",
    "contract",
    "bola",
    "clean",
)
_SECTION = re.compile(r"^-- (\S+) --$")
_GIT = git_command("-c", "commit.gpgsign=false", "-c", "diff.ignoreSubmodules=all", "-c", "user.name=bench", "-c", "user.email=bench@example.com", "-c", "init.defaultBranch=main")


class CaseError(ValueError):
    """A case file that cannot be read as a labelled case."""


def canon(rule: str) -> str:
    """One name per rule, whatever alias a label or an engine uses."""
    return min(expand_rule_aliases(rule))


def parse_case(path: Path) -> dict[str, Any]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _SECTION.match(line)
        if m:
            if m.group(1) in sections:
                raise CaseError(f"{path.name}: section {m.group(1)} appears twice")
            current = sections[m.group(1)] = []
        elif current is not None:
            current.append(line)
    if "label.yaml" not in sections:
        raise CaseError(f"{path.name}: no label.yaml section")
    label = yaml.safe_load("\n".join(sections.pop("label.yaml"))) or {}
    if not isinstance(label, dict):
        raise CaseError(f"{path.name}: label.yaml is not a mapping")
    must = [str(r) for r in label.get("must_fire") or []]
    must_not = [str(r) for r in label.get("must_not_fire") or []]
    if label.get("category") not in CATEGORIES:
        raise CaseError(f"{path.name}: category must be one of {', '.join(CATEGORIES)}")
    if not str(label.get("description") or "").strip():
        raise CaseError(f"{path.name}: description is empty")
    if {canon(r) for r in must} & {canon(r) for r in must_not}:
        raise CaseError(f"{path.name}: a rule is in both must_fire and must_not_fire")
    trees: dict[str, dict[str, str]] = {"base": {}, "head": {}}
    for name, lines in sections.items():
        side, _, rel = name.partition("/")
        if side not in trees or not rel or rel.startswith("/") or ".." in rel.split("/") or ".git" in rel.lower().split("/"):
            raise CaseError(f"{path.name}: bad section name {name!r} (want base/<path> or head/<path>)")
        trees[side][rel] = "\n".join(lines) + "\n"
    if trees["base"] == trees["head"]:
        raise CaseError(f"{path.name}: base and head are identical")
    return {"id": path.stem, "category": label["category"], "description": str(label["description"]).strip(),
            "must_fire": must, "must_not_fire": must_not, **trees}


def load_cases(cases_dir: Path) -> list[dict[str, Any]]:
    files = sorted(cases_dir.glob("*.txt"))
    if not files:
        raise CaseError(f"no *.txt cases in {cases_dir}")
    return [parse_case(f) for f in files]


@contextmanager
def _no_network() -> Iterator[None]:
    """The corpus is scanned offline: any connection attempt fails."""
    def refuse(*_a: Any, **_k: Any) -> Any:
        raise OSError("prufgate bench: network access is disabled")

    saved = socket.socket.connect, socket.create_connection, os.environ.pop("PRUFGATE_REGISTRY_CHECK", None)
    socket.socket.connect, socket.create_connection = refuse, refuse  # type: ignore[method-assign,assignment]
    try:
        yield
    finally:
        socket.socket.connect, socket.create_connection = saved[0], saved[1]  # type: ignore[method-assign]
        if saved[2] is not None:
            os.environ["PRUFGATE_REGISTRY_CHECK"] = saved[2]


# Safe settings for every git call during the scan, the engines' own included: a
# case must never get a nested repository's config, hooks or transports to run.
_SAFE_GIT_CONFIG = (("core.fsmonitor", "false"), ("core.hooksPath", "/dev/null"),
                    ("diff.ignoreSubmodules", "all"), ("protocol.allow", "never"))


@contextmanager
def _safe_git_env() -> Iterator[None]:
    env = {"GIT_CONFIG_COUNT": str(len(_SAFE_GIT_CONFIG))}
    for i, (k, v) in enumerate(_SAFE_GIT_CONFIG):
        env[f"GIT_CONFIG_KEY_{i}"], env[f"GIT_CONFIG_VALUE_{i}"] = k, v
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for p in root.iterdir():
        if p.name != ".git":
            shutil.rmtree(p) if p.is_dir() else p.unlink()
    for rel, text in files.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding="utf-8")


def _commit(root: Path, msg: str) -> str:
    subprocess.run([*_GIT, "add", "-A"], cwd=root, check=True, capture_output=True)
    subprocess.run([*_GIT, "commit", "-q", "--allow-empty", "-m", msg], cwd=root, check=True, capture_output=True)
    return subprocess.run([*_GIT, "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True).stdout.strip()


def fired_rules(case: dict[str, Any], profile: str = "core") -> set[str]:
    """Rules that `check --changed --base <base>` reports on the case."""
    from prufgate.cli import _collect_unified_findings
    if profile not in ("core", "review"):
        raise CaseError("unsupported evaluation profile")

    with tempfile.TemporaryDirectory(prefix="prufgate-bench-") as tmp:
        root = Path(tmp)
        subprocess.run([*_GIT, "init", "-q"], cwd=root, check=True, capture_output=True)
        _write_tree(root, case["base"])
        base = _commit(root, "base")
        _write_tree(root, case["head"])
        _commit(root, "head")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            if profile == "review":
                from prufgate.review.reviewer import get_git_diff, run_hybrid_review
                from prufgate.rules import review_rule_id
                comments = run_hybrid_review(get_git_diff(base, root, strict=True), enable_ai=False)
                findings = [{"rule": review_rule_id(c.title)} for c in comments]
            else:
                findings = _collect_unified_findings(root, changed_only=True, base_ref=base)
    return {str(f["rule"]) for f in findings}


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 3) if b else None


def score(results: list[dict[str, Any]], only_rule: str | None = None) -> dict[str, Any]:
    """Per-rule and overall TP/FP/FN, precision and recall, and the misses."""
    # Aliases of one rule are one rule, shown under the name the labels use.
    names = {canon(r): r for res in reversed(results) for r in res["must_fire"]}
    keep = (lambda r: r == canon(only_rule)) if only_rule else (lambda r: True)
    per: dict[str, dict[str, int]] = {}
    misses: list[dict[str, Any]] = []
    for res in results:
        must = {canon(r) for r in res["must_fire"]}
        fired: set[str] = set()
        for r in res["fired"]:
            names.setdefault(canon(r), r)
            fired.add(canon(r))
        must, fired = {r for r in must if keep(r)}, {r for r in fired if keep(r)}
        for kind, rules in (("tp", must & fired), ("fn", must - fired), ("fp", fired - must)):
            for r in sorted(names[c] for c in rules):
                per.setdefault(r, {"tp": 0, "fp": 0, "fn": 0})[kind] += 1
                if kind != "tp":
                    misses.append({"case": res["id"], "category": res["category"], "rule": r,
                                   "kind": "false-negative" if kind == "fn" else "false-positive"})
    for counts in per.values():
        counts["precision"] = _ratio(counts["tp"], counts["tp"] + counts["fp"])  # type: ignore[assignment]
        counts["recall"] = _ratio(counts["tp"], counts["tp"] + counts["fn"])  # type: ignore[assignment]
    tp, fp, fn = (sum(c[k] for c in per.values()) for k in ("tp", "fp", "fn"))
    categories: dict[str, int] = {}
    for res in results:
        categories[res["category"]] = categories.get(res["category"], 0) + 1
    return {
        "cases": len(results),
        "categories": dict(sorted(categories.items())),
        "overall": {"tp": tp, "fp": fp, "fn": fn, "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, tp + fn)},
        "rules": dict(sorted(per.items())),
        "misses": misses,
    }


def run(cases: list[dict[str, Any]], only_rule: str | None = None) -> dict[str, Any]:
    with _no_network(), _safe_git_env():
        results = [{**c, "fired": sorted(fired_rules(c))} for c in cases]
    return score(results, only_rule)


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.3f}"


def render(report: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2)
    o = report["overall"]
    head = (f"{report['cases']} cases; precision {_pct(o['precision'])}, recall {_pct(o['recall'])} "
            f"(TP {o['tp']}, FP {o['fp']}, FN {o['fn']})")
    if fmt == "markdown":
        lines = [head, "", "| Rule | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|"]
        lines += [f"| `{r}` | {c['tp']} | {c['fp']} | {c['fn']} | {_pct(c['precision'])} | {_pct(c['recall'])} |"
                  for r, c in report["rules"].items()]
        lines += ["", "| Case | Category | Rule | Miss |", "|---|---|---|---|"]
        lines += [f"| `{m['case']}` | {m['category']} | `{m['rule']}` | {m['kind']} |" for m in report["misses"]]
        return "\n".join(lines)
    lines = [head, ""]
    lines += [f"  {r:<42} TP {c['tp']:>3}  FP {c['fp']:>3}  FN {c['fn']:>3}  "
              f"P {_pct(c['precision'])}  R {_pct(c['recall'])}" for r, c in report["rules"].items()]
    if report["misses"]:
        lines += ["", "Misses:"] + [f"  {m['kind']:<15} {m['rule']:<42} {m['case']}" for m in report["misses"]]
    return "\n".join(lines)


def main(cases_dir: str | None, fmt: str, rule: str | None, min_precision: float | None, min_recall: float | None) -> int:
    """Exit 0 (a report), 1 below a requested floor, 2 a bad corpus or an engine error."""
    import sys

    path = Path(cases_dir or "bench/cases")
    if not path.is_dir():
        print(f"prufgate bench: no corpus at {path} (the corpus is not installed with the package: "
              "pass --cases DIR from a PrufGate checkout)", file=sys.stderr)
        return 2
    try:
        report = run(load_cases(path), rule)
    except (CaseError, yaml.YAMLError, OSError, subprocess.CalledProcessError) as exc:
        print(f"prufgate bench: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # an engine crash must never read as a score
        print(f"prufgate bench: engine error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2
    print(render(report, fmt))
    o, below = report["overall"], []
    if min_precision is not None and (o["precision"] or 0.0) < min_precision:
        below.append(f"precision {_pct(o['precision'])} < {min_precision}")
    if min_recall is not None and (o["recall"] or 0.0) < min_recall:
        below.append(f"recall {_pct(o['recall'])} < {min_recall}")
    for b in below:
        print(f"prufgate bench: {b}", file=sys.stderr)
    return 1 if below else 0
