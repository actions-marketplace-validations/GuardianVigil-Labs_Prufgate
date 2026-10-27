#!/usr/bin/env python3
"""Detect fabricated data, mock fallbacks, and simulated logic in enterprise applications.

Flags code paths that return plausible-looking production findings when the real
source is unavailable, disconnected UI mock handlers, and simulated business logic.

  python3 detector.py [paths...]             # default: src/ and backend/, else .
  python3 detector.py --changed              # files changed vs HEAD (local)
  python3 detector.py --changed=origin/main  # files changed vs a base ref (CI)
  python3 detector.py --json-out=report.json # also write findings as JSON
  python3 detector.py --config=path.yaml     # project settings (.prufgate/config.yaml or .prufgate/fabrication.json)
  python3 detector.py --pack=cti             # enable optional domain pack (e.g., cti)
  python3 detector.py --self-check           # prove every rule still fires

Project settings are optional. See docs/CUSTOM_RULES.md for the file format:
exemptions with reasons, tracked debt, the module that owns scoring, extra
model-call and evidence patterns, optional rule packs, and extra allowed paths.

Domain-specific rules (the optional CTI vocabulary) live in packs/cti.py and
run only with `--pack=cti` or `packs: [cti]`.

Exit codes: 0 clean, 1 findings, 2 bad usage, an unreadable file or a git error.
"""

from __future__ import annotations

import fnmatch
import functools
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

from prufgate import inline_ignore  # noqa: E402
from prufgate.anti_fabrication import literals  # noqa: E402
from prufgate.anti_fabrication.packs import cti  # noqa: E402
from prufgate.config import (  # noqa: E402
    DEFAULT_PACKS,
    ConfigError,
    PrufGateConfig,
    expand_rule_aliases,
    rules_match,
)
from prufgate.rules import visible  # noqa: E402

# Multi-language file extension mapping
LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "typescript",
    ".svelte": "typescript",
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
}
SUFFIXES = set(LANGUAGE_BY_SUFFIX.keys())
WEB_UI_SUFFIXES = {".ts", ".tsx", ".js", ".jsx", ".mjs", ".vue", ".svelte"}


def classify_file(path: str | Path) -> str | None:
    """Return normalized language identifier for a source file, or None if unsupported."""
    return LANGUAGE_BY_SUFFIX.get(Path(path).suffix.lower())


# Confidence/score fields set to a suspiciously specific constant.
SCORE_LITERAL = re.compile(r"""\b(?:score|confidence|similarity|rating|riskScore)\s*[:=]\s*(\d{2,3})\b""")

# Identifiers whose very name says the data is not real.
FAKE_NAME = re.compile(
    r"\b(?:mock|MOCK|Mock|FALLBACK_|fallbackData|dummy|DUMMY|FAKE_|fakeData|sampleResult|placeholderResult|demoPayload)\w*"
)

# A function that admits in its own comments that it is not real, sitting above
# a literal return.
SIMULATION_TELL = re.compile(
    r"simulat(?:e|es|ed|ion)|in\s+production,?\s+this|for\s+now,?\s+return|"
    r"placeholder|stub(?:bed)?\s+(?:out|value|response)|would\s+(?:normally\s+)?(?:compute|fetch|query|call)|"
    r"mock\s+implementation",
    re.IGNORECASE,
)

# Ends the comment window.
BLOCK_BOUNDARY = re.compile(
    r"^\s*$"                                            # blank line
    r"|^\s*[})\]];?\s*$"                                # a closing brace alone
    r"|^\s*(?:export\s+|default\s+|public\s+|private\s+|protected\s+|static\s+|async\s+|pub\s+)*"
    r"(?:def |func |fn |function |class |const |let |var )"  # a definition
)

# A bare literal handed back as a result: `return 0.925`, `return 87`, `= 0.92`, `return {"status": "ok"}`.
LITERAL_RETURN = re.compile(
    r"\breturn\s+(?:0?\.\d+|\d{1,3}(?:\.\d+)?|True|False|true|false|\{\s*[\"']\w+[\"']\s*:|\[\s*\{)\s*(?:$|[#;/])"
    # a one-line dict or object with a literal number or boolean in it: `return {"id": x, "balance": 1200}`
    r"|\breturn\s+\{[^}]*?:\s*(?:-?\d|True\b|False\b|true\b|false\b)[^}]*\}"
    r"|\bOk\(\s*(?:0?\.\d+|\d{1,3}(?:\.\d+)?)\s*\)"
)

# Fabricated operational state timestamp assigned the current time.
FRESH_EVENT_TIMESTAMP = re.compile(
    r"""\b(last|previous)\w*
        (?:Fired|Sync\w*|Seen|Run|Delivered|Contact\w*|Success\w*|Checked|Triggered|Used)
        \s*:\s*
        (?:new\s+Date\(\)|Date\.now\(\)|time\.Now\(\)|datetime\.(?:now|utcnow)\([^)]*\))""",
    re.VERBOSE | re.IGNORECASE,
)

# A state asserted as a literal.
ASSERTED_STATE_LITERAL = re.compile(
    r"""\b(?:status|state|health|connection|severity|risk)\s*:\s*
        ["'](?:Active|Connected|Online|Healthy|Enabled|Operational|Live
            |Degraded|Optimal|Attention\s+Needed)["']""",
    re.VERBOSE | re.IGNORECASE,
)

# Paths where invented data is legitimate: tests, fixtures and tooling.
# Directory names match whole path segments only (`out` never matches `checkout`).
SKIP_DIR_SEGMENTS = frozenset({
    "test_samples", "__tests__", "tests", "test", "spec", "node_modules", ".next", "dist",
    "build", "target", "vendor", "out", ".git", ".venv", "venv", "scripts",
})
# PrufGate's own report folder: skipped only at the top of the scanned tree
# (`src/app/reports/` is product code).
ROOT_ONLY_SKIP_SEGMENTS = frozenset({"reports"})
TEST_FILE_SUFFIXES = (
    "_test.go", "_test.py", "_spec.rb", "Test.java", "Tests.java", "Test.kt", "Test.cs", "Test.php",
    ".test.ts", ".test.tsx", ".test.js", ".test.jsx", ".test.mjs", ".spec.ts", ".spec.tsx",
    ".spec.js", ".spec.jsx",
)
# Extra project paths from `allowed_paths` (globs, files or directories).
ALLOWED: tuple[str, ...] = ()
ENABLED_LANGUAGES: set[str] = set()

# This installation of PrufGate: its own rule tables are full of deliberate
# fixtures, so it is skipped only when the scan reaches these very files.
PRUFGATE_ENGINE_DIR = _THIS_DIR.parent

DATA_JSON_DIRS = ("/data/",)

# Seed data is literal by nature: the line-level rules skip it.
SEED_DIR_SEGMENTS = frozenset({"seed", "seeds"})

# Enabled optional domain packs (e.g. {"cti"}). Empty by default.
ACTIVE_PACKS: set[str] = set()
ENABLED_RULE_PACKS: set[str] = set(DEFAULT_PACKS)

# RFC 5737 / RFC 3849 documentation addresses and RFC 2606 example domains in URLs.
DOC_ADDRESS = re.compile(
    r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b(?![./\d])"
    r"|\b2001:db8:[0-9a-f:]*[0-9a-f](?![0-9a-f:]*/)"
    r"|https?://(?:[\w-]+\.)?example\.(?:com|org|net)\b",
    re.IGNORECASE,
)

# The always-current fake: a record whose timestamp is computed from the clock at render time.
ALWAYS_CURRENT = re.compile(
    r"\b\w+\s*:\s*(?:new\s+Date\(\s*)?(?:Date\.now\(\)|new\s+Date\(\)\.getTime\(\))\s*[-+]\s*[\d(]"
    r"|['\"]?(?:created_at|updated_at|last_seen|last_login|createdAt|updatedAt|lastSeen|lastLogin)['\"]?\s*[:=]\s*"
    r"(?:datetime\.(?:now|utcnow)\([^)]*\)\s*-\s*timedelta\(|time\.Now\(\)\.Add\(\s*-|Instant\.now\(\)\.minus)"
)

# A declaration whose name says it is not real.
DEMO_NAMED = re.compile(
    r"\b(?:const|let|var|val|final)\s+(?:(?:SAMPLE|MOCK|DEMO|DUMMY|FAKE)_[A-Z0-9_]+|simulated[A-Z]\w*|demoPayload)\b"
    r"|\b(?:(?:SAMPLE|MOCK|DEMO|DUMMY|FAKE)_[A-Z0-9_]+|simulated[A-Z]\w*|demoPayload)\s*(?::[^=]+)?(?::=|=[^=])"
)

# A score or reputation written anywhere but the module that owns it. Opt-in.
SCORE_ASSIGNMENT = re.compile(r"\.(?:score|reputation|Score|Reputation)\s*(?:=|\+=|-=)(?!=)")
SCORE_OWNERS: tuple[str, ...] = ()

# A route that answers a failure with a success and a canned body.
FAILURE_BRANCH = re.compile(r"\}\s*catch\b|\bcatch\s*[({]|if\s*\(\s*!\s*[\w.]+\.ok\s*\)")
RESPONSE_CALL = re.compile(r"(?:NextResponse|Response)\.json\(|new\s+(?:Next)?Response\(")
ERROR_STATUS = re.compile(r"status:\s*(?:[1345]\d\d\b|[\w.]*[Ss]tatus\b)")

# Real fabrications that are known, tracked and not yet removed.
KNOWN_DEBT: dict[tuple[str, str], str] = {}
KNOWN_DEBT_CEILINGS: dict[str, int] = {}
DEBT_REF = re.compile(r"^#\d+: ")

# Files where a rule's hit is not a fabrication, with the reason.
V2_EXEMPT: dict[tuple[str, str], str] = {}


class Finding:
    def __init__(self, path: str, line: int, rule: str, text: str, end_line: int = 0):
        self.path, self.line, self.rule, self.text = path, line, rule, text.strip()[:110]
        self.end_line = end_line

    def to_dict(self) -> dict:
        d = {
            "file": self.path,
            "line": self.line,
            "rule": self.rule,
            "snippet": self.text,
        }
        if self.end_line > self.line:
            d["end_line"] = self.end_line
        return d

    def __str__(self) -> str:
        return f"{self.path}:{self.line}\n    [{self.rule}] {self.text}"


def _norm_path(p: str) -> str:
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _path_matches_pattern(rel: str, pattern: str) -> bool:
    """A file, a directory (whole segments), or a glob. Never a bare substring."""
    rel, pat = _norm_path(rel), _norm_path(pattern)
    if not pat:
        return False
    if any(ch in pat for ch in "*?["):
        if fnmatch.fnmatch(rel, pat):
            return True
        if pat.startswith("**/") and fnmatch.fnmatch(rel, pat[3:]):
            return True
        return pat.endswith("/**") and (rel + "/").startswith(pat[:-2])
    pat = pat.rstrip("/")
    return rel == pat or rel.startswith(pat + "/") or ("/" + rel).endswith("/" + pat) or f"/{pat}/" in f"/{rel}"


def _is_skipped_by_default(parts: tuple[str, ...]) -> bool:
    """Tests, fixtures, build output and tooling, judged on whole path segments."""
    if not parts:
        return False
    name = parts[-1]
    return (
        any(p in SKIP_DIR_SEGMENTS for p in parts[:-1])
        or (len(parts) > 1 and parts[0] in ROOT_ONLY_SKIP_SEGMENTS)
        or name.endswith(TEST_FILE_SUFFIXES)
        or (name.startswith("test_") and name.endswith(".py"))
    )


def _is_prufgate_own_file(path: Path) -> bool:
    try:
        path.resolve().relative_to(PRUFGATE_ENGINE_DIR)
        return True
    except (ValueError, OSError):
        return False


def data_findings(rel: str, lines: list[str]) -> list[Finding]:
    if "cti" not in ACTIVE_PACKS:
        return []
    return cti.scan_cti_data_json(rel, lines, Finding)


def in_error_path(lines: list[str], index: int, window: int = 4) -> bool:
    """True when the line sits inside a catch / missing-credential branch."""
    start = max(0, index - window)
    context = "\n".join(lines[start : index + 1])
    return bool(
        re.search(
            r"\bcatch\b|\bexcept\b|\brescue\b|if\s*\(\s*!\s*process\.env|"
            r"if\s+err\s*!=\s*nil|\|\|\s*$|fallback|unavailable|not\s+configured",
            context,
            re.IGNORECASE,
        )
    )


def is_simulated_value(lines: list[str], index: int, window: int = 6) -> bool:
    """True when a literal return sits under a comment admitting it is fake."""
    start = max(0, index - window)
    for j in range(index - 1, start - 1, -1):
        if BLOCK_BOUNDARY.match(lines[j]):
            start = j + 1
            break
    context = "\n".join(lines[start : index + 1])
    return bool(SIMULATION_TELL.search(context))


def is_outbound_config(lines: list[str], index: int, window: int = 8) -> bool:
    """Is this line inside a request body we are sending, rather than a claim?"""
    start = max(0, index - window)
    above = "\n".join(lines[start:index])
    return (
        re.search(
            r"\b(set|put|create|update|apply|configure|post|send)[A-Za-z]*\s*\(",
            above,
        )
        is not None
    )


MODEL_CALL_DEFAULT = (
    r"generateContent|genAI\.models|models\.generate"
    r"|chat\.completions\.create|messages\.create|responses\.create"
    r"|generateObject|streamObject|with_structured_output|litellm\.completion|acompletion"
    r"|@anthropic-ai/sdk|@google/genai|from\s+[\"'](?:openai|ai)[\"']"
    r"|^\s*(?:import|from)\s+(?:openai|anthropic|google\.genai|litellm|langchain\w*)\b"
)
MODEL_CALL = re.compile(MODEL_CALL_DEFAULT, re.IGNORECASE | re.MULTILINE)

JUDGEMENT_FIELDS_DEFAULT = r"risk_?score|risk_?level|score|verdict|approved|severity|confidence|disposition"


def _judgement_field(fields: str) -> re.Pattern:
    """A judgement asked for as a typed JSON field (`"risk_score": number`) or, in prose inside a
    string, as an instruction (`"Give a risk_score from 0 to 100"`)."""
    return re.compile(
        rf"""["'](?P<field>{fields})["']\s*:\s*(?:number|string|boolean|int|float|["'])"""
        rf"""|["'`][^"'`\n]*?\b(?:give|return|assign|provide|output|produce)\s+(?:(?:me|us)\s+)?(?:an?|the)\s+(?:{fields})\b""",
        re.IGNORECASE,
    )


JUDGEMENT_FIELD = _judgement_field(JUDGEMENT_FIELDS_DEFAULT)

EVIDENCE_DEFAULT = r"evidence|observed|observations|scan_?results|measurements|corroboration"
EVIDENCE_SUPPLIED = re.compile(EVIDENCE_DEFAULT, re.IGNORECASE)


def prompt_findings(rel: str, text: str, lines: list[str]) -> list[Finding]:
    """A prompt asking for a judgement with no evidence supplied."""
    if "ai-safety" not in ENABLED_RULE_PACKS:
        return []
    if not MODEL_CALL.search(text):
        return []
    if EVIDENCE_SUPPLIED.search(text):
        return []

    out: list[Finding] = []
    for i, line in enumerate(lines):
        match = JUDGEMENT_FIELD.search(line)
        if match:
            out.append(Finding(rel, i + 1, "prompt-invents-finding", line))
    return out


def _closing_line(lines: list[str], i: int, col: int, op: str, cl: str) -> int | None:
    """The line holding the bracket that closes the one opened at (i, col)."""
    depth = 0
    for j in range(i, min(len(lines), i + 80)):
        for ch in (lines[j][col:] if j == i else lines[j]):
            if ch == op:
                depth += 1
            elif ch == cl and depth:
                depth -= 1
                if depth == 0:
                    return j
    return None


def _response_args(lines: list[str], k: int) -> str:
    m = RESPONSE_CALL.search(lines[k])
    p = lines[k].index("(", m.start()) if m else 0
    end = _closing_line(lines, k, p, "(", ")")
    return "\n".join(lines[k : (end if end is not None else k) + 1])[p + 1 :]


def _is_canned(args: str, lines: list[str], k: int) -> bool:
    """The body is a literal, or a name bound to one just above."""
    a = args.lstrip()
    if a[:1] in "`'\"":
        return True
    if a[:1] in "[{" and re.search(r"\[\s*\{", a):
        return True
    m = re.match(r"([A-Za-z_]\w*)\s*[,)]", a)
    if m:
        bound = re.compile(r"\b(?:const|let)\s+" + m.group(1) + r"\s*(?::[^=]+)?=\s*[`'\"\[]")
        return any(bound.search(x) for x in lines[max(0, k - 40) : k])
    return False


def canned_fallbacks(lines: list[str]) -> list[int]:
    """Line numbers where a failure is answered with a success and a canned body."""

    def offends(k: int) -> bool:
        args = _response_args(lines, k)
        if ERROR_STATUS.search(args):
            return False
        return bool(re.search(r"status:\s*200\b", args)) or _is_canned(args, lines, k)

    hits: set[int] = set()
    for i, line in enumerate(lines):
        if line.strip().startswith(("//", "*")):
            continue
        m = FAILURE_BRANCH.search(line)
        if not m:
            continue
        brace = line.find("{", m.start())
        end = _closing_line(lines, i, brace, "{", "}") if brace >= 0 else None
        if end is None:
            continue
        for k in range(i, end + 1):
            if RESPONSE_CALL.search(lines[k]) and offends(k):
                hits.add(k + 1)
        code = "\n".join(x.split("//")[0] for x in lines[i + 1 : end + 1])
        if not re.search(r"\breturn\b|\bthrow\b", code):
            for k in range(end + 1, min(len(lines), end + 30)):
                if RESPONSE_CALL.search(lines[k]):
                    if offends(k):
                        hits.add(k + 1)
                    break
    return sorted(hits)


UNIMPLEMENTED_STUB_RE = re.compile(
    r"\braise\s+NotImplementedError\b"
    r"|\b(?:todo|unimplemented)!\s*\("
    r"|\bpanic\s*\(\s*[\"'](?:not\s+implemented|TODO\b)[^\"']*[\"']\s*\)"
    r"|\bthrow\s+new\s+(?:Error|NotImplementedException|UnsupportedOperationException)\s*\(\s*[\"'](?:not\s+implemented|TODO\b)[^\"']*[\"']\s*\)",
    re.IGNORECASE,
)

ABSTRACT_CONTEXT_RE = re.compile(
    r"@abstractmethod|\bABC\b|\bProtocol\b|\binterface\b|\babstract\s+(?:def|func|fn|class|method)\b",
    re.IGNORECASE,
)


# A documentation address shown to a person as an example, not used as an address.
EXAMPLE_TEXT_RE = re.compile(r"placeholder|\bfor\s+example\b|\be\.g\.|\bsuch\s+as\b", re.IGNORECASE)


def _code_before_comment(line: str) -> str:
    spans = literals.string_spans(line)
    for idx in range(len(line)):
        if literals.in_string(spans, idx):
            continue
        if line[idx] == "#" or line[idx : idx + 2] == "//":
            return line[:idx]
    return line


def _documented_example(lines: list[str], i: int) -> bool:
    """The address on lines[i] is an input placeholder (the attribute may open a few
    lines above, as in a multi-line ternary) or follows "for example" / "e.g."."""
    cur = _code_before_comment(lines[i])
    if EXAMPLE_TEXT_RE.search(cur):
        return True
    prev = "\n".join(_code_before_comment(ln) for ln in lines[max(0, i - 3) : i])
    return bool(re.search(r"\bplaceholder\s*[:=]", prev, re.IGNORECASE))


def v2_findings(rel: str, suffix: str, lines: list[str]) -> list[Finding]:
    """The core rules. Comments are skipped; exemptions are applied by the caller."""
    out: list[Finding] = []
    if "core" not in ENABLED_RULE_PACKS:
        if "cti" in ACTIVE_PACKS:
            out.extend(cti.scan_cti_v2_lines(rel, lines, Finding))
        return out
    route = suffix == ".ts" and rel.endswith("route.ts") and "/app/" in "/" + rel
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue
        if DOC_ADDRESS.search(line) and not _documented_example(lines, i):
            out.append(Finding(rel, i + 1, "documentation-address", line))
        if ALWAYS_CURRENT.search(line):
            out.append(Finding(rel, i + 1, "always-current-fake", line))
        if DEMO_NAMED.search(line):
            out.append(Finding(rel, i + 1, "demo-named-data", line))
        if SCORE_OWNERS and SCORE_ASSIGNMENT.search(line) and not rel.endswith(SCORE_OWNERS):
            out.append(Finding(rel, i + 1, "score-outside-scoring", line))
        if UNIMPLEMENTED_STUB_RE.search(line):
            prev_window = "\n".join(lines[max(0, i - 6) : i + 1])
            if not ABSTRACT_CONTEXT_RE.search(prev_window):
                out.append(Finding(rel, i + 1, "unimplemented-production-stub", line))
    if "cti" in ACTIVE_PACKS:
        out.extend(cti.scan_cti_v2_lines(rel, lines, Finding))
    if route:
        for n in canned_fallbacks(lines):
            out.append(Finding(rel, n, "route-canned-fallback", lines[n - 1]))
    return out


@functools.lru_cache(maxsize=1024)
def _repo_root(directory: Path) -> Path | None:
    for d in (directory, *directory.parents):
        if (d / ".git").exists() or (d / ".prufgate").is_dir():
            return d
    return None


def workspace_relative(path: Path, root: Path | None = None) -> str:
    """The path as the rules expect it: relative to `root`, else to the enclosing
    repository, else to the current directory, else as given."""
    p = Path(path)
    if p.is_absolute():
        resolved = p.resolve()
        for base in (root, _repo_root(resolved.parent), Path.cwd()):
            if base is None:
                continue
            try:
                return _norm_path(str(resolved.relative_to(Path(base).resolve())))
            except ValueError:
                continue
    return _norm_path(str(p))


def scan_file(path: Path, root: Path | None = None) -> list[Finding]:
    """Scan one file. The reported path, and every path-based rule and exemption,
    use the workspace-relative path even when `path` is absolute."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise ScanError(f"cannot read {path}: {e.strerror or e}") from e
    return scan_text(workspace_relative(path, root), path.suffix, text)


def _is_exempt_or_debt(rel: str, rule: str, table: dict[tuple[str, str], str]) -> bool:
    if (rel, rule) in table:
        return True
    for (ex_path, ex_rule) in table:
        if _path_matches_pattern(rel, ex_path) and rules_match(rule, ex_rule):
            return True
    return False


def scan_text(rel: str, suffix: str, text: str) -> list[Finding]:
    """Every finding, less the project's exemptions, tracked debt, and inline prufgate-ignore."""
    lines = text.split("\n")
    return [
        f
        for f in raw_findings(rel, suffix, text)
        if not _is_exempt_or_debt(rel, f.rule, V2_EXEMPT)
        and not _is_exempt_or_debt(rel, f.rule, KNOWN_DEBT)
        and not inline_ignore.suppressed_at(
            lines, f.line, f.rule, engine="anti-fabrication", path=rel, severity="P0",
            message=f"Fabrication pattern '{f.rule}': {f.text}",
        )
    ]


# --- Generic Fake Functionality & Multi-Language Rules ---
STUB_CLICK_HANDLER = re.compile(
    r"""(?:\b(?:onClick|onPress|onSelect)\s*=\s*\{(?:\s*\(\s*(?:e|event)?\s*\)\s*=>\s*(?:\{\s*\}|(?:console\.log|alert)\s*\([^)]*\))|\s*\(\s*\)\s*=>\s*(?:undefined|void\s+0|null|noop)\s*)\})"""
    r"""|(?:(?:@click|on:click)\s*=\s*["'\{]\s*(?:\(\s*\)\s*=>\s*\{\s*\}|noop)\s*["'\}])"""
)
SYNTHETIC_DELAY = re.compile(
    r"""(?:setTimeout\s*\([^,]+,\s*\d+\)|await\s+(?:sleep\s*\(\d+\)|new\s+Promise\s*\(\s*(?:\w+\s*=>\s*)?setTimeout\)))"""
    r"""|(?:(?:await\s+)?(?:asyncio|time)\.sleep\s*\(\s*\d+(?:\.\d+)?\s*\))"""
    r"""|(?:time\.Sleep\s*\(\s*\d+[^)]*\))"""
    r"""|(?:(?:thread::sleep|tokio::time::sleep)\s*\(\s*Duration::from_(?:millis|secs)\s*\(\s*\d+\s*\)\s*\))"""
    r"""|(?:Thread\.sleep\s*\(\s*\d+\s*\))"""
)
SYNTHETIC_MOCK_RETURN = re.compile(
    r"""return\s+(?:\{[^}]*(?:['"]?(?:success|ok)['"]?\s*:\s*(?:true|True)|['"]?data['"]?\s*:|['"]?status['"]?\s*:\s*['"](?:success|ok|complete|completed|done)['"]|['"]?items['"]?\s*:)|(?:MOCK_|DEMO_|DUMMY_|FAKE_|fake)\w+)"""
    r"""|(?:c\.JSON\s*\(\s*(?:200|http\.StatusOK)\s*,\s*gin\.H\s*\{)"""
    r"""|(?:Ok\s*\(\s*Json\s*\(\s*json!\s*\(\s*\{)"""
)

MULTI_LANG_ERROR_SWALLOW_RE = re.compile(
    r"^\s*(?:except(?:\s*\([^)]*\)|\s+[\w.]+)?(?:\s+as\s+\w+)?\s*:|if\s+err\s*!=\s*nil\s*\{|Err\s*\(\s*[_a-zA-Z]\w*\s*\)\s*=>"
    r"|rescue\b(?:\s+[\w:]+)?)"
)
# catch blocks in Java, Kotlin, C# and PHP (JS/TS have their own empty-catch rule).
BRACE_CATCH_RE = re.compile(r"(?:^|\})\s*catch\s*\(")
BRACE_CATCH_SUFFIXES = {".java", ".kt", ".kts", ".cs", ".php"}
_OK = r"""(?:ok|success)"""
MULTI_LANG_CANNED_OK_RE = re.compile(
    r"""return\s+\{\s*['"](?:ok|success|status)['"]\s*:\s*(?:True|true|['"](?:ok|success)['"])"""
    r"""|c\.JSON\s*\(\s*(?:200|http\.StatusOK)\s*,\s*(?:gin\.H|map\[)"""
    # A decision field answered yes: `return {"approved": True, ...}` (Python, JS)
    r"""|return\s+\{[^}]*['"](?:approved|authori[sz]ed|verified|valid|allowed|passed)['"]\s*:\s*true\b"""
    # Go: `if err != nil { return true, nil }`, success and no error on the failure path
    r"""|(?-i:\breturn\s+true\s*,\s*nil\b)"""
    r"""|Ok\s*\(\s*Json\s*\(\s*json!\s*\(\s*\{\s*["'](?:ok|success)["']\s*:\s*true"""
    # Java / Kotlin: a 200 or an "ok" map handed back from a catch
    r"""|\bResponseEntity\s*\.\s*ok\s*\(|\bResponseEntity\s*\.\s*status\s*\(\s*HttpStatus\.OK\b"""
    rf"""|\b(?:Map\.of|mapOf)\s*\(\s*["']{_OK}["']\s*(?:,|to)\s*true"""
    # PHP
    rf"""|(?:return|json\s*\()\s*\[\s*['"]{_OK}['"]\s*=>\s*true"""
    # C#
    r"""|(?-i:\breturn\s+Ok\s*\((?!\s*\(\s*\)))"""
    rf"""|\bnew\s*\{{\s*{_OK}\s*=\s*true"""
    # Ruby
    rf"""|\brender\s+json:\s*\{{\s*["']?{_OK}["']?\s*(?::|=>)\s*true""",
    re.IGNORECASE,
)


def _canned_ok(window: str) -> bool:
    """A canned success in a handler. A Go `c.JSON(200, gin.H{...})` that carries the
    error in its body (`"error": err.Error()`) reports the failure, it does not hide it."""
    for m in MULTI_LANG_CANNED_OK_RE.finditer(window):
        rest = window[m.start() :]
        if m.group(0).lstrip().startswith("c.JSON"):
            err_m = re.search(r"""["']error["']\s*:\s*([^,\n}]+)""", rest)
            if (
                err_m
                and not re.match(r"""^(?:nil|false|""|'')\b""", err_m.group(1).strip())
                and not SUCCESS_CLAIM_RE.search(rest)
            ):
                continue
        return True
    return False


# `except:`, `except Exception:`, `except BaseException as e:` or a tuple naming either
# (`except (ValueError, Exception):`): a handler that catches everything.
PY_BROAD_EXCEPT_RE = re.compile(
    r"^\s*except(?:\s*\((?:\s*[\w.]+\s*,)*\s*(?:Exception|BaseException)\s*(?:,\s*[\w.]+\s*)*,?\s*\)"
    r"|\s+(?:Exception|BaseException))?(?:\s+as\s+\w+)?\s*:"
)
# Functions where swallowing an error is the point: releasing a resource on the way out.
_PY_CLEANUP_DEF_RE = re.compile(
    r"^\s*(?:async\s+)?def\s+(?:__(?:a?exit|del)__|_*(?:\w+_)?(?:close|cleanup|clean_up|shutdown|teardown|tear_down|dispose)(?:_\w+)?)\s*\(",
    re.IGNORECASE,
)


def _in_cleanup_def(lines: list[str], i: int) -> bool:
    """The Python line lines[i] sits in a `close` / `cleanup` / `shutdown` / `teardown` /
    `dispose` / `__exit__` / `__del__` function (the nearest enclosing `def`)."""
    indent = len(lines[i]) - len(lines[i].lstrip())
    for k in range(i - 1, -1, -1):
        t = lines[k]
        if t.strip() and not t.lstrip().startswith(("#", "@")) and len(t) - len(t.lstrip()) < indent:
            if re.match(r"^\s*(?:async\s+)?def\s", t):
                return bool(_PY_CLEANUP_DEF_RE.match(t))
            indent = len(t) - len(t.lstrip())
    return False


def _only_pass(lines: list[str], i: int, end: int) -> bool:
    """The Python handler at lines[i] (ending before `end`) does nothing: `pass` or `...` only."""
    body = [lines[i].split(":", 1)[1]] + lines[i + 1 : end]
    code = [b.split("#", 1)[0].strip() for b in body]
    code = [c for c in code if c]
    return bool(code) and all(c in ("pass", "...") for c in code)


TRAILING_COMMENT_RE = re.compile(r"\s*(?://(?![^\"'`]*[\"'`]\s*[,;)}\]]).*|/\*.*?\*/)\s*$")


CATCH_OPEN_RE = re.compile(r"\bcatch\s*(?:\([^)]*\))?\s*\{")
# A success claimed outright: `ok: true`, `status: "ok"`.
SUCCESS_CLAIM_RE = re.compile(
    r"""['"]?\b(?:ok|success|succeeded|valid|verified|approved|authori[sz]ed|allowed|passed|saved|sent|delivered|completed?|charged|refunded|synced|processed|paid)\b['"]?\s*:\s*true\b"""
    r"""|['"]?\bstatus['"]?\s*:\s*['"](?:ok|success|succeeded|healthy|complete|completed|done|active|synced|paid|charged|refunded|processed)['"]""",
    re.IGNORECASE,
)
# A failure said as a failure: `success: false`, an `error` / `reason` field with a non-empty value, `state: "unavailable"`.
FAILURE_MARK_RE = re.compile(
    r"""['"]?\b(?:error|errors|err|reason|detail|details|failure|message|problem)\b['"]?\s*(?:,(?!\s*$)|$|:\s*(?!(?:null|undefined|false|0|""|''|\[\s*\]|\{\s*\})\b)\S)"""
    r"""|['"]?\b(?!(?:failed|failure|errors?|err|is_?error|has_?error|invalid|expired|rejected|denied|refused|blocked|disabled|offline|stale|cancell?ed)\b)[A-Za-z_$][\w$]*['"]?\s*:\s*false\b"""
    r"""|:\s*['"](?:unavailable|failed|failure|error|unknown|denied|refused|rejected)['"]""",
    re.IGNORECASE,
)
LITERAL_VALUE_RE = re.compile(
    r"""(?:true|false|null|undefined|-?\d[\d_.]*|"[^"]*"|'[^']*'|`[^`$]*`|\[\s*\]|\{\s*\})"""
)
# A comment that is a placeholder, not a reason.
NON_REASON_RE = re.compile(
    r"\b(?:todo|fixme|xxx|hack|for\s+now|later|temporar\w*|swallow\w*|ignore\w*|suppress\w*|noop|no-op|do\s+nothing|silent\w*)\b",
    re.IGNORECASE,
)
# A function whose job is to let go of something: a failure there has nowhere to go.
JS_CLEANUP_NAME_RE = re.compile(
    r"(?<![.\w])(?:close|cleanup|cleanUp|dispose|teardown|tearDown|shutdown|destroy|release|abort|stop|unmount|finali[sz]e)\w*\s*[:=(]"
)
JS_CLEANUP_CALL_RE = re.compile(
    r"\.(?:close|end|destroy|dispose|kill|release|disconnect|abort|terminate|unlink|unref|cancel|stop|quit)\s*\("
)
JS_LOOP_RE = re.compile(r"\b(?:for|while)\s*\(|\bdo\s*\{")
JS_WAIT_RE = re.compile(r"\b(?:sleep|wait\w*|setTimeout|delay|backoff|retry|retries|attempts?)\b", re.IGNORECASE)


def _props(inner: str) -> list[str]:
    """Top-level comma-separated parts of an object literal's body."""
    parts, depth, cur, quote = [], 0, "", ""
    for c in inner:
        if quote:
            quote = "" if c == quote else quote
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
            continue
        cur += c
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _is_literal_expr(val: str, depth: int = 0) -> bool:
    val = val.strip()
    if not val or depth > 3:
        return False
    if LITERAL_VALUE_RE.fullmatch(val):
        return True
    if val.startswith("[") and val.endswith("]"):
        items = _props(val[1:-1])
        return all(_is_literal_expr(x, depth + 1) for x in items)
    if val.startswith("{") and val.endswith("}"):
        props = _props(val[1:-1])
        return bool(props) and all(
            ":" in p and _is_literal_expr(p.split(":", 1)[1], depth + 1) for p in props
        )
    return False


def canned_object(inner: str) -> bool:
    """The body of an object literal answered on a failure path is a canned success:
    it claims success, or holds nothing but literals and no word of the failure."""
    if SUCCESS_CLAIM_RE.search(inner):
        return True
    if FAILURE_MARK_RE.search(inner):
        return False
    props = _props(inner)
    return bool(props) and all(
        ":" in p and _is_literal_expr(p.split(":", 1)[1]) for p in props
    )


def _classify_catch_body(body: str) -> str | None:
    comments = []
    code_lines = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("//", "/*", "*")):
            comments.append(line)
            continue
        m = TRAILING_COMMENT_RE.search(line)
        if m and m.group(0).strip():
            comments.append(m.group(0))
            line = line[: m.start()].strip()
        elif line.startswith("/*") or "/*" in line:
            comments.append(line)
            line = re.sub(r"/\*.*?\*/", "", line).strip()
        if line:
            code_lines.append(line)
    if not code_lines:
        # A comment that gives a reason documents a deliberate choice; "// ignore" does not.
        text = re.sub(r"[/*]+", " ", " ".join(comments))
        if len(re.findall(r"[A-Za-z]{2,}", text)) >= 3 and not NON_REASON_RE.search(text):
            return None
        return "empty"
    code = " ".join(code_lines)
    # `return null` / `false` / `{}` is the function's documented "no value" answer.
    if re.match(r"^return\s*true;?$", code):
        return "empty"
    m_ret = re.match(r"^return\s*(\{.*\})\s*;?$", code)
    if m_ret:
        obj = m_ret.group(1)
        if len(obj) > 2 and _match_brace(_masked(obj), 0, 1) == len(obj) - 1 and canned_object(obj[1:-1]):
            return "canned"
    return None


def _match_brace(s: str, i: int, step: int) -> int | None:
    """Index of the brace matching s[i], scanning forward (step 1) or back (step -1)."""
    depth = 0
    opener, closer = ("{", "}") if step == 1 else ("}", "{")
    while 0 <= i < len(s):
        if s[i] == opener:
            depth += 1
        elif s[i] == closer:
            depth -= 1
            if depth == 0:
                return i
        i += step
    return None


def _masked(line: str) -> str:
    """`line` with the inside of each string literal and comment blanked, same length."""
    spans = literals.string_spans(line)
    out = list(line)
    for a, b in spans:
        for k in range(a + 1, b - 1):
            out[k] = " "
    i, n = 0, len(out)
    while i < n - 1:
        if any(a <= i < b for a, b in spans):
            i += 1
            continue
        if out[i] == "/" and out[i + 1] == "/":
            for k in range(i + 2, n):
                out[k] = " "
            break
        if out[i] == "/" and out[i + 1] == "*":
            end = line.find("*/", i + 2)
            stop = end + 2 if end != -1 else n
            for k in range(i, stop):
                out[k] = " "
            i = stop
            continue
        i += 1
    return "".join(out)


def _strip_js_comments(text: str) -> str:
    text = re.sub(r"/\*[\s\S]*?\*/", " ", text)
    return re.sub(r"//[^\n]*", "", text)


def _swallow_is_deliberate(masked: str, try_open: int, try_close: int, catch_close: int) -> bool:
    """An empty catch that is not hiding a failure: a best-effort release, a retry
    loop that tries again, a `return` in the try with the failure path below it, or
    a read into a variable that already holds its default."""
    line_start = masked.rfind("\n", 0, masked.rfind("\n", 0, try_open)) + 1
    prefix = _strip_js_comments(masked[line_start:try_open])
    try_body = _strip_js_comments(masked[try_open + 1 : try_close]).strip()
    after = _strip_js_comments(masked[catch_close + 1 :]).lstrip()
    stmts = [s.strip() for s in re.split(r"[;\n]+", try_body) if s.strip()]
    if JS_CLEANUP_NAME_RE.search(prefix) or (JS_CLEANUP_CALL_RE.search(try_body) and len(stmts) <= 1):
        return True
    before = "\n".join(_strip_js_comments(masked[:try_open]).split("\n")[-4:])
    if JS_LOOP_RE.search(before) and JS_WAIT_RE.search(before + _strip_js_comments(masked[catch_close : catch_close + 200])):
        return True
    last = stmts[-1] if stmts else ""
    if re.match(r"^(?:return\b|break$|continue$)", last) and after and not after.startswith("}"):
        return True
    assign = re.fullmatch(r"([A-Za-z_$][\w$]*)\s*=[^=][^;]*;?", try_body)
    if assign and len(stmts) == 1 and re.search(
        rf"\b(?:let|var)\s+{re.escape(assign.group(1))}\b[^;\n]*=", _strip_js_comments(masked[:try_open])
    ):
        return True
    return False


def check_empty_catch(lines: list[str], i: int) -> str | None:
    """"empty" for a catch opened on lines[i] that swallows the error with nothing,
    "canned" for one that answers it with a literal success; None otherwise.
    Comments are ignored, unless a comment is all the catch holds and gives a reason."""
    start = max(0, i - 12)
    raw = "\n".join(lines[start : i + 12])
    masked = "\n".join(_masked(line) for line in lines[start : i + 12])
    off = sum(len(line) + 1 for line in lines[start:i])
    line_end = off + len(lines[i])
    for m in CATCH_OPEN_RE.finditer(masked, off):
        if m.start() >= line_end:
            break
        open_ = m.end() - 1
        close = _match_brace(masked, open_, 1)
        if close is None:
            continue
        kind = _classify_catch_body(raw[open_ + 1 : close])
        if kind == "empty":
            try_close = masked.rfind("}", 0, m.start())
            try_open = _match_brace(masked, try_close, -1) if try_close >= 0 else None
            if try_open is not None and re.search(r"\btry\s*$", masked[:try_open]):
                if _swallow_is_deliberate(masked, try_open, try_close, close):
                    continue
        if kind:
            return kind
    return None


# `promise.catch(() => ({ ok: true }))`: the same canned success, written as a promise handler.
PROMISE_CANNED_RE = re.compile(
    r"\.catch\(\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\(\s*\{([^{}]*)\}\s*\)\s*\)"
)

FORM_PREVENT_DEFAULT = re.compile(r"""(?:\be|event|evt|ev)\.preventDefault\(\)""")
# The handler is a form submit: `onSubmit`, `addEventListener("submit"`, `@submit`, `handleSubmit`.
SUBMIT_CONTEXT_RE = re.compile(r"""[Ss]ubmit\b|[Ss]ubmit\w*\s*[=:(]|\(\s*["']submit["']|<form\b""")
# What a disconnected handler may still do: stop the event, log, alert, or read FormData Locally.
INERT_CALL_RE = re.compile(
    r"""(?:\b\w+\.)?(?:preventDefault|stopPropagation|stopImmediatePropagation)\s*\(\s*\)"""
    r"""|\bconsole\.\w+\s*\((?:[^()]|\([^()]*\))*\)"""
    r"""|\b(?:window\.)?alert\s*\((?:[^()]|\([^()]*\))*\)"""
    r"""|\bnew\s+(?:FormData|URLSearchParams)\s*\((?:[^()]|\([^()]*\))*\)"""
    r"""|\bObject\.fromEntries\s*\((?:[^()]|\([^()]*\))*\)"""
)
_LOCAL_DECL_RE = re.compile(r"\b(?:const|let|var)\s+(?:[A-Za-z_$][\w$]*|\{[^}]*\}|\[[^\]]*\])\s*=(?![=>])")
# Anything else the handler does: a call, or a write to something outside it.
HANDLER_EFFECT_RE = re.compile(
    r"""(?<![\w$.])(?!(?:if|for|while|switch|return|catch|function|typeof|await|new)\b)[A-Za-z_$][\w$.]*\s*\("""
    r"""|[\w$\]]\.[\w$]+\s*(?:=(?![=>])|\+=|-=)|\b[A-Za-z_$][\w$]*\s*(?:=(?![=>])|\+\+|--)"""
)


def disconnected_submit(lines: list[str], i: int, col: int) -> int:
    """Return the 1-based closing line of the submit handler whose `preventDefault()` is at
    lines[i][col] if the handler does nothing else, or 0 if it has a real effect."""
    context = "\n".join(_masked(line) for line in lines[max(0, i - 3) : i]) + _masked(lines[i])[:col]
    if not SUBMIT_CONTEXT_RE.search(context):
        return 0
    body, depth = [], 0
    for k in range(i, min(len(lines), i + 40)):
        text = _masked(lines[k])[col if k == i else 0 :]
        text = re.sub(r"//.*$|/\*.*?\*/", "", text)
        for pos, c in enumerate(text):
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth < 0:
                    body.append(text[:pos])
                    rest = INERT_CALL_RE.sub("", "\n".join(body))
                    rest = _LOCAL_DECL_RE.sub("", rest)
                    return (k + 1) if not HANDLER_EFFECT_RE.search(rest) else 0
        body.append(text)
    return 0


def generic_fake_findings(rel: str, suffix: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    core_enabled = "core" in ENABLED_RULE_PACKS
    web_ui_enabled = "web-ui" in ENABLED_RULE_PACKS
    is_web_ui = suffix in WEB_UI_SUFFIXES

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue
        if web_ui_enabled and is_web_ui and literals.search_code(STUB_CLICK_HANDLER, line):
            out.append(Finding(rel, i + 1, "stub-click-handler", line))
        if core_enabled and SYNTHETIC_DELAY.search(line):
            window = "\n".join(lines[i : i + 7])
            if SYNTHETIC_MOCK_RETURN.search(window):
                out.append(Finding(rel, i + 1, "synthetic-delay-mock", line, end_line=min(len(lines), i + 7)))
        if core_enabled and is_web_ui and "catch" in line:
            kind = check_empty_catch(lines, i)
            promise = literals.search_code(PROMISE_CANNED_RE, line)
            if not kind and promise and canned_object(promise.group(1)):
                kind = "canned"
            if kind:
                rule = "canned-error-fallback" if kind == "canned" else "unhandled-empty-catch"
                out.append(Finding(rel, i + 1, rule, line))
        brace_catch = suffix in BRACE_CATCH_SUFFIXES and BRACE_CATCH_RE.search(line)
        if core_enabled and (brace_catch or MULTI_LANG_ERROR_SWALLOW_RE.search(line)):
            end = min(len(lines), i + 6)
            brace = line.find("{", brace_catch.end() if brace_catch else 0)
            if brace >= 0:  # a brace language: the handler ends at its closing brace
                close = _closing_line(lines, i, brace, "{", "}")
                end = (close + 1) if close is not None else end
            elif suffix == ".py":  # an indented handler ends at the first line not indented under it
                indent = len(line) - len(line.lstrip())
                for k in range(i + 1, end):
                    # A comment line does not end the handler, whatever its indentation.
                    if lines[k].strip() and not lines[k].lstrip().startswith("#") and len(lines[k]) - len(lines[k].lstrip()) <= indent:
                        end = k
                        break
            window = "\n".join(lines[i:end])
            if _canned_ok(window):
                out.append(Finding(rel, i + 1, "canned-error-fallback", line, end_line=end))
            # `except Exception: pass` in a close()/cleanup helper is a best-effort release, not a fake.
            elif suffix == ".py" and PY_BROAD_EXCEPT_RE.match(line) and _only_pass(lines, i, end) and not _in_cleanup_def(lines, i):
                out.append(Finding(rel, i + 1, "unhandled-empty-catch", line, end_line=end))
        prevent = web_ui_enabled and is_web_ui and FORM_PREVENT_DEFAULT.search(line)
        if prevent:
            sub_end = disconnected_submit(lines, i, prevent.start())
            if sub_end:
                out.append(Finding(rel, i + 1, "disconnected-form-submit", line, end_line=sub_end))
    return out


def _python_string_lines(text: str) -> set[int]:
    """0-based lines inside multi-line Python strings (docstrings, templates).

    Uses the tokenizer, so a triple quote inside a comment or a one-line string
    never flips the state. Falls back to a quote count, comments excluded, when
    the file does not tokenize.
    """
    import io
    import tokenize

    out: set[int] = set()
    try:
        start = None
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            kind = tokenize.tok_name.get(tok.type, "")
            if kind == "STRING" and tok.end[0] > tok.start[0]:
                out.update(range(tok.start[0] - 1, tok.end[0]))
            elif kind == "FSTRING_START":
                start = tok.start[0]
            elif kind == "FSTRING_END" and start is not None:
                if tok.end[0] > start:
                    out.update(range(start - 1, tok.end[0]))
                start = None
        return out
    except (tokenize.TokenError, SyntaxError, IndentationError):
        pass
    inside = False
    for i, line in enumerate(text.split("\n")):
        stripped = line.strip()
        if stripped.startswith("#"):
            if inside:
                out.add(i)
            continue
        if (stripped.count('"""') + stripped.count("'''")) % 2 == 1:
            inside = not inside
            out.add(i)
        elif inside:
            out.add(i)
    return out


def raw_findings(rel: str, suffix: str, text: str) -> list[Finding]:
    lines = text.split("\n")
    if suffix == ".json":
        return data_findings(rel, lines)
    findings = v2_findings(rel, suffix, lines)
    findings.extend(generic_fake_findings(rel, suffix, lines))
    if any(p in SEED_DIR_SEGMENTS for p in _norm_path(rel).split("/")[:-1]):
        return findings
    skip_lines = _python_string_lines(text) if suffix == ".py" else set()
    cti_enabled = "cti" in ACTIVE_PACKS
    core_enabled = "core" in ENABLED_RULE_PACKS

    for i, line in enumerate(lines):
        if i in skip_lines:
            continue
        stripped = line.strip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue

        is_type_union = "|" in line and re.search(r"""["'];?\s*$|["']\s*\|""", line)
        if cti_enabled:
            findings.extend(cti.scan_cti_legacy_line(rel, lines, i, line, Finding))
            if cti.CVE_LITERAL.search(line):
                findings.append(Finding(rel, i + 1, "hardcoded-cve", line))
            if cti.VERDICT_LITERAL.search(line) and in_error_path(lines, i) and not is_type_union:
                findings.append(Finding(rel, i + 1, "verdict-on-error-path", line))

        if not core_enabled:
            continue

        if FAKE_NAME.search(line) and ("return" in line or "=" in line):
            findings.append(Finding(rel, i + 1, "fake-named-data", line))

        if literals.search_code(LITERAL_RETURN, line) and is_simulated_value(lines, i):
            findings.append(Finding(rel, i + 1, "simulated-return-value", line))

        if FRESH_EVENT_TIMESTAMP.search(line):
            findings.append(Finding(rel, i + 1, "invented-event-timestamp", line))

        state = ASSERTED_STATE_LITERAL.search(line) or (cti_enabled and cti.ASSERTED_STATE_LITERAL.search(line))
        if state and not is_type_union and not is_outbound_config(lines, i):
            findings.append(Finding(rel, i + 1, "asserted-state", line))

        score = SCORE_LITERAL.search(line) or (cti_enabled and cti.SCORE_LITERAL.search(line))
        if score and in_error_path(lines, i) and int(score.group(1)) > 0:
            findings.append(Finding(rel, i + 1, "score-on-error-path", line))

    findings.extend(prompt_findings(rel, text, lines))

    return findings


# --- self-check ------------------------------------------------------------

SELF_CHECK_SETTINGS = {
    "score_owners": ["src/billing/pricing.ts"],
    "model_call_patterns": [r"lib/ai\b"],
}

SELF_CHECK_CASES: list[tuple[str, str, bool]] = [
    (
        "a prompt asking for an approval and a risk score with nothing supplied",
        """
        import { GoogleGenAI } from "@google/genai";
        const r = await genAI.models.generateContent({
          contents: `Assess loan application "${applicationId}". Return JSON:
            { "approved": boolean, "risk_score": number }`,
        });
        """,
        True,
    ),
    (
        "the same request through a project wrapper named in model_call_patterns",
        """
        import { generate } from "@/lib/ai";
        return generate({ prompt: `Assess it. Return JSON:
          { "riskScore": number, "severity": "high" | "low" }`, parse: (v) => v });
        """,
        True,
    ),
    (
        "a verdict asked for with no evidence supplied",
        """
        import OpenAI from "openai";
        const r = await client.chat.completions.create({ messages: [{ role: "user",
          content: `Review this refund. Return JSON: { "verdict": "approve" | "reject" }` }] });
        """,
        True,
    ),
    (
        "the same request, with observed evidence supplied",
        """
        import { generate } from "@/lib/ai";
        const ev = evidenceBlock(order, ledgerRows);
        return generate({ prompt: `${ev} Return JSON:
          { "summary": "string", "points": [{ "text": "string", "source": "string" }] }`,
          parse: (v) => v });
        """,
        False,
    ),
    (
        "a judgement asked for in prose, with nothing supplied",
        """
        from openai import OpenAI
        prompt = f"Give a risk_score from 0 to 100 and a verdict for the vendor {vendor.name}."
        resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": prompt}])
        """,
        True,
    ),
    (
        "a summary asked for in prose: no judgement",
        """
        from openai import OpenAI
        prompt = f"Give a short summary of the release notes for {repo.name}."
        resp = client.chat.completions.create(model="m", messages=[{"role": "user", "content": prompt}])
        """,
        False,
    ),
    (
        "a type definition that never calls a model",
        """
        export interface Review {
          "riskScore": number;
          verdict: "approve" | "reject";
        }
        """,
        False,
    ),
    (
        "code reading a score rather than asking for one",
        """
        import { generate } from "@/lib/ai";
        const out = { riskScore: row.score, verdict: row.verdict };
        return generate({ prompt: summarise(out), parse: (v) => v });
        """,
        False,
    ),
]


V2_SELF_CHECK_CASES: list[tuple[str, str, str, str | None]] = [
    ("a documentation address hardcoded as an upstream", "src/lib/client.ts",
     '  const UPSTREAM = "198.51.100.52";', "documentation-address"),
    ("a documentation IPv6 address", "src/components/x.tsx",
     "  { ip: '2001:db8:85a3::8a2e:370:7334' },", "documentation-address"),
    ("a documentation range, not an address", "internal/net/allowlist.go",
     '\t\t"198.51.100.0/24",', None),
    ("a documentation prefix in an exclusion list", "src/lib/ipfilter.ts",
     '  "203.0.113.",', None),
    ("a documentation address as an input placeholder", "src/components/x.tsx",
     '  <input placeholder="e.g. 203.0.113.5" />', None),
    ("an always-current record timestamp", "src/components/ActivityFeed.tsx",
     "    updatedAt: new Date(Date.now() - 36 * 3600 * 1000).toISOString(),",
     "always-current-fake"),
    ("a query window computed from the clock", "src/components/x.tsx",
     "  const since = new Date(Date.now() - 30 * 86_400_000);", None),
    ("a sample array presented as a live stream", "src/data/orders.ts",
     "export const SAMPLE_ORDER_STREAM: Order[] = [", "demo-named-data"),
    ("a simulated result", "internal/billing/invoice.go",
     "\tsimulatedTotal := 42", "demo-named-data"),
    ("an invented service health row", "src/components/StatusWidget.tsx",
     "    { name: 'payments-api', region: 'eu-west', status: 'Healthy' },",
     "asserted-state"),
    ("a score raised outside the scoring module", "src/lib/cart.ts",
     "      order.score = 10;", "score-outside-scoring"),
    ("a score comparison is not an assignment", "src/lib/x.ts",
     "  if (result.score === 0) return;", None),
    ("the module that owns the score", "src/billing/pricing.ts",
     "  result.score = total;", None),
    ("a score set to a constant on the error path", "app/services/rank.py",
     "    except Exception:\n        confidence = 87", "score-on-error-path"),
    ("a catalogue route that serves a canned list when upstream fails", "src/app/api/catalog/route.ts", """
export async function GET(request) {
  try {
    const upstream = await fetch(url);
    if (upstream.ok) {
      return new NextResponse(await upstream.text(), { status: upstream.status });
    }
  } catch {
    // Fall back to a snapshot
  }
  const content = `# catalog
sku-1001 widget`;
  return new NextResponse(content, { status: 200 });
}
""", "route-canned-fallback"),
    ("a canned data set on a failed upstream", "src/app/api/x/route.ts", """
  if (!upstream.ok) {
    return NextResponse.json({ items: [{ sku: "sku-1001" }] });
  }
""", "route-canned-fallback"),
    ("a failure answered as a failure", "src/app/api/x/route.ts", """
  } catch (error) {
    return NextResponse.json({ error: "The gateway did not answer." }, { status: 502 });
  }
""", None),
    ("a side effect swallowed before a real answer", "src/app/api/x/route.ts", """
  try {
    await sendEmail(app);
  } catch (emailErr) {
    log.error("failed to send", emailErr);
  }
  return NextResponse.json({ ok: true, application: app });
""", None),
    # Generic fake functionality.
    ("a stub click handler", "src/components/Button.tsx",
     '  <button onClick={() => {}}>Save</button>', "stub-click-handler"),
    ("a stub click handler suppressed with prufgate-ignore", "src/components/Button.tsx",
     '  // prufgate-ignore: stub-click-handler - intentional placeholder\n  <button onClick={() => {}}>Save</button>', None),
    ("a prufgate-ignore without a reason suppresses nothing", "src/components/Button.tsx",
     '  <button onClick={() => {}}>Save</button> {/* prufgate-ignore: stub-click-handler */}', "stub-click-handler"),
    ("a reasoned prufgate-ignore naming another rule suppresses nothing", "src/components/Button.tsx",
     '  <button onClick={() => {}}>Save</button> {/* prufgate-ignore: synthetic-delay -- demo only */}', "stub-click-handler"),
    ("a valid click handler with logic", "src/components/Button.tsx",
     '  <button onClick={() => handleClick(id)}>Save</button>', None),
    ("synthetic delay mock returning hardcoded data", "src/services/api.ts", """
export async function getStats() {
  await new Promise((r) => setTimeout(r, 500));
  return { success: true, items: [1, 2, 3] };
}
""", "synthetic-delay-mock"),
    ("a catch answering a failure with a canned success", "src/services/handler.ts", """
  try {
    doRiskyThing();
  } catch (err) {
    return { success: true }; // keep the UI happy
  }
""", "canned-error-fallback"),
    ("an empty catch swallowing the error", "src/services/handler.ts", """
  try {
    doRiskyThing();
  } catch (err) {
    // ignore
  }
""", "unhandled-empty-catch"),
    ("catch with proper error logging passes", "src/services/handler.ts", """
  try {
    doRiskyThing();
  } catch (err) {
    console.error("Failed:", err);
    throw err;
  }
""", None),
    ("disconnected form submit", "src/components/Form.tsx", """
const onFormSubmit = (e) => {
  e.preventDefault();
  // stubbed form
};
""", "disconnected-form-submit"),
    ("connected form submit with state setter passes", "src/components/Form.tsx", """
const onFormSubmit = (e) => {
  e.preventDefault();
  setSubmitted(true);
};
""", None),
    ("Python canned error fallback returning ok True", "app/services/payment.py", """
def charge_card(amount: int) -> dict:
    try:
        return gateway.charge(amount)
    except Exception:
        return {"ok": True, "data": []}
""", "canned-error-fallback"),
    ("Python error recovery calling backup service passes", "app/services/payment.py", """
def charge_card(amount: int) -> dict:
    try:
        return primary_gateway.charge(amount)
    except Exception:
        return backup_gateway.charge(amount)
""", None),
    ("Python failure answered with a hard-coded approval", "app/services/payment.py", """
def charge(order_id):
    try:
        result = gateway.submit(order_id)
    except Exception:
        return {"approved": True, "reference": "ok"}
    return {"approved": result.approved}
""", "canned-error-fallback"),
    ("Python failure answered as a decline", "app/services/payment.py", """
def charge(order_id):
    try:
        result = gateway.submit(order_id)
    except Exception:
        return {"approved": False, "reason": "gateway"}
    return {"approved": True, "reference": result.reference}
""", None),
    ("Go lookup error answered as valid", "internal/license/check.go", """
func IsValid(key string) (bool, error) {
	rec, err := lookup(key)
	if err != nil {
		return true, nil
	}
	return rec.Active, nil
}
""", "canned-error-fallback"),
    ("Go not-found answered as invalid, without an error", "internal/license/check.go", """
func IsValid(key string) (bool, error) {
	rec, err := lookup(key)
	if err != nil {
		return false, nil
	}
	return rec.Active, nil
}
""", None),
    ("Python broad except swallowed with pass", "app/sync/run.py", """
def sync(source, target):
    for item in source.items():
        try:
            target.put(item)
        except Exception:
            pass
""", "unhandled-empty-catch"),
    ("Python bare except: pass on one line", "app/sync/run.py", """
def sync(source, target):
    try:
        target.flush()
    except: pass
""", "unhandled-empty-catch"),
    ("Python narrow except with pass passes", "app/sync/cleanup.py", """
def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
""", None),
    ("Python broad except that logs passes", "app/sync/run.py", """
def sync(source, target):
    try:
        target.put(item)
    except Exception:
        log.exception("put failed")
        pass
""", None),
    ("a literal dict under a 'simulated' comment", "app/accounts/balance.py", """
def balance(client, account_id):
    # simulated response until the ledger API is wired up
    return {"account": account_id, "balance": 1200}
""", "simulated-return-value"),
    ("a computed dict under an honest comment passes", "app/accounts/balance.py", """
def balance(client, account_id):
    # the ledger answers in cents
    return {"account": account_id, "balance": client.cents(account_id) / 100}
""", None),
    ("a sleep before a fixed 'complete' result", "app/jobs/report.py", """
def run_report(engine, report_id):
    time.sleep(2)
    return {"status": "complete", "rows": 42}
""", "synthetic-delay-mock"),
    ("a sleep before the real result passes", "app/jobs/report.py", """
def run_report(engine, report_id):
    time.sleep(2)
    return engine.result(report_id)
""", None),
    ("Go canned error fallback returning HTTP 200", "internal/api/handler.go", """
func GetItems(c *gin.Context) {
    items, err := repo.Fetch()
    if err != nil {
        c.JSON(200, gin.H{"ok": true, "items": []string{}})
        return
    }
}
""", "canned-error-fallback"),
    ("Go error answered as an error, then success after the branch, passes", "internal/api/handler.go", """
func GetItems(c *gin.Context) {
    items, err := repo.Fetch()
    if err != nil {
        c.JSON(502, gin.H{"error": "upstream"})
        return
    }
    c.JSON(200, gin.H{"ok": true, "items": items})
}
""", None),
    ("Java catch answering a failure with 200", "src/main/java/OrderController.java", """
try {
  return svc.list();
} catch (Exception e) {
  return ResponseEntity.ok(Map.of("ok", true));
}
""", "canned-error-fallback"),
    ("PHP catch answering a failure with ok", "app/Http/Controllers/OrderController.php", """
try {
  return $svc->list();
} catch (Exception $e) {
  return response()->json(['ok' => true]);
}
""", "canned-error-fallback"),
    ("C# catch answering a failure with Ok", "Controllers/OrdersController.cs", """
try {
  return Ok(svc.List());
} catch (Exception) {
  return Ok(new { success = true });
}
""", "canned-error-fallback"),
    ("Ruby rescue rendering ok", "app/controllers/orders_controller.rb", """
def index
  render json: svc.list
rescue StandardError
  render json: { ok: true }
end
""", "canned-error-fallback"),
    ("Rust unimplemented production stub", "src/handlers/checkout.rs", """
pub async fn process_order(order_id: String) -> Result<(), Error> {
    todo!("implement checkout")
}
""", "unimplemented-production-stub"),
    ("Python NotImplementedError in production route", "app/routes/export.py", """
def export_report(request):
    raise NotImplementedError("export not wired yet")
""", "unimplemented-production-stub"),
    ("Python abstractmethod NotImplementedError passes", "app/domain/base.py", """
class BaseExporter(ABC):
    @abstractmethod
    def export(self) -> bytes:
        raise NotImplementedError
""", None),
    ("Python synthetic delay mock", "app/services/analytics.py", """
async def fetch_metrics():
    await asyncio.sleep(1)
    return {"status": "ok", "items": [1, 2, 3]}
""", "synthetic-delay-mock"),
    ("Python simulated return value under placeholder comment", "app/services/score.py", """
def compute_trust_score(user_id: str) -> float:
    # placeholder: would normally compute from ledger
    return 0.95
""", "simulated-return-value"),
    ("a docstring mentioning a placeholder is not code", "app/services/doc.py", '''
def f():
    """Placeholder: would normally compute.
    return 0.95
    """
    return compute()
''', None),
    ("Python always-current fake timestamp", "app/services/events.py", """
def get_latest_event():
    return {"updated_at": datetime.now() - timedelta(minutes=5)}
""", "always-current-fake-timestamp"),
    ("RFC 2606 example.com endpoint in production code", "src/services/webhook.ts", """
const WEBHOOK_ENDPOINT = "https://api.example.com/v1/events";
""", "documentation-ip-or-domain"),
]


def _check_v2_case(name: str, rel: str, source: str, rule: str | None) -> bool:
    got_raw = {f.rule for f in scan_text(rel, Path(rel).suffix, source)}
    got_expanded: set[str] = set()
    for r in got_raw:
        got_expanded |= expand_rule_aliases(r)
    if (rule is None and got_raw) or (rule is not None and rule not in got_expanded):
        want = f"flag {rule}" if rule else "pass"
        print(f"  FAIL  expected to {want}: {name} (got {sorted(got_raw) or 'nothing'})", file=sys.stderr)
        return False
    return True


def _check_prompt_cases(cases: list[tuple[str, str, bool]]) -> int:
    failures = 0
    for name, source, should_flag in cases:
        flagged = bool(prompt_findings("<self-check>", source, source.split("\n")))
        if flagged != should_flag:
            failures += 1
            want = "flag" if should_flag else "pass"
            print(f"  FAIL  expected to {want}: {name}", file=sys.stderr)
    return failures


def self_check() -> int:
    """Prove each rule still fires. Returns a process exit code."""
    failures = 0
    try:
        apply_settings(SELF_CHECK_SETTINGS)
        failures += _check_prompt_cases(SELF_CHECK_CASES)
        failures += sum(not _check_v2_case(*case) for case in V2_SELF_CHECK_CASES)

        # The optional CTI pack, on.
        apply_settings({**SELF_CHECK_SETTINGS, "packs": ["cti"]})
        failures += _check_prompt_cases(cti.PROMPT_SELF_CHECK_CASES)
        failures += sum(not _check_v2_case(*case) for case in cti.SELF_CHECK_CASES)

        # Score ownership and the CTI pack are opt-in: with default settings they are silent.
        apply_settings({})
        if scan_text("src/lib/cart.ts", ".ts", "      order.score = 10;"):
            failures += 1
            print("  FAIL  score-outside-scoring fired with no score_owners configured", file=sys.stderr)
        cti_rules = {rule for _, _, _, rule in cti.SELF_CHECK_CASES if rule}
        for name, rel, source, _rule in cti.SELF_CHECK_CASES:
            leaked = {f.rule for f in scan_text(rel, Path(rel).suffix, source)} & cti_rules
            if leaked:
                failures += 1
                print(f"  FAIL  pack rule fired with the pack off: {name} ({sorted(leaked)})", file=sys.stderr)

        import tempfile

        apply_settings({"packs": ["cti"]})
        with tempfile.TemporaryDirectory() as tmp:
            data = Path(tmp) / "svc" / "data" / "signatures.json"
            data.parent.mkdir(parents=True)
            data.write_text('{"http_body_hash": "' + cti.EMPTY_SHA256 + '"}')
            other = Path(tmp) / "svc" / "package.json"
            other.write_text("{}")
            got = collect([str(Path(tmp) / "svc")])
            if data not in got or other in got:
                failures += 1
                print("  FAIL  shipped data/*.json is not collected (or other .json is)", file=sys.stderr)

            bad = Path(tmp) / "fabrication.json"
            bad.write_text(json.dumps({"known_debt": [{"path": "a.ts", "rule": "r", "reason": "no ticket"}]}))
            try:
                load_settings(str(bad))
                failures += 1
                print("  FAIL  known_debt without an issue reference was accepted", file=sys.stderr)
            except SettingsError:
                pass
    finally:
        apply_settings({})

    if failures:
        print(
            f"\n{failures} self-check case(s) failed. A rule is not detecting what "
            f"it was written for. For the prompt rule, most likely a call site "
            f"moved and MODEL_CALL no longer recognises it.",
            file=sys.stderr,
        )
        return 1

    total = len(SELF_CHECK_CASES) + len(V2_SELF_CHECK_CASES) + len(cti.SELF_CHECK_CASES) + len(cti.PROMPT_SELF_CHECK_CASES)
    print(f"detector self-check: {total} case(s) ok")
    return 0


# --- project settings ------------------------------------------------------

SettingsError = ConfigError


class GitError(RuntimeError):
    """git could not answer: not a repository, an unknown ref, or a refused argument."""


class ScanError(RuntimeError):
    """A file selected for scanning could not be read."""


def load_settings(path: str | None, ref: str | None = None) -> dict:
    """Read and validate a settings file (.prufgate/config.yaml or .prufgate/fabrication.json),
    as it is at the base ref `ref` when one is given."""
    cfg = PrufGateConfig.load(".", explicit_path=path, ref=ref)
    if cfg.source_path is None and path is None:
        return {}
    return cfg.to_detector_settings()


def apply_settings(settings: dict) -> None:
    """Install settings into the module's rule tables. Replaces, never merges."""
    global V2_EXEMPT, KNOWN_DEBT, KNOWN_DEBT_CEILINGS, SCORE_OWNERS, ALLOWED, JUDGEMENT_FIELD
    global ENABLED_LANGUAGES, MODEL_CALL, EVIDENCE_SUPPLIED, ACTIVE_PACKS, ENABLED_RULE_PACKS
    V2_EXEMPT = dict(settings.get("exempt", {}))
    KNOWN_DEBT = dict(settings.get("known_debt", {}))
    KNOWN_DEBT_CEILINGS = dict(settings.get("known_debt_ceilings", {}))
    SCORE_OWNERS = tuple(settings.get("score_owners", ()))
    ALLOWED = tuple(settings.get("allowed_paths", ()))
    ENABLED_LANGUAGES = {lang.lower() for lang in settings.get("languages", ())}
    env_packs = {p.strip() for p in os.environ.get("PRUFGATE_PACKS", "").split(",") if p.strip()}
    explicit_packs = set(settings.get("packs", ())) | env_packs
    ACTIVE_PACKS = explicit_packs
    if explicit_packs & set(DEFAULT_PACKS):
        ENABLED_RULE_PACKS = set(explicit_packs)
    else:
        ENABLED_RULE_PACKS = set(DEFAULT_PACKS) | explicit_packs
    MODEL_CALL = re.compile(
        "|".join([MODEL_CALL_DEFAULT, *settings.get("model_call_patterns", [])]),
        re.IGNORECASE | re.MULTILINE,
    )
    cti_on = "cti" in ACTIVE_PACKS
    JUDGEMENT_FIELD = _judgement_field(
        JUDGEMENT_FIELDS_DEFAULT + ("|" + cti.JUDGEMENT_FIELDS if cti_on else "")
    )
    EVIDENCE_SUPPLIED = re.compile(
        "|".join([EVIDENCE_DEFAULT, *([cti.EVIDENCE_MARKERS] if cti_on else []), *settings.get("evidence_markers", [])]),
        re.IGNORECASE,
    )


def collect(paths: list[str]) -> list[Path]:
    """Source files under `paths`, less tests, build output, tooling and
    `allowed_paths`. Skip rules look at path segments below each given root (a
    workspace that itself sits under `build/` is still scanned)."""
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        candidates = [p] if p.is_file() else p.rglob("*")
        for f in candidates:
            rel_parts = Path(workspace_relative(p)).parts if p.is_file() else f.relative_to(p).parts
            if not p.is_file() and any(part.startswith(".") or part == "__pycache__" for part in rel_parts):
                continue
            is_data = f.suffix == ".json" and any(d in "/" + _norm_path(str(f)) for d in DATA_JSON_DIRS)
            if not f.is_file() or not (f.suffix in SUFFIXES or is_data):
                continue
            if ENABLED_LANGUAGES and not is_data:
                lang = classify_file(f)
                if lang not in ENABLED_LANGUAGES:
                    continue
            if _is_skipped_by_default(tuple(rel_parts)) or _is_prufgate_own_file(f):
                continue
            rel = workspace_relative(f) if f.is_absolute() else _norm_path(str(f))
            if any(_path_matches_pattern(rel, a) for a in ALLOWED):
                continue
            out.append(f)
    return sorted(set(out))


def _git(args: list[str], cwd: Path | str | None) -> str:
    try:
        res = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace"
        )
    except OSError as e:
        raise GitError(f"cannot run git: {e}") from e
    if res.returncode != 0:
        raise GitError(git_error_line(res.stderr) or f"git {args[0]} failed")
    return res.stdout


def git_error_line(stderr: str) -> str:
    """git's own reason (the `fatal:`/`error:` line), not a trailing usage hint."""
    lines = [ln.strip() for ln in stderr.strip().splitlines() if ln.strip()]
    return next((ln for ln in lines if ln.startswith(("fatal:", "error:"))), lines[0] if lines else "")


def changed_files(base: str | None = None, cwd: Path | str | None = None) -> list[str]:
    """Files changed against `base` (three-dot, for CI) or the working tree,
    plus untracked files, relative to `cwd`. Raises GitError when git cannot
    answer, so a broken diff never reads as "nothing changed"."""
    if base is not None and (not base or base.startswith("-")):
        raise GitError(f"refusing base ref {base!r}")
    rng = [f"{base}...HEAD"] if base else ["HEAD"]
    diff = _git(["diff", "--name-only", "-z", "--relative", "--end-of-options", *rng], cwd)
    untracked = _git(["ls-files", "-z", "--others", "--exclude-standard"], cwd)
    return [f for f in (diff + untracked).split("\0") if f]


def main() -> int:
    args = sys.argv[1:]
    if "--self-check" in args:
        return self_check()

    json_out = None
    config_path = None
    cli_packs: list[str] = []
    clean_args = []
    it = iter(args)
    for a in it:
        if a.startswith("--json-out="):
            json_out = a.split("=", 1)[1]
        elif a == "--json-out":
            json_out = next(it, None)
        elif a.startswith("--config="):
            config_path = a.split("=", 1)[1]
        elif a == "--config":
            config_path = next(it, None)
        elif a.startswith("--pack="):
            cli_packs.extend(p.strip() for p in a.split("=", 1)[1].split(",") if p.strip())
        elif a == "--pack":
            val = next(it, None)
            if val:
                cli_packs.extend(p.strip() for p in val.split(",") if p.strip())
        elif a.startswith("--") and not a.startswith("--changed"):
            print(f"unknown option: {a}", file=sys.stderr)
            return 2
        else:
            clean_args.append(a)
    args = clean_args

    changed_arg = next((a for a in args if a.startswith("--changed")), None)
    base = changed_arg.split("=", 1)[1] if changed_arg and "=" in changed_arg else None
    try:
        loaded = load_settings(config_path, base)
        if cli_packs:
            loaded["packs"] = list(set(loaded.get("packs", [])) | set(cli_packs))
        apply_settings(loaded)
    except SettingsError as e:
        print(f"fabrication settings: {e}", file=sys.stderr)
        return 2

    if changed_arg:
        try:
            targets = [f for f in changed_files(base) if Path(f).exists()]
        except GitError as e:
            print(f"--changed: {e}", file=sys.stderr)
            return 2
        if not targets:
            print("No changed files to scan.")
            if json_out:
                Path(json_out).parent.mkdir(parents=True, exist_ok=True)
                Path(json_out).write_text("[]")
            return 0
    else:
        targets = args or ["."]

    missing = [t for t in targets if not Path(t).exists()]
    if missing:
        print(f"no such path: {', '.join(missing)}", file=sys.stderr)
        return 2
    files = collect(targets)
    findings: list[Finding] = []
    try:
        for f in files:
            findings.extend(scan_file(f))
    except ScanError as e:
        print(str(e), file=sys.stderr)
        return 2

    if not changed_arg and not args:
        for table, entries in (("V2_EXEMPT", V2_EXEMPT), ("KNOWN_DEBT", KNOWN_DEBT)):
            for (path, rule), reason in entries.items():
                p = Path(path)
                if p.is_file():
                    text = p.read_text(encoding="utf-8", errors="replace")
                    live = any(rules_match(f.rule, rule) for f in raw_findings(path, p.suffix, text))
                else:  # a glob or a directory: stale when no scanned file matching it still trips the rule
                    live = any(
                        rules_match(f.rule, rule)
                        for g in files
                        if _path_matches_pattern(workspace_relative(g), path)
                        for f in raw_findings(workspace_relative(g), g.suffix, g.read_text(encoding="utf-8", errors="replace"))
                    )
                if not live:
                    findings.append(
                        Finding(
                            path,
                            0,
                            "stale-exemption",
                            f"{table}[{rule}] no longer matches anything: {reason}",
                        )
                    )
        if KNOWN_DEBT:
            print(f"Known debt, not yet removed ({len(KNOWN_DEBT)}):")
            for (path, rule), reason in KNOWN_DEBT.items():
                print(f"  {path} [{rule}] {reason}")
            print()

    # Low-confidence rules are off unless the config turns them on: they neither
    # report nor count toward a debt ceiling.
    findings = visible(findings, bool(loaded.get("enable_low_confidence")))

    if KNOWN_DEBT_CEILINGS:
        cfg_obj = PrufGateConfig(known_debt_ceilings=KNOWN_DEBT_CEILINGS)
        violations, advisories = cfg_obj.check_debt_ratchet(findings)
        for adv in advisories:
            print(f"  [ratchet-down] {adv}")
        if violations:
            for v in violations:
                findings.append(Finding(".prufgate/config.yaml", 1, "debt-ceiling-breached", v))
        elif not changed_arg:
            # Filter out findings covered by non-breached numeric ceilings (full scan only)
            findings = [
                f
                for f in findings
                if not any(rules_match(f.rule, cr) for cr in KNOWN_DEBT_CEILINGS)
            ]

    if json_out:
        Path(json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(json_out).write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    if not findings:
        print(f"No fabrication patterns found across {len(files)} file(s).")
        return 0

    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule, []).append(f)

    print(f"{len(findings)} possible fabrication(s) across {len(files)} file(s):\n")
    for rule, group in sorted(by_rule.items()):
        print(f"── {rule} ({len(group)})")
        for f in group:
            print(f"  {f}")
        print()

    print("Each is a candidate, not a verdict. Ask: if the real source is")
    print("unavailable, does this render as though it were observed data?")
    return 1


if __name__ == "__main__":
    sys.exit(main())
