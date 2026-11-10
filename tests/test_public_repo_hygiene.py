"""Leak guard: this repository is public, so no tracked file and no new commit
may carry private data.

Structural checks only, run on every tracked file (this one included):
local home paths on Linux, macOS and Windows; email addresses outside the
invented example domains and the project's own public addresses; IPv4
addresses other than loopback, documentation ranges and cloud metadata
endpoints; credential-shaped tokens and private keys; private access-gateway
domains; AI attribution trailers.

Project-specific names are never written here, not even hashed: a short name
is recovered from its hash with a word list. Maintainers who have such a list
keep it outside the repository and pass it at run time:

    PRUFGATE_PRIVATE_TERMS_FILE=/path/to/terms   (regular expressions separated by | , or newlines)
    PRUFGATE_PRIVATE_TERMS="term1,term2"         (the same, inline)

Without either, that layer is skipped and says so. Findings print the file,
the line and the kind of check, never the matched text.

New commits are checked too (author and committer addresses, messages):
the range is PRUFGATE_HYGIENE_RANGE, else origin/main..HEAD when origin/main
exists, else the whole history. Issues and pull requests cannot be checked
from here: see AGENTS.md.
"""
from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Names that are public by design: the publisher and its public domain.
ALLOWED_NAMES = ("GuardianVigil-Labs", "GuardianVigil", "guardianvigil.io")

ALLOWED_IPV4 = re.compile(
    r"^(?:127\.|0\.0\.0\.0$|255\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|169\.254\.169\.254$|100\.100\.100\.200$)"
)
ALLOWED_EMAIL = re.compile(
    r"@(?:(?:[a-z0-9-]+\.)*(?:example|example\.(?:com|org|net)|test|invalid|localhost)"
    r"|guardianvigil\.io|users\.noreply\.github\.com)$"
    r"|^(?:noreply@github\.com|support@github\.com|git@[\w.-]+)$",
    re.I,
)
AI_NAMES = r"(?:claude|anthropic|copilot|cursor|gemini|chatgpt|openai|codex|antigravity|devin|windsurf|aider|opencode)"

CHECKS: dict[str, tuple[re.Pattern, re.Pattern | None]] = {
    "a local home path": (
        re.compile(
            r"/home/(?!(?:prufgate|runner)(?![\w.-]))[A-Za-z_][\w.-]*"
            r"|/Users/(?!Shared(?![\w.-]))[A-Za-z][\w.-]*|\b[A-Za-z]:\\{1,2}Users\\{1,2}[\w.-]+"
        ),
        None,
    ),
    "an email address": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"), ALLOWED_EMAIL),
    "an IPv4 address": (re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d|\.\d)"), ALLOWED_IPV4),
    "a private key": (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), None),
    "a credential-shaped token": (
        re.compile(
            r"\bAKIA[0-9A-Z]{16}\b|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_\w{30,}"
            r"|\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|\beyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,}|\bxox[abprs]-[\w-]{10,}"
            r"|\bASIA[0-9A-Z]{16}\b|\b[sr]k_live_[A-Za-z0-9]{16,}|\bAIza[0-9A-Za-z_-]{35}|\bglpat-[\w-]{20,}"
            r"|\bhf_[A-Za-z0-9]{30,}|\bnpm_[A-Za-z0-9]{36}|hooks\.slack\.com/services/T\w+/"
        ),
        None,
    ),
    "a private access-gateway domain": (re.compile(r"[a-z0-9-]+\.cloudflareaccess\.com"), None),
    "an AI attribution trailer": (
        re.compile(
            rf"(?im)^\W*(?:co-authored-by|assisted-by):[^\n]*{AI_NAMES}|generated (?:with|by|using) \[?{AI_NAMES}"
            rf"|claude\.ai/code/session|\U0001F916"
        ),
        None,
    ),
}


def _split_top(s: str) -> list[str]:
    """Split a regex at top-level | , or newlines, honouring escapes and groups."""
    out, depth, start, i = [], 0, 0, 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c in "|,\n":
            out.append(s[start:i])
            start = i + 1
        i += 1
    out.append(s[start:])
    return [p.strip() for p in out if p.strip()]


def private_terms() -> list[re.Pattern]:
    raw = os.environ.get("PRUFGATE_PRIVATE_TERMS", "")
    path = os.environ.get("PRUFGATE_PRIVATE_TERMS_FILE", "")
    if path:
        # A path that is set but missing is a mistake, not a reason to skip.
        raw += "\n" + Path(path).read_text(encoding="utf-8")
    pats = []
    for alt in _split_top(raw):
        rx = re.compile(alt, re.I)
        if not any(rx.fullmatch(name) for name in ALLOWED_NAMES):
            pats.append(rx)
    return pats


def _allowed_spans(line: str) -> list[tuple[int, int]]:
    low, spans = line.lower(), []
    for name in ALLOWED_NAMES:
        name, i = name.lower(), 0
        while (j := low.find(name, i)) >= 0:
            spans.append((j, j + len(name)))
            i = j + 1
    return spans


def findings(text: str, terms: list[re.Pattern] | None = None) -> list[tuple[int, str]]:
    """(line number, kind of check) for each line with private data. Never the text."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        # Escapes inside code strings ("...\\n@pytest.fixture") are not text.
        line = re.sub(r"\\[nrt]", " ", line)
        for what, (rx, allow) in CHECKS.items():
            if any(not (allow and allow.search(m.group(0))) for m in rx.finditer(line)):
                out.append((n, what))
        if terms:
            spans = _allowed_spans(line)
            if any(not any(a <= m.start() and m.end() <= b for a, b in spans) for rx in terms for m in rx.finditer(line)):
                out.append((n, "a private term"))
    return out


def tracked_files() -> list[str]:
    if not (ROOT / ".git").exists():
        raise unittest.SkipTest("not a git checkout: tracked files cannot be listed")
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [f for f in out.split("\0") if f]


def scan_tree(terms: list[re.Pattern] | None = None) -> list[str]:
    hits = []
    for rel in tracked_files():
        hits += [f"{rel}: file name: {what}" for _, what in findings(rel, terms)]
        try:
            text = (ROOT / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binary files (images)
        hits += [f"{rel}:{n}: {what}" for n, what in findings(text, terms)]
    return hits


def commit_range() -> str | None:
    if os.environ.get("PRUFGATE_HYGIENE_RANGE"):
        return os.environ["PRUFGATE_HYGIENE_RANGE"]
    if subprocess.run(["git", "rev-parse", "--verify", "-q", "HEAD"], cwd=ROOT, capture_output=True).returncode:
        return None  # no commits yet
    has_main = subprocess.run(["git", "rev-parse", "--verify", "-q", "origin/main"], cwd=ROOT, capture_output=True).returncode == 0
    return "origin/main..HEAD" if has_main else "HEAD"


def scan_commits(rng: str, terms: list[re.Pattern] | None = None) -> list[str]:
    log = subprocess.run(
        ["git", "log", "--format=%x00%h%n%ae%n%ce%n%B", rng], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    hits = []
    for entry in filter(None, log.split("\0")):
        sha, author, committer, body = (entry.split("\n", 3) + ["", "", ""])[:4]
        for who, addr in (("author", author), ("committer", committer)):
            if not ALLOWED_EMAIL.search(addr.strip()):
                hits.append(f"commit {sha}: {who} address is not a noreply or project address")
        hits += [f"commit {sha}: message line {n}: {what}" for n, what in findings(body, terms)]
    return hits


class PublicRepositoryHygiene(unittest.TestCase):
    def test_no_tracked_file_carries_private_data(self):
        hits = scan_tree()
        self.assertEqual(hits, [], "private data in a public repository:\n" + "\n".join(hits))

    def test_no_tracked_file_carries_project_terms(self):
        terms = private_terms()
        if not terms:
            self.skipTest("PRUFGATE_PRIVATE_TERMS(_FILE) is not set: project-specific terms were not checked")
        hits = scan_tree(terms)
        self.assertEqual(hits, [], "private project terms in a public repository:\n" + "\n".join(hits))

    def test_new_commits_are_clean(self):
        rng = commit_range()
        if rng is None:
            self.skipTest("no commits to check")
        hits = scan_commits(rng, private_terms())
        self.assertEqual(hits, [], "private data in commit metadata:\n" + "\n".join(hits))

    def test_every_check_still_catches(self):
        # Samples are assembled at run time so this file is not itself a finding.
        j = "".join
        catches = {
            "a local home path": [j(["/ho", "me/someone/src"]), j(["/ho", "me/Alice/x"]), j(["/ho", "me/prufgate-", "dev/x"]), j(["/Us", "ers/someone/src"]), j(["C:", "\\Users\\someone"])],
            "an email address": [j(["someone", "@", "mail-provider.org"]), j(["x\\tbob", "@", "corp-mail.org"])],
            "an IPv4 address": [j(["10", ".20.30", ".40"]), j(["192", ".168.1.20"]), j(["server at 10", ".1.2.3."])],
            "a private key": [j(["-----BEGIN ", "RSA PRIVATE", " KEY-----"])],
            "a credential-shaped token": [j(["AKIA", "ABCDEFGHIJKLMNOP"]), j(["ghp", "_", "a" * 36]), j(["sk-", "ant-", "b" * 24]),
                                          j(["eyJ", "e" * 12, ".", "f" * 12, ".", "g" * 12]),
                                          j(["ASIA", "ABCDEFGHIJKLMNOP"]), j(["sk_", "live_", "c" * 24]), j(["AIza", "d" * 35]),
                                          j(["glpat-", "e" * 20]), j(["hf_", "f" * 34]), j(["npm_", "g" * 36]),
                                          j(["https://hooks.", "slack.com/services/", "T000/B000/xyz"])],
            "a private access-gateway domain": [j(["team", ".cloudflareaccess", ".com"])],
            "an AI attribution trailer": [j(["Co-Authored-", "By: Claude <x@example.com>"]), j(["Generated ", "with [Claude Code]"]), chr(0x1F916) + " made this",
                                          j(["Assisted-", "by: Copilot"]), j(["https://claude", ".ai/code/session", "_abc"])],
        }
        for what, samples in catches.items():
            for sample in samples:
                self.assertIn(what, [w for _, w in findings(sample)], f"missed {what}")
        clean = [
            "a documentation address 192.0.2.10, 127.0.0.1, 0.0.0.0 and the metadata host 169.254.169.254",
            "write to alice@example.com, bob@corp.example or security@guardianvigil.io",
            "the container home /home/prufgate/.cache and the runner /home/runner/work",
            "Co-authored-by: A Person <123+a@users.noreply.github.com>",
            "Signed-off-by: dependabot[bot] <support@github.com>",
            "published by GuardianVigil",
            "clone git@github.com:org/repo.git with netmask 255.255.255.0 into /Users/Shared/tmp",
            "src = \"import pytest\\n\\n@pytest.fixture\\ndef test_user(): ...\"",
        ]
        for text in clean:
            self.assertEqual(findings(text), [], f"false positive on {text!r}")

    def test_private_terms_are_read_from_outside_and_allowed_names_pass(self):
        old = dict(os.environ)
        try:
            os.environ.pop("PRUFGATE_PRIVATE_TERMS_FILE", None)
            os.environ["PRUFGATE_PRIVATE_TERMS"] = "secret-(alpha|beta),GuardianVigil"
            terms = private_terms()
            self.assertEqual(len(terms), 1, "an allowed name must not become a term")
            self.assertEqual(findings("ships secret-beta", terms), [(1, "a private term")])
            self.assertEqual(findings("by GuardianVigil", terms), [])
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_gitignore_protects_local_agent_and_ide_configs(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for required_pattern in (".claude/", ".cursor/", ".agents/", "*.local.json", "*.mdc"):
            self.assertIn(required_pattern, gitignore, f"Missing '{required_pattern}' in .gitignore")
        for rel in tracked_files():
            self.assertFalse(rel.startswith((".claude/", ".cursor/", ".agents/")), f"Tracked IDE/agent file: {rel}")
            self.assertFalse(rel.endswith((".local.json", ".mdc")), f"Tracked local config file: {rel}")

    def test_core_detector_excludes_domain_cti_rules_by_default(self):
        from prufgate.anti_fabrication import detector

        detector.apply_settings({})
        try:
            self.assertEqual(detector.ACTIVE_PACKS, set())
            cti_sample = '  "jarm": "' + "0" * 62 + '",\n'
            self.assertEqual(detector.raw_findings("data/c2.json", ".json", cti_sample), [])
            detector.apply_settings({"packs": ["cti"]})
            hits = detector.raw_findings("data/c2.json", ".json", cti_sample)
            self.assertEqual([h.rule for h in hits], ["zero-jarm-as-fingerprint"])
        finally:
            detector.apply_settings({})


if __name__ == "__main__":
    unittest.main()
