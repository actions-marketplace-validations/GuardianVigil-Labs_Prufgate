"""Universal YAML/JSON Configuration Loader for PrufGate.

Supports `.prufgate/config.yaml`, `.prufgate/config.yml`, `.prufgate.yaml`, `.prufgate.yml`,
and legacy `.prufgate/fabrication.json` / `.prufgate/debt-ceiling.json` files.

With a base ref the configuration is read from that ref (`git show`), never from
the working tree: a change cannot switch off the checks that review it. Its
configuration edits take effect once it is merged.
"""

from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import subprocess
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

DEFAULT_CONFIG_FILES = (
    ".prufgate/config.yaml",
    ".prufgate/config.yml",
    ".prufgate.yaml",
    ".prufgate.yml",
    ".prufgate/fabrication.json",
    ".prufgate/debt-ceiling.json",
)

VALID_PACKS = {"core", "web-ui", "ai-safety", "cti"}
DEFAULT_PACKS = ("core", "web-ui", "ai-safety")

SUPPORTED_LANGUAGES = {
    "typescript",
    "javascript",
    "python",
    "go",
    "rust",
    "java",
    "kotlin",
    "php",
    "ruby",
    "csharp",
}

CONFIG_KEYS = {
    "version",
    "packs",
    "languages",
    "exclude",
    "allowed_paths",
    "auth_guards",
    "tenant_keys",
    "score_owners",
    "exempt",
    "known_debt",
    "model_call_patterns",
    "evidence_markers",
    "registry_check",
    "ghost_symbols",
    "enable_low_confidence",
    "bola",
    "ai_adjudicate",
}
BOLA_KEYS = {"global_tables"}
REGISTRY_CHECK_KEYS = {"offline_ok", "max_age_days", "max_lookups"}
GHOST_SYMBOLS_KEYS = {"third_party"}
# `ai_adjudicate` integer settings: (default, minimum, maximum).
AI_ADJUDICATE_LIMITS = {
    "max_findings": (20, 0, 500),
    "timeout": (30, 1, 300),
    "context_lines": (8, 0, 50),
    "max_window_bytes": (2000, 200, 16000),
}
AI_ADJUDICATE_LEVELS = ("low", "medium")  # high-confidence findings are never sent

DEBT_REF_RE = re.compile(r"^#\d+:\s*\S")

# Bidirectional rule alias groups so legacy and current rule IDs work interchangeably
RULE_ALIAS_GROUPS: tuple[frozenset[str], ...] = (
    frozenset({"documentation-address", "documentation-ip-or-domain"}),
    frozenset({"demo-named-data", "fake-named-data", "fake-named-production-data"}),
    frozenset({"always-current-fake", "invented-event-timestamp", "always-current-fake-timestamp"}),
    frozenset({"prompt-invents-finding", "unseeded-llm-judgment-prompt"}),
    frozenset({"stub-click-handler", "stub-event-handler", "disconnected-form-submit", "disconnected-ui-handler"}),
    frozenset({"route-canned-fallback", "unhandled-empty-catch", "canned-error-fallback"}),
    frozenset({"zero-assertion-test", "assertion-free-test"}),
    frozenset({"self-mocked-unit-under-test", "over-mocked-sut"}),
    frozenset({"diff-assertion-weakening", "weakened-or-deleted-assertion-in-diff"}),
    frozenset({"test-skip-smuggling", "test-skip-or-focus-leak"}),
    frozenset({"suppression-comment-smuggling", "linter-or-type-suppression-abuse"}),
    frozenset({"undeclared-or-hallucinated-import", "ghost-dependency", "slopsquatting-import"}),
    frozenset({"undocumented-env-var-drift", "env-var-drift"}),
    frozenset({"frontend-backend-route-mismatch", "api-route-contract-mismatch"}),
    frozenset({"static-bola-unscoped-access", "BOLA-UNSCOPED-OBJECT-ACCESS"}),
    frozenset({"live-bola-differential-probe", "BOLA-CROSS-TENANT-ACCESS", "BOLA-UNAUTHENTICATED-ACCESS"}),
)


def expand_rule_aliases(rule: str) -> set[str]:
    """Return all equivalent aliases for a given rule ID (including itself)."""
    norm = rule.strip()
    out = {norm}
    for group in RULE_ALIAS_GROUPS:
        if norm in group:
            out |= group
    return out


def rules_match(rule_a: str, rule_b: str) -> bool:
    """Return True if rule_a and rule_b are identical or aliases of the same rule."""
    if rule_a == rule_b:
        return True
    return rule_b in expand_rule_aliases(rule_a)


def path_matches_pattern(rel: str, pattern: str) -> bool:
    """Return True if `rel` is the file `pattern` names, lies under the directory
    it names, or matches it as a glob. Never a bare substring: `a.py` must not
    match `data.py`, nor `test` match `src/latest.py`."""
    norm_rel = rel.replace("\\", "/").removeprefix("./")
    norm_pat = pattern.replace("\\", "/").removeprefix("./")
    if not norm_pat:
        return False
    if norm_rel == norm_pat.rstrip("/") or norm_rel.startswith(norm_pat.rstrip("/") + "/"):
        return True
    if any(ch in norm_pat for ch in "*?["):
        if fnmatch.fnmatch(norm_rel, norm_pat):
            return True
        if norm_pat.startswith("**/") and fnmatch.fnmatch(norm_rel, norm_pat[3:]):
            return True
        if norm_pat.endswith("/**") and norm_rel.startswith(norm_pat[:-2]):
            return True
    return False


class ConfigError(ValueError):
    """Raised when a PrufGate configuration file is missing, malformed, or invalid."""


class BaseConfigInvalid(ConfigError):
    """The configuration at the base ref was read but this version rejects it."""


class BaseConfigNotAFile(BaseConfigInvalid):
    """A configuration path at the base ref is a directory or a submodule, not a file."""


class GitDiffError(RuntimeError):
    """git could not produce the diff: not a repository, an unknown ref, or a refused argument."""


class NotAFileError(GitDiffError):
    """The path exists at the commit but is a directory or a submodule, not a file."""


# Regular files, executables and symbolic links: the only entries git_blob reads.
BLOB_MODES = ("100644", "100755", "120000")


EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _git(args: list[str], cwd: Path | str | None) -> str:
    try:
        res = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as e:
        raise GitDiffError(f"cannot run git: {e}") from e
    if res.returncode != 0:
        lines = [ln.strip() for ln in res.stderr.strip().splitlines() if ln.strip()]
        reason = next((ln for ln in lines if ln.startswith(("fatal:", "error:"))), lines[0] if lines else "")
        raise GitDiffError(reason or f"git {args[0]} failed")
    return res.stdout


def _diff_base(base_ref: str | None, cwd: Path | str | None) -> str:
    """The commit the working tree is compared with: the merge base with
    `base_ref` (committed and uncommitted PR changes alike), else HEAD, else the
    empty tree in a repository with no commits yet."""
    if base_ref is not None:
        if not base_ref or base_ref.startswith("-"):
            raise GitDiffError(f"refusing base ref {base_ref!r}")
        candidates = [base_ref] if base_ref.startswith("origin/") else [base_ref, f"origin/{base_ref}"]
        for ref in candidates:
            try:
                return _git(["merge-base", ref, "HEAD"], cwd).strip()
            except GitDiffError:
                continue
        raise GitDiffError(f"unknown base ref {base_ref!r}")
    _git(["rev-parse", "--is-inside-work-tree"], cwd)
    try:
        return _git(["rev-parse", "--verify", "--quiet", "HEAD"], cwd).strip()
    except GitDiffError:
        return EMPTY_TREE


def git_blob(commit: str, rel: str, root: Path, depth: int = 0) -> str | None:
    """The text of `rel` (repository-relative) at `commit`, following an
    in-repository symbolic link a few levels; None when it is not there.
    Only files and links are read: a directory or a submodule raises
    NotAFileError (`git show` of a tree prints its listing, never a file).
    Raises GitDiffError when git cannot read `commit` at all."""
    entry = _git(["ls-tree", "-z", "--full-tree", commit, "--", rel], root).split("\0")[0]
    if not entry:
        return None
    mode = entry.split(" ", 1)[0]
    if mode not in BLOB_MODES:
        raise NotAFileError(f"{rel} is not a file at {commit[:12]}")
    blob = _git(["show", f"{commit}:{rel}"], root)
    if mode != "120000":
        return blob
    target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), blob.strip()))
    if depth >= 5 or target.startswith("../") or target == ".." or posixpath.isabs(target):
        return None
    return git_blob(commit, target, root, depth + 1)


def repo_prefix(root: Path) -> str:
    """`root` relative to the repository top level ("" at the top), as git paths use it."""
    try:
        return _git(["rev-parse", "--show-prefix"], root).strip()
    except GitDiffError:
        return ""


def _parse_str_list(raw: Any, key: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) and x.strip() for x in raw):
        raise ConfigError(f"{key} must be a list of non-empty strings")
    return [x.strip() for x in raw]


def _parse_registry_check(raw: Any) -> tuple[bool, bool, int, int]:
    """`registry_check`: true/false, or a mapping of settings (which turns it on).
    Returns (enabled, offline_ok, max_age_days, max_lookups)."""
    if raw is None or isinstance(raw, bool):
        return bool(raw), False, 30, 50
    if not isinstance(raw, dict):
        raise ConfigError("registry_check must be true, false or a mapping")
    unknown = set(raw) - REGISTRY_CHECK_KEYS
    if unknown:
        raise ConfigError(f"registry_check: unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    offline_ok = raw.get("offline_ok", False)
    if not isinstance(offline_ok, bool):
        raise ConfigError("registry_check.offline_ok must be true or false")
    numbers = []
    for key, default in (("max_age_days", 30), ("max_lookups", 50)):
        value = raw.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ConfigError(f"registry_check.{key} must be a non-negative integer")
        numbers.append(value)
    return True, offline_ok, numbers[0], numbers[1]


def _parse_ghost_symbols(raw: Any) -> bool:
    """`ghost_symbols: {third_party: true}`: also check names imported from installed packages."""
    if raw is None:
        return False
    if not isinstance(raw, dict):
        raise ConfigError("ghost_symbols must be a mapping")
    unknown = set(raw) - GHOST_SYMBOLS_KEYS
    if unknown:
        raise ConfigError(f"ghost_symbols: unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    third_party = raw.get("third_party", False)
    if not isinstance(third_party, bool):
        raise ConfigError("ghost_symbols.third_party must be true or false")
    return third_party


def _parse_bola(raw: Any) -> list[str]:
    """`bola`: a mapping; `global_tables` lists tables shared by every tenant (countries,
    currencies) that BOLA-TABLE-MISSING-TENANT-COLUMN must not flag."""
    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise ConfigError("bola must be a mapping")
    unknown = set(raw) - BOLA_KEYS
    if unknown:
        raise ConfigError(f"bola: unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    tables = _parse_str_list(raw.get("global_tables"), "bola.global_tables")
    for t in tables:
        if not re.fullmatch(r"[A-Za-z0-9_]+", t):
            raise ConfigError(f"bola.global_tables: {t!r} is not a table name")
    return tables
@dataclass(frozen=True)
class AiAdjudicate:
    """`ai_adjudicate`: let an AI provider dismiss PrufGate's own low-confidence findings."""

    enabled: bool = False
    confidence: tuple[str, ...] = ("low",)
    max_findings: int = AI_ADJUDICATE_LIMITS["max_findings"][0]
    timeout: int = AI_ADJUDICATE_LIMITS["timeout"][0]
    context_lines: int = AI_ADJUDICATE_LIMITS["context_lines"][0]
    max_window_bytes: int = AI_ADJUDICATE_LIMITS["max_window_bytes"][0]


def _parse_ai_adjudicate(raw: Any) -> AiAdjudicate:
    """`ai_adjudicate`: true/false, or a mapping of settings (which turns it on
    unless it says `enabled: false`)."""
    if raw is None or isinstance(raw, bool):
        return AiAdjudicate(enabled=bool(raw))
    if not isinstance(raw, dict):
        raise ConfigError("ai_adjudicate must be true, false or a mapping")
    unknown = set(raw) - {"enabled", "confidence", *AI_ADJUDICATE_LIMITS}
    if unknown:
        raise ConfigError(f"ai_adjudicate: unknown key(s): {', '.join(sorted(map(str, unknown)))}")
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError("ai_adjudicate.enabled must be true or false")
    levels = raw.get("confidence", ["low"])
    if isinstance(levels, str):
        levels = [levels]
    if not isinstance(levels, list) or not levels or any(lv not in AI_ADJUDICATE_LEVELS for lv in levels):
        raise ConfigError("ai_adjudicate.confidence must list low and/or medium (high is never sent)")
    numbers: dict[str, int] = {}
    for key, (default, lo, hi) in AI_ADJUDICATE_LIMITS.items():
        value = raw.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
            raise ConfigError(f"ai_adjudicate.{key} must be an integer from {lo} to {hi}")
        numbers[key] = value
    return AiAdjudicate(enabled=enabled, confidence=tuple(sorted(set(levels))), **numbers)


def _parse_exempt(raw: Any) -> dict[tuple[str, str], str]:
    """Parse `exempt` in any of its three forms: a list of {path, rule, reason},
    {rule: [path, ...]} or {path: {rule: reason}}."""
    if raw is None or raw == {}:
        return {}
    out: dict[tuple[str, str], str] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or not all(
                isinstance(item.get(k), str) and item.get(k).strip() for k in ("path", "rule", "reason")
            ):
                raise ConfigError("each exempt entry needs a non-empty path, rule and reason")
            out[(item["path"].strip(), item["rule"].strip())] = item["reason"].strip()
        return out
    if isinstance(raw, dict):
        for rule_key, paths_val in raw.items():
            if isinstance(paths_val, dict):
                # {path: {rule: reason}}: the file-first form, a reason per rule.
                path_key = rule_key
                if not isinstance(path_key, str) or not path_key.strip() or not paths_val:
                    raise ConfigError("exempt file entries need a path and at least one rule")
                for r, reason in paths_val.items():
                    if not isinstance(r, str) or not r.strip() or not isinstance(reason, str) or not reason.strip():
                        raise ConfigError(f"exempt[{path_key!r}] needs a non-empty reason for each rule")
                    out[(path_key.strip(), r.strip())] = reason.strip()
                continue
            if not isinstance(rule_key, str) or not rule_key.strip():
                raise ConfigError("exempt mapping keys must be non-empty rule IDs")
            if not isinstance(paths_val, list) or not paths_val:
                raise ConfigError(f"exempt[{rule_key!r}] must be a non-empty list of file paths")
            for entry in paths_val:
                if isinstance(entry, str) and entry.strip():
                    out[(entry.strip(), rule_key.strip())] = f"Exempted in config under {rule_key.strip()}"
                elif isinstance(entry, dict) and isinstance(entry.get("path"), str) and entry["path"].strip():
                    reason = str(entry.get("reason") or f"Exempted in config under {rule_key.strip()}").strip()
                    out[(entry["path"].strip(), rule_key.strip())] = reason
                else:
                    raise ConfigError(f"exempt[{rule_key!r}] entries must be non-empty path strings or {{path, reason}} mappings")
        return out
    raise ConfigError("exempt must be a list or mapping")


def _parse_known_debt(raw: Any) -> tuple[dict[tuple[str, str], str], dict[str, int]]:
    """Parse `known_debt` into per-file tracked debt entries and per-rule numeric ratchet ceilings."""
    if raw is None or raw == {}:
        return {}, {}
    entries: dict[tuple[str, str], str] = {}
    ceilings: dict[str, int] = {}
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict) or not all(
                isinstance(item.get(k), str) and item.get(k).strip() for k in ("path", "rule", "reason")
            ):
                raise ConfigError("each known_debt entry needs a non-empty path, rule and reason")
            reason = item["reason"].strip()
            key = (item["path"].strip(), item["rule"].strip())
            if not DEBT_REF_RE.match(reason):
                raise ConfigError(f"known_debt {key} must start with an issue reference ('#123: why')")
            entries[key] = reason
        return entries, ceilings
    if isinstance(raw, dict):
        for k, v in raw.items():
            if not isinstance(k, str) or not k.strip():
                raise ConfigError("known_debt keys must be non-empty strings")
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                ceilings[k.strip()] = v
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and isinstance(item.get("path"), str) and isinstance(item.get("reason"), str):
                        reason = item["reason"].strip()
                        key = (item["path"].strip(), k.strip())
                        if not DEBT_REF_RE.match(reason):
                            raise ConfigError(f"known_debt {key} must start with an issue reference ('#123: why')")
                        entries[key] = reason
                    else:
                        raise ConfigError(f"known_debt[{k!r}] list items must be {{path, reason}} mappings")
            else:
                raise ConfigError(f"known_debt[{k!r}] must be a non-negative integer ceiling or list of {{path, reason}} entries")
        return entries, ceilings
    raise ConfigError("known_debt must be a list or mapping")


@dataclass
class PrufGateConfig:
    """Normalized configuration for PrufGate."""

    version: int = 1
    packs: list[str] = field(default_factory=lambda: list(DEFAULT_PACKS))
    packs_explicit: bool = False
    languages: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    auth_guards: list[str] = field(default_factory=list)
    tenant_keys: list[str] = field(default_factory=list)
    score_owners: list[str] = field(default_factory=list)
    exempt: dict[tuple[str, str], str] = field(default_factory=dict)
    known_debt: dict[tuple[str, str], str] = field(default_factory=dict)
    known_debt_ceilings: dict[str, int] = field(default_factory=dict)
    model_call_patterns: list[str] = field(default_factory=list)
    evidence_markers: list[str] = field(default_factory=list)
    registry_check: bool = False
    registry_offline_ok: bool = False
    registry_max_age_days: int = 30
    registry_max_lookups: int = 50
    ghost_third_party: bool = False
    enable_low_confidence: bool = False
    bola_global_tables: list[str] = field(default_factory=list)
    ai_adjudicate: AiAdjudicate = field(default_factory=AiAdjudicate)
    source_path: Path | None = None

    def is_excluded(self, rel_path: str) -> bool:
        """Return True if `rel_path` matches any pattern in `exclude`."""
        return any(path_matches_pattern(rel_path, pat) for pat in self.exclude)

    def is_exempt(self, rel_path: str, rule: str) -> bool:
        """Return True if `(rel_path, rule)` is exempted or tracked as per-file known debt."""
        for (ex_path, ex_rule) in list(self.exempt.keys()) + list(self.known_debt.keys()):
            if rules_match(ex_rule, rule) and path_matches_pattern(rel_path, ex_path):
                return True
        return False

    def to_detector_settings(self) -> dict[str, Any]:
        """Convert to the dictionary structure consumed by `detector.apply_settings()`."""
        return {
            "packs": list(self.packs) if self.packs_explicit else [],
            "default_packs": list(self.packs),
            "languages": list(self.languages),
            "exempt": dict(self.exempt),
            "known_debt": dict(self.known_debt),
            "known_debt_ceilings": dict(self.known_debt_ceilings),
            "score_owners": list(self.score_owners),
            "allowed_paths": list(self.exclude),
            "auth_guards": list(self.auth_guards),
            "tenant_keys": list(self.tenant_keys),
            "model_call_patterns": list(self.model_call_patterns),
            "evidence_markers": list(self.evidence_markers),
            "enable_low_confidence": self.enable_low_confidence,
        }

    def check_debt_ratchet(self, findings: list[Any]) -> tuple[list[str], list[str]]:
        """Compare finding counts against `known_debt_ceilings`.

        Returns `(violations, ratchet_down_advisories)`:
        - `violations`: rules whose current count exceeds the configured ceiling (blocks CI).
        - `ratchet_down_advisories`: rules whose current count is lower than the ceiling
          so the developer can ratchet the ceiling down.
        """
        if not self.known_debt_ceilings:
            return [], []
        counts: dict[str, int] = {rule: 0 for rule in self.known_debt_ceilings}
        for f in findings:
            f_rule = getattr(f, "rule", None) or (f.get("rule") if isinstance(f, dict) else None)
            if not f_rule:
                continue
            for ceiling_rule in self.known_debt_ceilings:
                if rules_match(str(f_rule), ceiling_rule):
                    counts[ceiling_rule] = counts.get(ceiling_rule, 0) + 1

        violations: list[str] = []
        advisories: list[str] = []
        for rule, ceiling in sorted(self.known_debt_ceilings.items()):
            actual = counts.get(rule, 0)
            if actual > ceiling:
                violations.append(
                    f"known_debt ceiling breached for '{rule}': found {actual}, ceiling is {ceiling}"
                )
            elif actual < ceiling:
                advisories.append(
                    f"known_debt for '{rule}' improved ({actual} < {ceiling}): ratchet known_debt.{rule} down to {actual}"
                )
        return violations, advisories

    @classmethod
    def load(
        cls,
        repo_root: Path | str = ".",
        explicit_path: str | Path | None = None,
        ref: str | None = None,
    ) -> PrufGateConfig:
        """Discover, parse, and validate `.prufgate/config.yaml` (or legacy JSON fallback).

        With `ref` (the base ref a changed-files scan diffs against) the files are
        read as they are at the merge base with that ref, never from the working
        tree; the defaults apply when the base has none, and the working-tree
        file when this version rejects the base's. A ref git cannot read raises
        ConfigError, so the run fails closed."""
        root = Path(repo_root)
        if ref is not None:
            try:
                commit = _diff_base(ref, root)
            except GitDiffError as e:
                raise ConfigError(
                    f"cannot read the PrufGate configuration at base ref {ref!r}: {e} (shallow clone? fetch it first)"
                ) from e
            try:
                return cls.load_at_commit(root, explicit_path, commit)
            except BaseConfigInvalid:
                # Already merged, so not the change's doing: a PrufGate upgrade that
                # rejects an old key must not block the change that fixes it. The
                # branch's configuration applies (it must be valid); the diff guard
                # reports `prufgate-config-base-invalid`.
                return cls.load(root, explicit_path)
        if explicit_path is not None:
            p = Path(explicit_path)
            if not p.is_absolute() and not p.is_file():
                candidate = root / p
                if candidate.is_file():
                    p = candidate
            if not p.is_file():
                raise ConfigError(f"settings file not found: {explicit_path}")
        else:
            found = next((root / rel for rel in DEFAULT_CONFIG_FILES if (root / rel).is_file()), None)
            if not found:
                return cls()
            p = found

        raw = cls._read_raw_file(p)
        if not isinstance(raw, dict):
            raise ConfigError(f"{p}: expected a top-level mapping/object")
        if not all(isinstance(k, str) for k in raw):
            raise ConfigError(f"{p}: top-level keys must be strings")

        # Handle legacy debt-ceiling.json files that may contain arbitrary rule-count keys
        if p.name == "debt-ceiling.json" and not (set(raw) & CONFIG_KEYS):
            _, ceilings = _parse_known_debt(raw)
            return cls(known_debt_ceilings=ceilings, source_path=p)

        unknown = set(raw) - CONFIG_KEYS
        if unknown:
            raise ConfigError(f"{p}: unknown key(s): {', '.join(sorted(unknown))}")

        version = raw.get("version", 1)
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ConfigError(f"{p}: version must be a positive integer")

        packs_explicit = "packs" in raw and raw.get("packs") is not None
        if packs_explicit:
            packs = _parse_str_list(raw.get("packs"), "packs")
            unknown_packs = set(packs) - VALID_PACKS
            if unknown_packs:
                raise ConfigError(
                    f"{p}: unknown pack(s): {', '.join(sorted(unknown_packs))} "
                    f"(valid: {', '.join(sorted(VALID_PACKS))})"
                )
        else:
            packs = list(DEFAULT_PACKS)

        languages = [lang.lower() for lang in _parse_str_list(raw.get("languages"), "languages")]
        unknown_langs = set(languages) - SUPPORTED_LANGUAGES
        if unknown_langs:
            raise ConfigError(
                f"{p}: unsupported language(s): {', '.join(sorted(unknown_langs))} "
                f"(supported: {', '.join(sorted(SUPPORTED_LANGUAGES))})"
            )

        exclude = _parse_str_list(raw.get("exclude"), "exclude") + _parse_str_list(
            raw.get("allowed_paths"), "allowed_paths"
        )
        auth_guards = _parse_str_list(raw.get("auth_guards"), "auth_guards")
        tenant_keys = _parse_str_list(raw.get("tenant_keys"), "tenant_keys")
        score_owners = _parse_str_list(raw.get("score_owners"), "score_owners")
        model_call_patterns = _parse_str_list(raw.get("model_call_patterns"), "model_call_patterns")
        evidence_markers = _parse_str_list(raw.get("evidence_markers"), "evidence_markers")

        enable_low_confidence = raw.get("enable_low_confidence", False)
        if not isinstance(enable_low_confidence, bool):
            raise ConfigError(
                f"{p}: enable_low_confidence must be true or false, not {enable_low_confidence!r}"
            )

        ai_adjudicate = _parse_ai_adjudicate(raw.get("ai_adjudicate"))
        exempt = _parse_exempt(raw.get("exempt"))
        bola_global_tables = _parse_bola(raw.get("bola"))
        registry_check, registry_offline_ok, registry_max_age_days, registry_max_lookups = _parse_registry_check(
            raw.get("registry_check")
        )
        known_debt, known_debt_ceilings = _parse_known_debt(raw.get("known_debt"))
        ghost_third_party = _parse_ghost_symbols(raw.get("ghost_symbols"))

        for key in known_debt:
            for ex_path, ex_rule in exempt:
                if ex_path == key[0] and rules_match(ex_rule, key[1]):
                    raise ConfigError(f"{key} is both exempt and known debt; it is one or the other")

        for pattern in model_call_patterns + evidence_markers:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ConfigError(f"invalid pattern {pattern!r}: {e}") from e

        return cls(
            version=version,
            packs=packs,
            packs_explicit=packs_explicit,
            languages=languages,
            exclude=exclude,
            auth_guards=auth_guards,
            tenant_keys=tenant_keys,
            score_owners=score_owners,
            exempt=exempt,
            known_debt=known_debt,
            known_debt_ceilings=known_debt_ceilings,
            model_call_patterns=model_call_patterns,
            evidence_markers=evidence_markers,
            registry_check=registry_check,
            registry_offline_ok=registry_offline_ok,
            registry_max_age_days=registry_max_age_days,
            registry_max_lookups=registry_max_lookups,
            ghost_third_party=ghost_third_party,
            enable_low_confidence=enable_low_confidence,
            bola_global_tables=bola_global_tables,
            ai_adjudicate=ai_adjudicate,
            source_path=p,
        )

    @classmethod
    def load_at_commit(cls, repo_root: Path | str, explicit_path: str | Path | None, commit: str) -> PrufGateConfig:
        """The configuration as committed at `commit` (a commit or tree), or the
        defaults when it had none. Only file contents are read; nothing runs.
        A `--config` outside the repository is the operator's, not the
        change's, and is read from disk."""
        root = Path(repo_root)
        explicit: str | None = None
        rels = list(DEFAULT_CONFIG_FILES)
        if explicit_path is not None:
            cp = Path(explicit_path)
            rel = posixpath.normpath(Path(os.path.relpath(cp, root)).as_posix() if cp.is_absolute() else cp.as_posix())
            if rel.startswith("../") or rel == "..":
                return cls.load(root, explicit_path)
            explicit, rels = rel, [rel]
        prefix = repo_prefix(root)
        with tempfile.TemporaryDirectory() as tmp:
            found = False
            for rel in rels:
                # Paths are taken as written, never resolved on disk: a link in the
                # branch must not decide which base file is read.
                try:
                    blob = git_blob(commit, posixpath.normpath(prefix + rel), root)
                except NotAFileError as e:
                    raise BaseConfigNotAFile(str(e)) from e
                except GitDiffError as e:
                    raise ConfigError(f"cannot read {rel} at {commit[:12]}: {e}") from e
                if blob is None:
                    continue
                found = True
                dest = Path(tmp) / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(blob, encoding="utf-8")
            if not found:
                return cls()
            try:
                # Rooted in the copy: a relative --config must not resolve against
                # the working directory and read the branch's file.
                cfg = cls.load(tmp, Path(tmp) / explicit if explicit else None)
            except ConfigError as e:
                raise BaseConfigInvalid(str(e).replace(tmp + os.sep, "")) from e
        # Name the repository file in reports, not the deleted temporary copy.
        if cfg.source_path is not None:
            cfg.source_path = root / Path(cfg.source_path).relative_to(tmp)
        return cfg

    def same_settings(self, other: PrufGateConfig) -> bool:
        """True when both apply the same settings, wherever they were read from."""
        return replace(self, source_path=None) == replace(other, source_path=None)

    @staticmethod
    def _read_raw_file(p: Path) -> Any:
        try:
            content = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise ConfigError(f"{p}: cannot be read as UTF-8 text: {e}") from e
        if p.suffix.lower() in {".yaml", ".yml"}:
            if yaml is None:
                raise ConfigError(f"{p}: PyYAML is required to load YAML configuration files")
            try:
                loaded = yaml.safe_load(content)
                return {} if loaded is None else loaded
            except Exception as e:
                raise ConfigError(f"{p}: invalid YAML: {e}") from e
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigError(f"{p}: invalid JSON: {e}") from e
