"""Registry check for dependencies added in a diff (slopsquatting), opt-in.

A coding agent can add a package name that does not exist, or a near miss of a
popular one, to a manifest. The import check passes because the import is now
"declared". This check compares the manifests at the base with the working tree
and looks up every newly added name on its public registry:

- `dependency-not-on-registry` (P0): the registry has no such package.
- `dependency-recently-published` (P1): its first release is younger than
  `max_age_days` (npm, PyPI and crates.io; the Go proxy gives no cheap date).
- `dependency-typosquat` (P1): the name is one or two edits (a swap counts as one)
  from a popular package, or differs only in `-`, `_` or `.`.

Off by default: it needs the network. Lookups go to fixed HTTPS hosts with no
credentials, a short timeout and a bounded count per run. A lookup that fails
stops the run (exit 2) unless `offline_ok` is set. Results are cached for a day
in `$XDG_CACHE_HOME/prufgate/registry.json` (default `~/.cache`), never inside the
scanned repository.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from prufgate.contract_guard.dependency_guard import (
    GO_REQUIRE_RE,
    NODE_DEP_SECTIONS,
    Finding,
    _normalize_pypi_name,
    _pyproject_dependency_names,
    cargo_dependencies,
    find_manifest_files,
)
from prufgate.process import git_command
from prufgate.safe_fs import safe_read_text

USER_AGENT = "prufgate-registry-check (+https://github.com/GuardianVigil-Labs/Prufgate)"
TIMEOUT_SECONDS = 10
MAX_BODY_BYTES = 16 * 1024 * 1024
CACHE_TTL_SECONDS = 24 * 3600
RULES = ("dependency-not-on-registry", "dependency-recently-published", "dependency-typosquat")

# Fetcher: (url, headers) -> (HTTP status, body or None when larger than MAX_BODY_BYTES).
# Raises OSError (urllib.error.URLError is one) when the registry cannot be reached.
Fetcher = Callable[[str, Dict[str, str]], Tuple[int, Optional[bytes]]]

# Popular names a typosquat imitates. Hand-picked from the top of each registry's
# public download rankings (npm, PyPI via the top-pypi-packages list, crates.io
# sorted by downloads) and widely used Go modules, as of 2026-10. Kept short on
# purpose: refresh by hand from the same rankings; a name on this list is never
# itself flagged.
POPULAR: dict[str, tuple[str, ...]] = {
    "npm": (
        "react", "react-dom", "next", "vue", "express", "lodash", "axios", "chalk", "commander",
        "debug", "dotenv", "eslint", "prettier", "typescript", "webpack", "vite", "jest", "vitest",
        "moment", "dayjs", "uuid", "zod", "yargs", "semver", "glob", "rimraf", "mkdirp", "minimist",
        "classnames", "tslib", "rxjs", "jquery", "underscore", "async", "request", "body-parser",
        "cors", "jsonwebtoken", "bcrypt", "mongoose", "redis", "socket.io", "nodemon", "inquirer",
        "preact", "svelte", "tailwindcss", "postcss", "babel-core", "ws", "colors", "cross-env",
    ),
    "pypi": (
        "requests", "urllib3", "numpy", "pandas", "boto3", "botocore", "setuptools", "certifi",
        "idna", "charset-normalizer", "six", "python-dateutil", "pyyaml", "typing-extensions",
        "cryptography", "packaging", "pip", "wheel", "attrs", "click", "jinja2", "markupsafe",
        "pydantic", "fastapi", "flask", "django", "sqlalchemy", "pytest", "scipy", "matplotlib",
        "pillow", "beautifulsoup4", "lxml", "protobuf", "grpcio", "aiohttp", "httpx", "openai",
        "anthropic", "tensorflow", "torch", "scikit-learn", "selenium", "colorama", "tqdm", "rich",
    ),
    "crates": (
        "serde", "serde_json", "serde_derive", "tokio", "rand", "syn", "quote", "proc-macro2",
        "libc", "clap", "regex", "log", "anyhow", "thiserror", "lazy_static", "once_cell", "futures",
        "bytes", "hyper", "reqwest", "chrono", "itertools", "bitflags", "cfg-if", "base64", "uuid",
        "tracing", "env_logger", "rayon", "memchr", "hashbrown", "parking_lot", "smallvec", "axum",
    ),
    "go": (
        "github.com/stretchr/testify", "github.com/google/uuid", "github.com/spf13/cobra",
        "github.com/spf13/viper", "github.com/gin-gonic/gin", "github.com/sirupsen/logrus",
        "github.com/pkg/errors", "github.com/gorilla/mux", "github.com/go-chi/chi",
        "github.com/labstack/echo", "github.com/golang-jwt/jwt", "github.com/jackc/pgx",
        "github.com/lib/pq", "github.com/redis/go-redis", "github.com/prometheus/client_golang",
        "go.uber.org/zap", "golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sync",
        "google.golang.org/grpc", "google.golang.org/protobuf", "gopkg.in/yaml.v3",
    ),
}

_VALID_NAME = {
    "npm": re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9._~-][a-z0-9._~-]*$", re.IGNORECASE),
    "pypi": re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$", re.IGNORECASE),
    "crates": re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$"),
    "go": re.compile(r"^[A-Za-z0-9.-]+(?:/[A-Za-z0-9._~-]+)+$"),
}
_REGISTRY_LABEL = {"npm": "npm", "pypi": "PyPI", "crates": "crates.io", "go": "the Go module proxy"}


class RegistryError(RuntimeError):
    """A registry lookup failed, so the check could not run."""


def canonical(ecosystem: str, name: str) -> str:
    """The form two names of one package share on its registry."""
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem == "crates":
        return name.replace("_", "-").lower()
    return name.lower()


def registry_url(ecosystem: str, name: str) -> str:
    """The HTTPS URL that answers whether `name` exists (and when it was first published)."""
    if ecosystem == "npm":
        return "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    if ecosystem == "pypi":
        # The Simple JSON index (PEP 691/700): the JSON API's `releases` key is deprecated.
        return f"https://pypi.org/simple/{canonical('pypi', name)}/"
    if ecosystem == "crates":
        return "https://crates.io/api/v1/crates/" + urllib.parse.quote(name, safe="")
    if ecosystem == "go":
        # Module path escaping: each upper-case letter becomes `!` and its lower case.
        escaped = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)
        return f"https://proxy.golang.org/{urllib.parse.quote(escaped, safe='/!~')}/@v/list"
    raise ValueError(f"unknown ecosystem: {ecosystem}")


def _headers(ecosystem: str) -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT}
    if ecosystem == "pypi":
        headers["Accept"] = "application/vnd.pypi.simple.v1+json"
    return headers


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        if not newurl.startswith("https://"):
            raise urllib.error.URLError(f"refused a redirect away from HTTPS: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects())
_last_crates_call = [0.0]


def default_fetch(url: str, headers: dict[str, str]) -> tuple[int, bytes | None]:
    """GET `url` over HTTPS with no credentials and a short timeout."""
    if not url.startswith("https://"):
        raise ValueError(f"registry lookups are HTTPS only: {url}")
    if url.startswith("https://crates.io/"):  # crates.io asks crawlers for at most one request a second
        time.sleep(max(0.0, 1.0 - (time.monotonic() - _last_crates_call[0])))
        _last_crates_call[0] = time.monotonic()
    try:
        with _OPENER.open(urllib.request.Request(url, headers=headers), timeout=TIMEOUT_SECONDS) as resp:
            body = resp.read(MAX_BODY_BYTES + 1)
            return resp.status, (None if len(body) > MAX_BODY_BYTES else body)
    except urllib.error.HTTPError as e:
        return e.code, b""


def _epoch(stamp: object) -> float | None:
    if not isinstance(stamp, str) or not stamp:
        return None
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except ValueError:
        return None


def lookup(ecosystem: str, name: str, fetch: Fetcher) -> dict[str, object]:
    """{"exists": bool, "created": epoch seconds or None}. Raises RegistryError when unsure."""
    url = registry_url(ecosystem, name)
    try:
        status, body = fetch(url, _headers(ecosystem))
    except (OSError, ValueError) as e:
        raise RegistryError(f"{_REGISTRY_LABEL[ecosystem]} lookup of {name!r} failed: {e}") from e
    if status == 404 or (ecosystem == "go" and status == 410):
        return {"exists": False, "created": None}
    if status != 200:
        raise RegistryError(f"{_REGISTRY_LABEL[ecosystem]} lookup of {name!r} answered HTTP {status}")
    if ecosystem == "go":
        return {"exists": True, "created": None}
    if body is None:
        # ponytail: only long-lived packages have documents this large; treat as established.
        return {"exists": True, "created": None}
    try:
        data = json.loads(body)
    except ValueError as e:
        raise RegistryError(f"{_REGISTRY_LABEL[ecosystem]} sent an unreadable answer for {name!r}") from e
    if not isinstance(data, dict):
        raise RegistryError(f"{_REGISTRY_LABEL[ecosystem]} sent an unexpected answer for {name!r}")
    if ecosystem == "npm":
        times = data.get("time") if isinstance(data.get("time"), dict) else {}
        # An unpublished package keeps its document but has no versions to install.
        return {"exists": bool(data.get("versions")), "created": _epoch(times.get("created"))}
    if ecosystem == "pypi":
        files = data.get("files") if isinstance(data.get("files"), list) else []
        stamps = [t for t in (_epoch(f.get("upload-time")) for f in files if isinstance(f, dict)) if t is not None]
        return {"exists": bool(files), "created": min(stamps) if stamps else None}
    crate = data.get("crate") if isinstance(data.get("crate"), dict) else {}
    return {"exists": True, "created": _epoch(crate.get("created_at"))}


def _osa_distance(a: str, b: str, limit: int) -> int:
    """Edit distance where swapping two neighbouring letters counts as one edit."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[len(b)]


def typosquat_of(ecosystem: str, name: str) -> str | None:
    """The popular package `name` imitates, or None."""
    mine = canonical(ecosystem, name)
    popular = {canonical(ecosystem, p): p for p in POPULAR.get(ecosystem, ())}
    if mine in popular:
        return None
    squashed = re.sub(r"[-_.]", "", mine)
    for canon, original in popular.items():
        if squashed == re.sub(r"[-_.]", "", canon):
            return original
    if len(mine) < 4:
        return None  # ponytail: short names sit within two edits of too many others
    limit = 1 if len(mine) < 8 else 2
    for canon, original in popular.items():
        if _osa_distance(mine, canon, limit) <= limit:
            return original
    return None


def _manifest_names(kind: str, text: str) -> list[tuple[str, str]]:
    """(ecosystem, registry name) of every registry dependency a manifest declares."""
    out: list[tuple[str, str]] = []
    if kind == "package.json":
        try:
            data = json.loads(text or "{}")
        except ValueError:
            return out
        for section in NODE_DEP_SECTIONS if isinstance(data, dict) else ():
            deps = data.get(section)
            for name, spec in (deps.items() if isinstance(deps, dict) else ()):
                spec = spec if isinstance(spec, str) else ""
                if spec.startswith("npm:"):  # an alias installs the package it names
                    real = spec[4:]
                    at = real.rfind("@")
                    out.append(("npm", real[:at] if at > 0 else real))
                elif ":" not in spec and "/" not in spec:  # not file:, git, workspace: or user/repo
                    out.append(("npm", name))
    elif kind in ("pyproject.toml", "req"):
        lines = _pyproject_dependency_names(text) if kind == "pyproject.toml" else text.splitlines()
        for line in lines:
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-") or "://" in line or "@" in line:
                continue  # options, URLs and direct references are not registry names
            norm = _normalize_pypi_name(line)
            if norm:
                out.append(("pypi", canonical("pypi", norm)))
    elif kind == "go.mod":
        own = set(re.findall(r"^\s*module\s+(\S+)", text, re.MULTILINE))
        out += [("go", m.group(1)) for m in GO_REQUIRE_RE.finditer(text) if m.group(1) not in own]
    elif kind == "Cargo.toml":
        for key, val in cargo_dependencies(text)[1].items():
            if re.search(r"\b(?:path|git)\s*=|\bworkspace\s*=\s*true", val):
                continue
            m_pkg = re.search(r"""\bpackage\s*=\s*["']([^"']+)["']""", val)
            out.append(("crates", m_pkg.group(1) if m_pkg else key))
    return out


def _git(workspace: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(git_command(*args), cwd=workspace, capture_output=True, text=True, timeout=30, check=False)


def added_dependencies(workspace: Path, base: str | None) -> list[tuple[str, str, str, str]]:
    """(ecosystem, name, manifest path, manifest text) for each name declared now but not at `base`.

    Without a base, the working tree is compared with HEAD.
    """
    ref = base or "HEAD"
    if ref.startswith("-"):
        raise RegistryError(f"invalid base ref: {ref!r}")
    commit = _git(workspace, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}")
    if commit.returncode != 0:
        raise RegistryError(f"registry_check needs a git repository with a usable base ref (got {ref!r})")
    base_commit = commit.stdout.strip()
    if base:
        merge_base = _git(workspace, "merge-base", base_commit, "HEAD")
        if merge_base.returncode == 0 and merge_base.stdout.strip():
            base_commit = merge_base.stdout.strip()
    base_names: set[tuple[str, str]] = set()
    head_entries: list[tuple[str, str, str, str]] = []
    for kind, paths in find_manifest_files(workspace).items():
        for path in paths:
            rel = path.relative_to(workspace).as_posix()
            head_text = safe_read_text(path, encoding="utf-8", errors="ignore")
            shown = _git(workspace, "show", f"{base_commit}:{rel}")
            base_text = shown.stdout if shown.returncode == 0 else ""
            base_names |= {(e, canonical(e, n)) for e, n in _manifest_names(kind, base_text)}
            head_entries += [(e, n, rel, head_text) for e, n in _manifest_names(kind, head_text)]
    out: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for eco, name, rel, text in head_entries:
        # Once per manifest: the caller drops excluded manifests, and that must
        # not drop the same name added in a manifest it keeps.
        key = (eco, canonical(eco, name))
        if key not in base_names and (*key, rel) not in seen:
            seen.add((*key, rel))
            out.append((eco, name, rel, text))
    return out


def cache_path() -> Path:
    root = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(root) / "prufgate" / "registry.json"


def _load_cache(path: Path) -> dict[str, dict[str, object]]:
    try:
        data = json.loads(safe_read_text(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_cache(path: Path, cache: dict[str, dict[str, object]], workspace: Path) -> None:
    try:
        if path.resolve().is_relative_to(workspace.resolve()):
            return  # never write into the repository under review
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass  # the cache only saves lookups; a read-only home must not fail the run


def _line_of(text: str, name: str) -> int:
    pattern = re.compile(r"[-_.]".join(re.escape(p) for p in re.split(r"[-_.]", name)), re.IGNORECASE)
    for ln, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return ln
    return 1


def check_new_dependencies(
    workspace: Path,
    base: str | None,
    *,
    max_age_days: int = 30,
    max_lookups: int = 50,
    offline_ok: bool = False,
    fetch: Fetcher | None = None,
    cache_file: Path | None = None,
    now: float | None = None,
) -> list[Finding]:
    """Registry findings for dependencies added since `base`. Raises RegistryError (exit 2)
    when a lookup fails, unless `offline_ok`."""
    fetch = fetch or default_fetch
    now = time.time() if now is None else now
    cache_file = cache_file or cache_path()
    cache = _load_cache(cache_file)
    lookups = 0
    skipped: list[str] = []
    findings: list[Finding] = []
    for eco, name, rel, text in added_dependencies(workspace, base):
        line = _line_of(text, name)
        where = _REGISTRY_LABEL[eco]
        if not _VALID_NAME[eco].match(name):
            findings.append(_finding(rel, line, "dependency-not-on-registry", "P0", name,
                                     f"'{name}' in {rel} is not a valid {where} package name."))
            continue
        key = f"{eco}:{canonical(eco, name)}"
        entry = cache.get(key)
        if not (isinstance(entry, dict) and isinstance(entry.get("at"), (int, float))
                and 0 <= now - float(entry["at"]) < CACHE_TTL_SECONDS):  # a future time is not fresh
            try:
                if lookups >= max_lookups:
                    raise RegistryError(
                        f"more than {max_lookups} new dependencies need a registry lookup; "
                        "raise registry_check.max_lookups"
                    )
                lookups += 1
                entry = {**lookup(eco, name, fetch), "at": now}
            except RegistryError as e:
                if not offline_ok:
                    raise
                skipped.append(f"{name} ({e})")
                continue
            cache[key] = entry
        if not entry.get("exists"):
            findings.append(_finding(rel, line, "dependency-not-on-registry", "P0", name,
                                     f"New dependency '{name}' in {rel} does not exist on {where}: "
                                     "a hallucinated name an attacker can register (slopsquatting)."))
            continue
        created = entry.get("created")
        if isinstance(created, (int, float)) and now - created < max_age_days * 86400:
            days = int((now - created) // 86400)
            findings.append(_finding(rel, line, "dependency-recently-published", "P1", name,
                                     f"New dependency '{name}' in {rel} was first published on {where} "
                                     f"{days} day(s) ago (under {max_age_days}); check it is the package you meant."))
        target = typosquat_of(eco, name)
        if target:
            findings.append(_finding(rel, line, "dependency-typosquat", "P1", name,
                                     f"New dependency '{name}' in {rel} is a near miss of the popular "
                                     f"package '{target}'; check it is not a typosquat."))
    if lookups:
        _save_cache(cache_file, cache, workspace)
    if skipped:
        print(f"registry_check: offline_ok, not checked: {'; '.join(skipped)}", file=sys.stderr)
    return findings


def _finding(path: str, line: int, rule: str, severity: str, name: str, message: str) -> Finding:
    return Finding(path=path, line=line, rule=rule, severity=severity, text=name, message=message)
