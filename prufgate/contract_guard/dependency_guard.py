#!/usr/bin/env python3
"""PrufGate Ghost Dependency & Slopsquatting Guard (`undeclared-or-hallucinated-import`).

Detects imports of third-party packages in TypeScript/JavaScript, Python, Go, and Rust
that are not declared in the repository's dependency manifests (`package.json`,
`pyproject.toml`, `requirements*.txt`, `go.mod`, `Cargo.toml`), preventing AI
coding agent slopsquatting and undeclared transitive dependency breakage.
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
import sysconfig
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent.parent))

from prufgate import inline_ignore  # noqa: E402
from prufgate.config import PrufGateConfig  # noqa: E402


@dataclass
class Finding:
    """A single contract, dependency, or environment drift finding."""

    path: str
    line: int
    rule: str
    text: str
    severity: str = "P0"
    message: str = ""

    def __post_init__(self) -> None:
        self.text = self.text.strip()[:140]
        if not self.message:
            self.message = f"Contract guard violation ({self.rule}): {self.text}"

    @property
    def rule_id(self) -> str:
        return self.rule

    @property
    def file(self) -> str:
        return self.path

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.path,
            "line": self.line,
            "rule": self.rule,
            "rule_id": self.rule,
            "severity": self.severity,
            "category": "contract-guard",
            "message": self.message,
            "snippet": self.text,
        }

    def __str__(self) -> str:
        return f"{self.path}:{self.line}\n    [{self.severity}] [{self.rule}] {self.text}"


@dataclass
class WorkspaceManifests:
    """Aggregated declared dependencies across manifests in a workspace."""

    has_node_manifest: bool = False
    node_packages: set[str] = field(default_factory=set)
    has_python_manifest: bool = False
    python_modules: set[str] = field(default_factory=set)
    local_python_modules: set[str] = field(default_factory=set)
    has_go_manifest: bool = False
    go_modules: set[str] = field(default_factory=set)
    has_rust_manifest: bool = False
    rust_crates: set[str] = field(default_factory=set)


NODE_BUILTINS = {
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "test",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
}

PYPI_TO_IMPORT_MAP: dict[str, set[str]] = {
    "pyyaml": {"yaml"},
    "beautifulsoup4": {"bs4"},
    "pillow": {"pil", "PIL"},
    "scikit_learn": {"sklearn"},
    "opencv_python": {"cv2"},
    "opencv_python_headless": {"cv2"},
    "python_dotenv": {"dotenv"},
    "pyjwt": {"jwt"},
    "psycopg2_binary": {"psycopg2"},
    "attrs": {"attr", "attrs"},
    "protobuf": {"google"},
    "gitpython": {"git"},
    "pycryptodome": {"Crypto"},
    "pycryptodomex": {"Cryptodome"},
    "python_dateutil": {"dateutil"},
    "defusedxml": {"defusedxml"},
    "pymysql": {"pymysql"},
    "pymongo": {"pymongo", "bson", "gridfs"},
    "graphql_core": {"graphql"},
}

def _fallback_stdlib_names() -> set[str]:
    """Standard-library module names on Pythons without `sys.stdlib_module_names` (3.9)."""
    names = set(sys.builtin_module_names)
    for key in ("stdlib", "platstdlib"):
        root = Path(sysconfig.get_paths()[key])
        for entry in (list(root.iterdir()) if root.is_dir() else []) + (
            list((root / "lib-dynload").iterdir()) if (root / "lib-dynload").is_dir() else []
        ):
            if entry.name in ("site-packages", "dist-packages") or entry.name.startswith("."):
                continue
            stem = entry.name.split(".", 1)[0]
            if entry.is_dir() or entry.suffix in (".py", ".so", ".pyd"):
                names.add(stem)
    return names


PYTHON_STDLIB: set[str] = set(getattr(sys, "stdlib_module_names", None) or _fallback_stdlib_names()) | {
    "__future__",
    "typing_extensions",
    "builtins",
    "os",
    "sys",
    "re",
    "json",
    "math",
    "time",
    "datetime",
    "pathlib",
    "subprocess",
    "unittest",
    "collections",
    "itertools",
    "functools",
    "dataclasses",
    "typing",
    "urllib",
    "http",
    "socket",
    "ssl",
    "hashlib",
    "hmac",
    "secrets",
    "tempfile",
    "shutil",
    "glob",
    "fnmatch",
    "argparse",
    "logging",
    "io",
    "csv",
    "sqlite3",
    "threading",
    "multiprocessing",
    "concurrent",
    "asyncio",
    "contextlib",
    "abc",
    "enum",
    "copy",
    "pprint",
    "traceback",
    "warnings",
    "weakref",
    "ast",
    "inspect",
    "importlib",
    "pkgutil",
    "platform",
    "signal",
    "struct",
    "base64",
    "binascii",
    "uuid",
    "xml",
    "html",
    "email",
    "gzip",
    "zipfile",
    "tarfile",
}

RUST_BUILTIN_CRATES = {
    "std",
    "core",
    "alloc",
    "proc_macro",
    "test",
    "crate",
    "self",
    "super",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".next",
    "dist",
    "build",
    "target",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
}


def _normalize_pypi_name(raw_spec: str) -> str:
    """Extract package name from PEP 508 requirement string and normalize `-` to `_`."""
    cleaned = raw_spec.split("#", 1)[0].strip()
    if not cleaned or cleaned.startswith("-"):
        return ""
    m = re.match(r"^([A-Za-z0-9_.-]+)", cleaned)
    if not m:
        return ""
    return m.group(1).lower().replace("-", "_").replace(".", "_")


_QUOTED_RE = re.compile(r""""([^"]*)"|'([^']*)'""")
_TOML_KEY_RE = re.compile(r"""^\s*["']?([A-Za-z0-9_.-]+)["']?\s*=\s*(.*)$""")


def _pyproject_dependency_names(text: str) -> set[str]:
    """Package names from the dependency tables of a pyproject.toml, and only those.

    Line-based so it runs on Python 3.9/3.10 (no tomllib). Covers PEP 621
    (`[project] dependencies`, `optional-dependencies`), PEP 735 `[dependency-groups]`,
    `[build-system] requires`, Poetry, PDM, uv and Hatch dependency tables.
    """

    def array_key(section: str, key: str) -> bool:
        return (
            (section == "project" and key == "dependencies")
            or section in ("project.optional-dependencies", "dependency-groups", "tool.pdm.dev-dependencies")
            or (section == "build-system" and key == "requires")
            or (section == "tool.uv" and key == "dev-dependencies")
            or (section.startswith("tool.hatch.envs.") and key in ("dependencies", "extra-dependencies"))
        )

    def table_section(section: str) -> bool:
        return section in ("tool.poetry.dependencies", "tool.poetry.dev-dependencies") or bool(
            re.fullmatch(r"tool\.poetry\.group\.[^.]+\.dependencies", section)
        )

    names: set[str] = set()
    section = ""
    collecting = False
    depth = 0
    for raw in text.splitlines():
        hash_at = _QUOTED_RE.sub(lambda m: " " * len(m.group(0)), raw).find("#")
        line = raw[:hash_at] if hash_at >= 0 else raw
        stripped = line.strip()
        if collecting:
            names.update(m.group(1) or m.group(2) or "" for m in _QUOTED_RE.finditer(stripped))
            unquoted = _QUOTED_RE.sub("", stripped)
            depth += unquoted.count("[") - unquoted.count("]")
            collecting = depth > 0
            continue
        m_sec = re.match(r"^\[\[?\s*([^\]]+?)\s*\]\]?\s*$", stripped)
        if m_sec:
            section = m_sec.group(1).replace('"', "").replace("'", "")
            continue
        m_key = _TOML_KEY_RE.match(stripped)
        if not m_key:
            continue
        key, value = m_key.group(1), m_key.group(2)
        if table_section(section):
            if key.lower() != "python":
                names.add(key)
        elif array_key(section, key) and value.startswith("["):
            names.update(m.group(1) or m.group(2) or "" for m in _QUOTED_RE.finditer(value))
            unquoted = _QUOTED_RE.sub("", value)
            depth = unquoted.count("[") - unquoted.count("]")
            collecting = depth > 0
    return names


# Packages a declared framework installs and documents as part of its API: importing them is
# not a hallucination. Only well-known, stable pairs; anything else must be declared.
PROVIDED_BY: dict[str, frozenset[str]] = {
    "fastapi": frozenset({"starlette", "pydantic"}),
    "sqlmodel": frozenset({"sqlalchemy", "pydantic"}),
    "flask": frozenset({"werkzeug", "jinja2", "click", "itsdangerous", "markupsafe"}),
    "requests": frozenset({"urllib3", "idna", "certifi", "charset_normalizer"}),
    "httpx": frozenset({"httpcore", "anyio", "sniffio", "certifi", "idna"}),
    "celery": frozenset({"kombu", "billiard", "vine"}),
    "pytest": frozenset({"_pytest", "pluggy"}),
}
# Example and documentation folders are not the package: their imports have their own setup.
NON_PACKAGE_DIRS = frozenset({"examples", "example", "docs", "doc"})


def _add_python_dep(manifests: WorkspaceManifests, raw_spec: str) -> None:
    norm = _normalize_pypi_name(raw_spec)
    if norm:
        manifests.python_modules.add(norm)
        manifests.python_modules |= {x.lower() for x in PYPI_TO_IMPORT_MAP.get(norm, set())}
        manifests.python_modules |= PROVIDED_BY.get(norm, frozenset())


def find_manifest_files(workspace: Path) -> dict[str, list[Path]]:
    """Manifest files under `workspace`, keyed by kind (`req` for requirements files)."""
    manifest_files: dict[str, list[Path]] = {"package.json": [], "pyproject.toml": [], "go.mod": [], "Cargo.toml": [], "req": []}
    for root, dirs, files in os.walk(workspace):
        # Pruned relative to the workspace: a workspace under e.g. /tmp/build/ is still scanned.
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in files:
            if name in manifest_files:
                manifest_files[name].append(Path(root) / name)
            elif name.endswith(".txt") and ("requirements" in name or Path(root).name == "requirements"):
                manifest_files["req"].append(Path(root) / name)
    return manifest_files


NODE_DEP_SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
GO_REQUIRE_RE = re.compile(r"^\s*(?:require\s+)?([a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._-]+)+)\s+v[0-9]", re.MULTILINE)


def cargo_dependencies(text: str) -> tuple[set[str], dict[str, str]]:
    """(`[package]`/`[lib]` names, {dependency key: its value}) from a Cargo.toml.

    A `[dependencies.serde]` table is keyed by its name, with its body lines as the value.
    """
    own: set[str] = set()
    deps: dict[str, str] = {}
    section = ""
    dotted = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        m_sec = re.match(r"^\[\[?([^\]]+)\]\]?$", line)
        if m_sec:
            section = m_sec.group(1).strip().lower()
            # `[dependencies.serde]` declares the crate in the table name itself.
            m_dotted = re.match(r"^(?:.*\.)?(?:dev-|build-)?dependencies\.([a-z0-9_-]+)$", section)
            dotted = m_dotted.group(1) if m_dotted else ""
            if dotted:
                deps.setdefault(dotted, "")
            continue
        m_dep = re.match(r"^([a-zA-Z0-9_-]+)\s*=\s*(.+)$", line)
        if not m_dep:
            continue
        key, val = m_dep.group(1), m_dep.group(2).strip()
        if dotted:
            deps[dotted] += f" {key} = {val}"
        elif section in ("package", "lib") and key == "name":
            m_name = re.match(r'^["\']([^"\']+)["\']', val)
            if m_name:
                own.add(m_name.group(1))
        elif re.search(r"(?:^|\.)(?:dev-|build-)?dependencies$", section):
            deps[key] = val
    return own, deps


def load_declared_dependencies(workspace: Path) -> WorkspaceManifests:
    """Discover and parse `package.json`, `pyproject.toml`, `requirements*.txt`, `go.mod`, and `Cargo.toml`."""
    manifests = WorkspaceManifests()
    if not workspace.is_dir():
        return manifests

    # Discover local Python packages/modules in workspace
    for child in workspace.iterdir():
        if child.name in SKIP_DIRS or child.name.startswith("."):
            continue
        if child.is_dir():
            manifests.local_python_modules.add(child.name)
            if child.name in ("src", "backend", "app", "lib", "packages"):
                for sub in child.iterdir():
                    if sub.is_dir() and not sub.name.startswith("."):
                        manifests.local_python_modules.add(sub.name)
                    elif sub.is_file() and sub.suffix == ".py":
                        manifests.local_python_modules.add(sub.stem)
        elif child.is_file() and child.suffix == ".py":
            manifests.local_python_modules.add(child.stem)

    manifest_files = find_manifest_files(workspace)

    # 1. Node package.json files
    for pkg_json in manifest_files["package.json"]:
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        manifests.has_node_manifest = True
        pkg_name = data.get("name")
        if isinstance(pkg_name, str) and pkg_name.strip():
            manifests.node_packages.add(pkg_name.strip())
        for section in NODE_DEP_SECTIONS:
            sec_obj = data.get(section)
            if not isinstance(sec_obj, dict):
                continue
            for dep_key in sec_obj:
                manifests.node_packages.add(dep_key)
                # If @types/foo is installed, allow importing 'foo'
                if dep_key.startswith("@types/"):
                    raw_typed = dep_key[len("@types/") :]
                    manifests.node_packages.add("@" + raw_typed.replace("__", "/", 1) if "__" in raw_typed else raw_typed)

    # 2. Python pyproject.toml & requirements*.txt
    for pyproj in manifest_files["pyproject.toml"]:
        manifests.has_python_manifest = True
        for name in _pyproject_dependency_names(pyproj.read_text(encoding="utf-8", errors="ignore")):
            _add_python_dep(manifests, name)

    for req_file in manifest_files["req"]:
        manifests.has_python_manifest = True
        for line in req_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            egg = re.search(r"#egg=([A-Za-z0-9_.-]+)", line)
            _add_python_dep(manifests, egg.group(1) if egg else line)

    # 3. Go go.mod files
    for gomod in manifest_files["go.mod"]:
        manifests.has_go_manifest = True
        text = gomod.read_text(encoding="utf-8", errors="ignore")
        for m_mod in re.finditer(r"^\s*module\s+(\S+)", text, re.MULTILINE):
            manifests.go_modules.add(m_mod.group(1).strip())
        for m_req in GO_REQUIRE_RE.finditer(text):
            manifests.go_modules.add(m_req.group(1).strip())

    # 4. Rust Cargo.toml files
    for cargo in manifest_files["Cargo.toml"]:
        manifests.has_rust_manifest = True
        own, deps = cargo_dependencies(cargo.read_text(encoding="utf-8", errors="ignore"))
        manifests.rust_crates |= {n.replace("-", "_") for n in own}
        for key, val in deps.items():
            manifests.rust_crates.add(key.replace("-", "_"))
            m_pkg = re.search(r"""\bpackage\s*=\s*["']([^"']+)["']""", val)
            if m_pkg:  # `alias = { package = "real-name" }` imports as `alias`
                manifests.rust_crates.add(m_pkg.group(1).replace("-", "_"))

    return manifests


def _extract_npm_package_name(specifier: str) -> str | None:
    """Return the npm package name (`pkg` or `@scope/pkg`) for a module specifier, or None if local/builtin."""
    s = specifier.strip()
    if not s or s.startswith((".", "/", "~/", "@/", "#", "http://", "https://", "data:", "node:", "virtual:")):
        return None
    if ":" in s:
        return None
    if s.startswith("@"):
        parts = s.split("/")
        if len(parts) < 2:
            return None
        pkg = f"{parts[0]}/{parts[1]}"
    else:
        pkg = s.split("/", 1)[0]

    if pkg in NODE_BUILTINS:
        return None
    return pkg


def _scan_js_ts_imports(
    rel_path: str,
    content: str,
    manifests: WorkspaceManifests,
) -> list[Finding]:
    if not manifests.has_node_manifest:
        return []
    findings: list[Finding] = []
    lines = content.splitlines()

    import_re = re.compile(
        r"""(?:^\s*(?:import|export)\s+(?:type\s+)?(?:[^"'\n]*?\s+from\s+)?["']([^"']+)["']|\b(?:require|import)\(\s*["']([^"']+)["']\s*\)"""
        # the closing line of a multi-line import: `} from "pkg";`
        r"""|^\s*\}\s*from\s+["']([^"']+)["'])"""
    )

    for ln, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith(("//", "/*", "*")):
            continue
        # Skip pure type-only imports if desired? No, unless @types or package is in package.json
        for m in import_re.finditer(s):
            spec = m.group(1) or m.group(2) or m.group(3) or ""
            pkg = _extract_npm_package_name(spec)
            if not pkg:
                continue
            if pkg not in manifests.node_packages:
                findings.append(
                    Finding(
                        path=rel_path,
                        line=ln,
                        rule="undeclared-or-hallucinated-import",
                        severity="P0",
                        text=s,
                        message=(
                            f"Imported package '{pkg}' in '{rel_path}:{ln}' is not declared in `package.json` "
                            f"(potential hallucinated/slopsquatted dependency)."
                        ),
                    )
                )
    return findings


def _scan_python_imports(
    path: Path,
    rel_path: str,
    content: str,
    manifests: WorkspaceManifests,
) -> list[Finding]:
    if not manifests.has_python_manifest:
        return []
    findings: list[Finding] = []
    lines = content.splitlines()
    sibling_modules = {
        p.stem for p in path.parent.glob("*.py")
    } if path.parent.is_dir() else set()

    try:
        tree = ast.parse(content)
        # Collect AST nodes inside `try: ... except (ImportError, ModuleNotFoundError):` or `if TYPE_CHECKING:`
        optional_nodes: set[int] = set()
        optional_flags: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                catches_import_err = False
                for h in node.handlers:
                    if h.type is None:
                        catches_import_err = True
                    else:
                        h_str = ast.unparse(h.type) if hasattr(ast, "unparse") else ""
                        if any(k in h_str for k in ("ImportError", "ModuleNotFoundError", "Exception")):
                            catches_import_err = True
                if catches_import_err:
                    for sub in ast.walk(node):
                        optional_nodes.add(id(sub))
                        # `has_simplejson = True` / `= False` in the try or its handler: a flag
                        # whose `if has_simplejson:` block imports the optional module again.
                        if isinstance(sub, ast.Assign):
                            optional_flags.update(t.id for t in sub.targets if isinstance(t, ast.Name))
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                cond_str = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                flagged = any(isinstance(n, ast.Name) and n.id in optional_flags for n in ast.walk(node.test))
                if "TYPE_CHECKING" in cond_str or flagged:
                    for sub in ast.walk(node):
                        optional_nodes.add(id(sub))

        for node in ast.walk(tree):
            if id(node) in optional_nodes:
                continue
            top_mods: list[tuple[int, str]] = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_mods.append((node.lineno, alias.name.split(".", 1)[0]))
            elif isinstance(node, ast.ImportFrom):
                if (node.level or 0) > 0 or not node.module:
                    continue
                top_mods.append((node.lineno, node.module.split(".", 1)[0]))

            for ln, mod in top_mods:
                raw_line = lines[ln - 1].strip() if 1 <= ln <= len(lines) else f"import {mod}"
                mod_norm = mod.lower().replace("-", "_")
                if (
                    mod in PYTHON_STDLIB
                    or mod_norm in PYTHON_STDLIB
                    or mod in manifests.local_python_modules
                    or mod in sibling_modules
                    or mod_norm in manifests.python_modules
                    or mod.lower() in manifests.python_modules
                ):
                    continue
                findings.append(
                    Finding(
                        path=rel_path,
                        line=ln,
                        rule="undeclared-or-hallucinated-import",
                        severity="P0",
                        text=raw_line,
                        message=(
                            f"Imported Python module '{mod}' in '{rel_path}:{ln}' is not declared in "
                            f"`pyproject.toml` or `requirements.txt`."
                        ),
                    )
                )
    except SyntaxError:
        pass

    return findings


def _scan_go_imports(
    rel_path: str,
    content: str,
    manifests: WorkspaceManifests,
) -> list[Finding]:
    if not manifests.has_go_manifest:
        return []
    findings: list[Finding] = []
    lines = content.splitlines()
    in_import_block = False

    for ln, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith("//"):
            continue
        if re.match(r"^import\s*\(", s):
            in_import_block = True
            continue
        if in_import_block and s.startswith(")"):
            in_import_block = False
            continue

        imp_path = None
        if in_import_block:
            m = re.search(r'"([^"]+)"', s)
            if m:
                imp_path = m.group(1)
        else:
            m = re.match(r'^import\s+(?:[a-zA-Z0-9_.]+\s+)?"([^"]+)"', s)
            if m:
                imp_path = m.group(1)

        if not imp_path:
            continue
        first_seg = imp_path.split("/", 1)[0]
        # Standard library Go packages do not contain a dot in the first path segment
        if "." not in first_seg:
            continue
        if not any(imp_path == mod or imp_path.startswith(mod + "/") for mod in manifests.go_modules):
            findings.append(
                Finding(
                    path=rel_path,
                    line=ln,
                    rule="undeclared-or-hallucinated-import",
                    severity="P0",
                    text=s,
                    message=f"Imported Go package '{imp_path}' in '{rel_path}:{ln}' is not declared in `go.mod`.",
                )
            )

    return findings


def _scan_rust_imports(
    rel_path: str,
    content: str,
    manifests: WorkspaceManifests,
) -> list[Finding]:
    if not manifests.has_rust_manifest:
        return []
    findings: list[Finding] = []
    lines = content.splitlines()
    # Collect local `mod foo;` declarations in the file
    local_mods = set(re.findall(r"^\s*(?:pub\s+)?mod\s+([a-zA-Z_]\w*)\s*[;{]", content, re.MULTILINE))

    use_re = re.compile(r"^\s*(?:pub\s+)?use\s+(?:::)?([a-zA-Z_]\w*)::")
    extern_re = re.compile(r"^\s*extern\s+crate\s+([a-zA-Z_]\w*)")

    for ln, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith("//"):
            continue
        m = use_re.match(s) or extern_re.match(s)
        if not m:
            continue
        crate_name = m.group(1).replace("-", "_")
        if crate_name in RUST_BUILTIN_CRATES or crate_name in local_mods:
            continue
        if crate_name not in manifests.rust_crates:
            findings.append(
                Finding(
                    path=rel_path,
                    line=ln,
                    rule="undeclared-or-hallucinated-import",
                    severity="P0",
                    text=s,
                    message=f"Imported Rust crate '{crate_name}' in '{rel_path}:{ln}' is not declared in `Cargo.toml`.",
                )
            )
    return findings


def scan_file_dependencies(
    path: Path | str,
    content: str,
    workspace: Path,
    manifests: WorkspaceManifests | None = None,
    config: PrufGateConfig | None = None,
) -> list[Finding]:
    """Scan a single source file for undeclared or hallucinated third-party imports."""
    p = Path(path)
    try:
        rel_path = str(p.resolve().relative_to(workspace.resolve())).replace("\\", "/")
    except ValueError:
        rel_path = str(p).replace("\\", "/")

    cfg = config or PrufGateConfig()
    if cfg.is_excluded(rel_path) or cfg.is_exempt(rel_path, "undeclared-or-hallucinated-import"):
        return []
    if NON_PACKAGE_DIRS & set(rel_path.split("/")[:-1]):
        return []

    mf = manifests or load_declared_dependencies(workspace)
    sfx = p.suffix.lower()

    if sfx in (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"):
        found = _scan_js_ts_imports(rel_path, content, mf)
    elif sfx == ".py":
        found = _scan_python_imports(p, rel_path, content, mf)
    elif sfx == ".go":
        found = _scan_go_imports(rel_path, content, mf)
    elif sfx == ".rs":
        found = _scan_rust_imports(rel_path, content, mf)
    else:
        return []
    lines = content.splitlines()
    return [
        f for f in found
        if not inline_ignore.suppressed_at(
            lines, f.line, f.rule, engine="contract-guard", path=rel_path, severity=f.severity, message=f.message
        )
    ]
