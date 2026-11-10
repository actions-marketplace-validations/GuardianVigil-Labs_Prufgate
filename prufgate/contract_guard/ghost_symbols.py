"""Ghost symbols (`ghost-symbol`): names imported or called that their module does not define.

An AI agent that invents an API writes `from app.billing import charge_card` when
`app/billing.py` has no `charge_card`. This module checks, for added lines only:

- Python: `from pkg.mod import name`, relative imports and `module.attr(...)` calls whose
  module is part of the scanned repository. With `third_party`, also installed packages
  in the current interpreter's environment, located with `PathFinder.find_spec` (which,
  unlike `importlib.util.find_spec`, never imports a parent package) and read with `ast`
  (a `.pyi` stub first). Nothing is ever imported or executed.
- TypeScript/JavaScript: `import { name } from "./relative"` against the target file's exports.

Anything that cannot be decided (a star import, a module `__getattr__`, a compiled module
without a stub, `export *` from a file that cannot be resolved, CommonJS) is unknown, and
unknown never produces a finding.
"""

from __future__ import annotations

import ast
import importlib
import re
import sys
from importlib.machinery import PathFinder
from pathlib import Path
from typing import Any, Iterator, Optional

from prufgate.contract_guard.dependency_guard import PYTHON_STDLIB, Finding
from prufgate.safe_fs import safe_read_text

RULE = "ghost-symbol"

# --- Python -----------------------------------------------------------------------


def _find_spec(parts: list[str], roots: list[str]) -> Any:
    """The spec of the dotted module `parts` under `roots`, without importing anything."""
    path: Optional[list[str]] = roots
    spec = None
    for i in range(len(parts)):
        if path is None:
            return None
        try:
            spec = PathFinder.find_spec(".".join(parts[: i + 1]), path)
        except (ImportError, ValueError, OSError):
            return None
        if spec is None:
            return None
        locs = spec.submodule_search_locations
        path = list(locs) if locs is not None else None
    return spec


def _module_names(tree: ast.Module) -> Optional[set[str]]:
    """Names a module defines at top level, conditional ones included; None when unknowable."""
    names: set[str] = set()
    stack: list[ast.AST] = list(tree.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == "__getattr__":
                return None  # PEP 562: any attribute may exist
            names.add(node.name)
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == "*":
                    return None
                names.add(alias.asname or alias.name.split(".", 1)[0])
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("globals", "vars"):
            return None  # `globals()[name] = ...` defines names we cannot see
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            if isinstance(node.value, (ast.List, ast.Tuple)):
                names.update(e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str))
        if isinstance(node, ast.Lambda):
            continue
        stack.extend(ast.iter_child_nodes(node))
    return names


_names_cache: dict[tuple[str, int, int], Optional[set[str]]] = {}
_MAX_MODULE_BYTES = 2 * 1024 * 1024


def _source_names(spec: Any) -> Optional[set[str]]:
    origin = getattr(spec, "origin", None)
    if not origin or not getattr(spec, "has_location", False):
        return None  # namespace package, builtin or frozen module
    src = Path(origin)
    stub = src.with_suffix(".pyi") if src.suffix == ".py" else src.with_name(src.name.split(".", 1)[0] + ".pyi")
    if stub.is_file():
        src = stub
    elif src.suffix != ".py":
        return None  # compiled module without a stub
    try:
        st = src.stat()
    except OSError:
        return None
    key = (str(src), st.st_mtime_ns, st.st_size)  # a long-running server sees edits
    if key not in _names_cache:
        try:
            if st.st_size > _MAX_MODULE_BYTES:
                raise ValueError("too large to read")
            _names_cache[key] = _module_names(ast.parse(safe_read_text(src, encoding="utf-8", errors="ignore")))
        except (OSError, SyntaxError, ValueError, RecursionError, MemoryError):
            _names_cache[key] = None  # unknown: its names are never reported missing
    return _names_cache[key]


def _within(spec: Any, roots: list[str]) -> bool:
    """Every location of `spec` lies inside one of `roots` once symlinks are resolved."""
    bases = [Path(r).resolve() for r in roots]
    locs = list(spec.submodule_search_locations or []) or [spec.origin or ""]
    return all(any(Path(loc).resolve().is_relative_to(b) for b in bases) for loc in locs)


class _Module:
    def __init__(self, spec: Any, label: str, opaque: bool = False) -> None:
        self.spec = spec
        self.label = label
        self.opaque = opaque  # exists, but lies outside its package: never read
        self.names = None if opaque else _source_names(spec)

    def submodule(self, name: str) -> Optional[_Module]:
        locs = None if self.opaque else self.spec.submodule_search_locations
        if locs is None:
            return None
        sub = _find_spec([name], list(locs))
        if sub is None:
            return None
        return _Module(sub, f"{self.label}.{name}", opaque=not _within(sub, list(locs)))

    def has(self, name: str) -> Optional[bool]:
        """True: defined. False: certainly missing. None: cannot tell."""
        if self.submodule(name) is not None:
            return True
        if self.names is None:
            return None
        return name in self.names


class _PythonResolver:
    def __init__(self, workspace: Path, third_party: bool) -> None:
        self.workspace = workspace.resolve()
        self.roots = [str(self.workspace)] + ([str(self.workspace / "src")] if (self.workspace / "src").is_dir() else [])
        self.third_party = third_party

    def _inside(self, spec: Any) -> bool:
        return _within(spec, [str(self.workspace)])

    def absolute(self, dotted: str, file_dir: Path) -> Optional[_Module]:
        parts = dotted.split(".")
        if parts[0] not in PYTHON_STDLIB:
            spec = _find_spec(parts, self.roots + [str(file_dir)])
            if spec is not None and self._inside(spec):
                return _Module(spec, dotted)
            if spec is None and self.third_party:
                spec = _find_spec(parts, [p for p in sys.path if p and Path(p).resolve() != self.workspace])
                if spec is not None and not self._inside(spec):
                    return _Module(spec, dotted)
        return None

    def relative(self, level: int, module: Optional[str], file_path: Path) -> Optional[_Module]:
        pkg_dir = file_path.resolve().parent
        for _ in range(level - 1):
            pkg_dir = pkg_dir.parent
        if not pkg_dir.is_relative_to(self.workspace):
            return None
        if module:
            parts = module.split(".")
            spec = _find_spec(parts, [str(pkg_dir)])
            return _Module(spec, "." * level + module) if spec is not None and self._inside(spec) else None
        if pkg_dir == self.workspace:
            return None  # `from . import x` at the top level would search the workspace's parent
        spec = _find_spec([pkg_dir.name], [str(pkg_dir.parent)])
        return _Module(spec, ".") if spec is not None and self._inside(spec) else None


_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _bindings(nodes: list[ast.AST], into_scopes: bool) -> dict[str, int]:
    """How many times each name is bound in `nodes`; nested function bodies are entered
    only with `into_scopes` (their own name always counts)."""
    counts: dict[str, int] = {}

    def bump(n: str) -> None:
        counts[n] = counts.get(n, 0) + 1

    stack = list(nodes)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                bump(a.asname or a.name.split(".", 1)[0])
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bump(node.id)
        elif isinstance(node, ast.arg):
            bump(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bump(node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bump(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for n in node.names:
                bump(n)
        if isinstance(node, _SCOPES) and not into_scopes:
            # Decorators and defaults run in the enclosing scope; the body and arguments do not.
            stack.extend(getattr(node, "decorator_list", []))
            stack.extend(d for d in node.args.defaults + node.args.kw_defaults if d is not None)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return counts


def _calls_in_scope(tree: ast.Module) -> Iterator[tuple[ast.Call, tuple[ast.AST, ...]]]:
    """Every call, with the functions it sits in (outermost first)."""
    stack: list[tuple[ast.AST, tuple[ast.AST, ...]]] = [(tree, ())]
    while stack:
        node, scopes = stack.pop()
        if isinstance(node, ast.Call):
            yield node, scopes
        inner = scopes + (node,) if isinstance(node, _SCOPES) else scopes
        stack.extend((child, inner) for child in ast.iter_child_nodes(node))


def _scan_python(file_path: Path, rel_path: str, content: str, added: Optional[set[int]], res: _PythonResolver) -> list[Finding]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    lines = content.splitlines()
    file_dir = file_path.resolve().parent
    out: list[Finding] = []

    def flag(line: int, name: str, mod: _Module) -> None:
        out.append(
            Finding(
                path=rel_path,
                line=line,
                rule=RULE,
                severity="P1",
                text=lines[line - 1] if 0 < line <= len(lines) else name,
                message=f"`{name}` is not defined in module `{mod.label}` (a hallucinated API: the import or call fails at runtime).",
            )
        )

    def resolve(node: ast.ImportFrom) -> Optional[_Module]:
        if node.level:
            return res.relative(node.level, node.module, file_path)
        return res.absolute(node.module, file_dir) if node.module else None

    aliases: dict[str, _Module] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = resolve(node)
            if mod is None:
                continue
            span = range(node.lineno, (getattr(node, "end_lineno", None) or node.lineno) + 1)
            for a in node.names:
                if a.name == "*":
                    continue
                # Each name of a multi-line `from x import (...)` counts on its own line
                # (Python 3.10+; older versions only know the statement's lines).
                at = getattr(a, "lineno", None)
                new = added is None or (at in added if at is not None else any(ln in added for ln in span))
                sub = mod.submodule(a.name)
                if sub is not None:
                    aliases[a.asname or a.name] = sub
                elif new and mod.has(a.name) is False:
                    flag(at or node.lineno, a.name, mod)
        elif isinstance(node, ast.Import):
            for a in node.names:
                target = a.name if a.asname else a.name.split(".", 1)[0]
                mod = res.absolute(target, file_dir)
                if mod is not None:
                    aliases[a.asname or target] = mod

    counts = _bindings(list(tree.body), into_scopes=False)
    local_cache: dict[int, dict[str, int]] = {}
    for node, scopes in _calls_in_scope(tree):
        if not isinstance(node.func, ast.Attribute):
            continue
        if added is not None and node.lineno not in added:
            continue
        chain: list[str] = []
        cur: ast.AST = node.func
        while isinstance(cur, ast.Attribute):
            chain.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name) or cur.id not in aliases or counts.get(cur.id, 0) != 1:
            continue
        # A parameter or local of an enclosing function shadows the module only there.
        if any(cur.id in local_cache.setdefault(id(f), _bindings(list(ast.iter_child_nodes(f)), True)) for f in scopes):
            continue
        mod = aliases[cur.id]
        for attr in reversed(chain):
            sub = mod.submodule(attr)
            if sub is not None:
                mod = sub
                continue
            if mod.has(attr) is False:
                flag(node.lineno, attr, mod)
            break
    return out


# --- TypeScript / JavaScript --------------------------------------------------------

_TS_IMPORT_RE = re.compile(
    r"""\bimport\s+(?:type\s+)?(?:[A-Za-z_$][\w$]*\s*,\s*)?\{([^}]*)\}\s*from\s*["'](\.{1,2}/[^"']*)["']"""
)
_TS_DECL_RE = re.compile(
    r"""\bexport\s+(?:declare\s+)?(?:default\s+)?(?:abstract\s+)?(?:async\s+)?"""
    r"""(?:function\s*\*?|class|const\s+enum|const|let|var|type|interface|enum|namespace|module)\s+([A-Za-z_$][\w$]*)"""
)
_TS_DESTRUCT_RE = re.compile(r"""\bexport\s+(?:declare\s+)?(?:const|let|var)\s*[{\[]([^}\]]*)[}\]]""")
_TS_LIST_RE = re.compile(r"""\bexport\s+(?:type\s+)?\{([^}]*)\}(?:\s*from\s*["']([^"']+)["'])?""")
_TS_STAR_RE = re.compile(r"""\bexport\s+\*\s+(?:as\s+([A-Za-z_$][\w$]*)\s+)?from\s*["']([^"']+)["']""")
_TS_CJS_RE = re.compile(r"""\bmodule\.exports\b|\bexports\.[A-Za-z_$]|\bexport\s*=""")
_TS_EXTS = (".ts", ".tsx", ".mts", ".cts", ".d.ts", ".js", ".jsx", ".mjs", ".cjs")


def _ts_names(spec_list: str) -> list[tuple[str, str]]:
    """`a, b as c, type D` -> [(imported, local)]."""
    out = []
    for part in spec_list.split(","):
        words = part.split()
        if words and words[0] == "type" and len(words) > 1:
            words = words[1:]
        if not words:
            continue
        out.append((words[0], words[-1] if len(words) >= 3 and words[1] == "as" else words[0]))
    return out


def _ts_resolve(base: Path, spec: str, workspace: Path) -> Optional[Path]:
    target = (base / spec).resolve()
    if not target.is_relative_to(workspace):
        return None
    candidates = [target]
    if target.suffix in (".js", ".jsx", ".mjs", ".cjs"):  # ESM TypeScript imports "./x.js" for x.ts
        stem = target.with_suffix("")
        candidates += [stem.with_suffix(e) for e in (".ts", ".tsx", ".mts", ".cts")]
    candidates += [Path(str(target) + e) for e in _TS_EXTS]
    candidates += [target / ("index" + e) for e in _TS_EXTS]
    found = next((c for c in candidates if c.is_file()), None)
    # `.vue`, `.json` and other non-script targets are not read
    return found if found is not None and found.name.endswith(_TS_EXTS) else None


def _ts_exports(path: Path, workspace: Path, seen: set[Path]) -> Optional[set[str]]:
    """Names `path` exports; None when they cannot all be known."""
    if path in seen:
        return set()
    if len(seen) >= 64:
        return None  # ponytail: a re-export chain this long is not followed
    seen.add(path)
    try:
        text = safe_read_text(path, encoding="utf-8", errors="ignore")
    except OSError:
        return None
    if _TS_CJS_RE.search(text):
        return None
    names = set(_TS_DECL_RE.findall(text))
    for m in re.finditer(r"""\bexport\s+(?:declare\s+)?(?:const|let|var)\s+[^;\n]*""", text):
        names.update(re.findall(r",\s*([A-Za-z_$][\w$]*)\s*[=:]", m.group(0)))  # `export const a = 1, b = 2`
    for m in _TS_DESTRUCT_RE.finditer(text):
        names.update(re.findall(r"[A-Za-z_$][\w$]*", m.group(1)))
    for m in _TS_LIST_RE.finditer(text):
        names.update(local for _, local in _ts_names(m.group(1)))
    for m in _TS_STAR_RE.finditer(text):
        if m.group(1):
            names.add(m.group(1))
            continue
        if not m.group(2).startswith("."):
            return None
        target = _ts_resolve(path.parent, m.group(2), workspace)
        sub = _ts_exports(target, workspace, seen) if target else None
        if sub is None:
            return None
        names |= sub
    return names


def _scan_ts(file_path: Path, rel_path: str, content: str, added: Optional[set[int]], workspace: Path) -> list[Finding]:
    out: list[Finding] = []
    lines = content.splitlines()
    for m in _TS_IMPORT_RE.finditer(content):
        first = content.count("\n", 0, m.start()) + 1
        last = first + m.group(0).count("\n")
        if first <= len(lines) and lines[first - 1].lstrip().startswith(("//", "/*", "*")):
            continue  # commented out
        if added is not None and not any(ln in added for ln in range(first, last + 1)):
            continue
        target = _ts_resolve(file_path.resolve().parent, m.group(2), workspace)
        if target is None:
            continue
        exports = _ts_exports(target, workspace, set())
        if exports is None:
            continue
        for imported, _local in _ts_names(m.group(1)):
            if imported != "default" and imported not in exports:
                out.append(
                    Finding(
                        path=rel_path,
                        line=first,
                        rule=RULE,
                        severity="P1",
                        text=lines[first - 1] if first <= len(lines) else imported,
                        message=f"`{imported}` is not exported by `{m.group(2)}` (a hallucinated API: the import fails).",
                    )
                )
    return out


def scan_file_ghost_symbols(
    file_path: Path,
    rel_path: str,
    content: str,
    workspace: Path,
    added: Optional[set[int]] = None,
    third_party: bool = False,
) -> list[Finding]:
    """`ghost-symbol` findings for one file; `added` limits them to those line numbers."""
    importlib.invalidate_caches()  # directory listings may have changed since the last scan
    sfx = file_path.suffix.lower()
    if sfx == ".py":
        return _scan_python(file_path, rel_path, content, added, _PythonResolver(workspace, third_party))
    if sfx in (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"):
        return _scan_ts(file_path, rel_path, content, added, workspace.resolve())
    return []
