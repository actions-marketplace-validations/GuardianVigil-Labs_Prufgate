"""Environment variable names declared outside `.env.example`.

A variable read in code counts as documented when one of these declares it:

- zod env schemas: `z.object({ FOO: z.string() })` and t3-env `createEnv({ server, client })`,
  in JS/TS files whose name contains `env`;
- pydantic-settings `BaseSettings` subclasses (parsed with `ast`): field names with `env_prefix`,
  `Field(alias=..., validation_alias=..., env=...)` and `AliasChoices(...)`;
- docker-compose `environment:` (list and map forms) and the files named by `env_file:`;
- Kubernetes manifests: `env: - name:`, and `envFrom` when the ConfigMap or Secret it names is
  defined in a scanned manifest. An `envFrom` whose source is not in the repository documents
  nothing, so the variables of that workload still need another source;
- Helm `values*.yaml` (`env:` blocks) and chart templates (`- name: UPPER_CASE`; Kubernetes
  object names are lower case, so an upper-case name there is an environment variable);
- GitHub Actions workflow `env:` blocks;
- Cloudflare Workers: `[vars]` (and `[env.<name>.vars]`) in `wrangler.toml`, `vars` (top level
  and per environment) in `wrangler.json` / `wrangler.jsonc`, and the dotenv-style `.dev.vars*`.

Only conventional paths are read, files over `MAX_SOURCE_BYTES` are skipped, and the `exclude`
configuration applies. A file that cannot be read or parsed is skipped with a warning on stderr,
like an unreadable `.env.example`: skipping a source can only add findings, never hide one.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from prufgate.bola.bola_engine import is_test_path, iter_workspace_files
from prufgate.config import PrufGateConfig

MAX_SOURCE_BYTES = 1_000_000

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_JS_SUFFIXES = {".ts", ".tsx", ".js", ".mjs", ".cjs", ".mts", ".cts"}
_YAML_SUFFIXES = {".yaml", ".yml"}
_DEPLOY_DIRS = {"k8s", "kubernetes", "kube", "manifests", "deploy", "deployment", "deployments", "helm", "charts", "kustomize", "infra"}
_PY_NAME_HINTS = ("settings", "config", "conf", "env")

# zod: an upper-case key whose value starts with `z.` (quoted or bare key).
_ZOD_KEY_RE = re.compile(r"""(?:^|[{,\s])["']?([A-Z][A-Z0-9_]*)["']?\s*:\s*z\s*\.""")
_JS_COMMENT_RE = re.compile(r"/\*.*?\*/|(?<![:\"'\\])//[^\n]*", re.DOTALL)
# Helm templates are not YAML until rendered: read env names literally.
_HELM_ENV_NAME_RE = re.compile(r"""^\s*-\s*name:\s*["']?([A-Z][A-Z0-9_]*)["']?\s*$""", re.MULTILINE)


def _warn(rel: str, why: str) -> None:
    print(f"contract_guard: warning: skipped env source {rel}: {why}", file=sys.stderr)


def _read(path: Path, rel: str) -> str | None:
    try:
        if path.stat().st_size > MAX_SOURCE_BYTES:
            _warn(rel, f"larger than {MAX_SOURCE_BYTES} bytes")
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        _warn(rel, str(e))
        return None


def _dotenv_keys(text: str) -> set[str]:
    key_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=")
    return {m.group(1) for line in text.splitlines() if (m := key_re.match(line))}


# --- zod / t3-env -------------------------------------------------------------------------------


def zod_env_vars(text: str) -> set[str]:
    if "z.object(" not in text and "createEnv(" not in text:
        return set()
    return set(_ZOD_KEY_RE.findall(_JS_COMMENT_RE.sub("", text)))


# --- pydantic-settings --------------------------------------------------------------------------


def _str_values(node: ast.AST | None) -> list[str]:
    """String literals in `node`: a constant, a list/tuple of them, or `AliasChoices("A", "B")`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [v for e in node.elts for v in _str_values(e)]
    if isinstance(node, ast.Call) and _name(node.func) == "AliasChoices":
        return [v for a in node.args for v in _str_values(a)]
    return []


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _kw(call: ast.Call, key: str) -> ast.AST | None:
    return next((k.value for k in call.keywords if k.arg == key), None)


def _class_prefix(cls: ast.ClassDef) -> str:
    for stmt in cls.body:
        value = None
        if isinstance(stmt, ast.Assign) and any(_name(t) == "model_config" for t in stmt.targets):
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and _name(stmt.target) == "model_config":
            value = stmt.value
        if isinstance(value, ast.Call):
            prefix = _str_values(_kw(value, "env_prefix"))
            if prefix:
                return prefix[0]
        if isinstance(value, ast.Dict):
            for k, v in zip(value.keys, value.values):
                if isinstance(k, ast.Constant) and k.value == "env_prefix" and _str_values(v):
                    return _str_values(v)[0]
        if isinstance(stmt, ast.ClassDef) and stmt.name == "Config":  # pydantic v1
            for inner in stmt.body:
                if isinstance(inner, ast.Assign) and any(_name(t) == "env_prefix" for t in inner.targets):
                    if _str_values(inner.value):
                        return _str_values(inner.value)[0]
    return ""


def pydantic_env_vars(text: str) -> set[str]:
    if "BaseSettings" not in text:
        return set()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    settings_classes = {"BaseSettings"}
    out: set[str] = set()
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        if not any(_name(b) in settings_classes for b in cls.bases):
            continue
        settings_classes.add(cls.name)
        prefix = _class_prefix(cls)
        for stmt in cls.body:
            if not isinstance(stmt, ast.AnnAssign) or not isinstance(stmt.target, ast.Name):
                continue
            field = stmt.target.id
            if field == "model_config":
                continue
            aliases: list[str] = []
            if isinstance(stmt.value, ast.Call) and _name(stmt.value.func) == "Field":
                for key in ("alias", "validation_alias", "env"):
                    aliases += _str_values(_kw(stmt.value, key))
            if aliases:  # an alias replaces the prefixed field name
                out.update(a for a in aliases if _ENV_NAME_RE.match(a))
                out.update(a.upper() for a in aliases if _ENV_NAME_RE.match(a))
            else:
                out.add((prefix + field).upper())
    return out


# --- YAML: compose, Kubernetes, Helm values, GitHub Actions ------------------------------------


# YAML aliases share one object, so a few hundred bytes can describe a graph that is exponential
# (or cyclic) when walked as a tree. Each container is visited once, and a walk stops at this many.
_MAX_YAML_NODES = 100_000


def _walk(root: Any, sink: dict[str, Any]) -> bool:
    """Collect env names, `env_file:` paths, `envFrom` refs and ConfigMap/Secret keys.
    False when the document has more than `_MAX_YAML_NODES` containers."""
    stack, seen = [root], set()
    while stack:
        node = stack.pop()
        if not isinstance(node, (list, dict)) or id(node) in seen:
            continue
        seen.add(id(node))
        if len(seen) > _MAX_YAML_NODES:
            return False
        if isinstance(node, list):
            stack.extend(node)
            continue
        _collect(node, sink)
        stack.extend(node.values())
    return True


def _collect(node: dict[Any, Any], sink: dict[str, Any]) -> None:
    if node.get("kind") in ("ConfigMap", "Secret") and isinstance(node.get("metadata"), dict):
        keys = set()
        for block in ("data", "stringData", "binaryData"):
            if isinstance(node.get(block), dict):
                keys |= {str(k) for k in node[block]}
        sink["sources"].setdefault(str(node["metadata"].get("name")), set()).update(keys)
    for key, value in node.items():
        if key in ("env", "environment", "extraEnv", "extraEnvVars"):
            if isinstance(value, dict):
                sink["names"].update(str(k) for k in value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and "name" in item:
                        sink["names"].add(str(item["name"]))
                    elif isinstance(item, str):
                        sink["names"].add(item.split("=", 1)[0].strip())
        elif key == "env_file":
            files = value if isinstance(value, list) else [value]
            for f in files:
                path = f.get("path") if isinstance(f, dict) else f
                if isinstance(path, str):
                    sink["env_files"].append(path)
        elif key == "envFrom" and isinstance(value, list):
            for item in value:
                if not isinstance(item, dict):
                    continue
                for ref_key in ("configMapRef", "secretRef"):
                    ref = item.get(ref_key)
                    if isinstance(ref, dict) and ref.get("name"):
                        sink["env_from"].append((str(ref["name"]), str(item.get("prefix") or "")))


# --- Cloudflare wrangler -------------------------------------------------------------------------

_TOML_TABLE_RE = re.compile(r"""^\s*\[\[?\s*([A-Za-z0-9_."' -]+(?:\.[A-Za-z0-9_."' -]+)*)\s*\]\]?\s*(?:#.*)?$""")
_TOML_KEY_RE = re.compile(r"""^\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*=""")
_TOML_INLINE_VARS_RE = re.compile(r"""^\s*vars\s*=\s*\{([^}]*)\}""", re.MULTILINE)
_INLINE_KEY_RE = re.compile(r"""(?:^|,)\s*["']?([A-Za-z_][A-Za-z0-9_]*)["']?\s*=""")


def wrangler_toml_vars(text: str) -> set[str]:
    """Keys of `[vars]` / `[env.<name>.vars]` tables and of inline `vars = { ... }`."""
    names: set[str] = set()
    in_vars = False
    bracket_depth = 0
    for line in text.splitlines():
        code_line = line.split("#", 1)[0]
        if bracket_depth <= 0 and (table := _TOML_TABLE_RE.match(line)):
            parts = [p.strip().strip("\"'") for p in table.group(1).split(".")]
            in_vars = parts == ["vars"] or (len(parts) == 3 and parts[0] == "env" and parts[2] == "vars")
            bracket_depth = 0
            continue
        if in_vars and bracket_depth <= 0 and (m := _TOML_KEY_RE.match(line)):
            names.add(m.group(1))
        rhs = code_line.split("=", 1)[1] if (bracket_depth <= 0 and "=" in code_line) else code_line
        bracket_depth = max(0, bracket_depth + rhs.count("[") - rhs.count("]"))
    for m in _TOML_INLINE_VARS_RE.finditer(text):
        names |= set(_INLINE_KEY_RE.findall(m.group(1)))
    return names


def _strip_jsonc(text: str) -> str:
    """JSON with comments and trailing commas (wrangler.jsonc) as plain JSON."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def wrangler_json_vars(text: str) -> set[str]:
    """Keys of `vars`, top level and under each `env.<name>`, in wrangler.json(c)."""
    data = json.loads(_strip_jsonc(text))
    if not isinstance(data, dict):
        return set()
    envs = data.get("env")
    blocks = [data] + ([e for e in envs.values() if isinstance(e, dict)] if isinstance(envs, dict) else [])
    return {str(k) for b in blocks if isinstance(b.get("vars"), dict) for k in b["vars"]}


def _is_yaml_source(rel: str) -> bool:
    parts = rel.lower().split("/")
    name = parts[-1]
    if name.startswith(("docker-compose", "compose")):
        return True
    if parts[:2] == [".github", "workflows"]:
        return True
    if name.startswith("values"):  # Helm values*.yaml
        return True
    return any(p in _DEPLOY_DIRS for p in parts[:-1])


def _is_helm_template(rel: str) -> bool:
    parts = rel.split("/")
    return "templates" in parts[:-1]


# --- discovery ----------------------------------------------------------------------------------


def load_env_sources(workspace: Path, config: PrufGateConfig | None = None) -> set[str]:
    """Env names declared by schemas and manifests under `workspace` (conventional paths only)."""
    cfg = config or PrufGateConfig()
    names: set[str] = set()
    sink: dict[str, Any] = {"names": set(), "env_files": [], "env_from": [], "sources": {}}
    compose_env_files: list[tuple[Path, str]] = []
    root = workspace.resolve()

    for path in iter_workspace_files(workspace, _JS_SUFFIXES | _YAML_SUFFIXES | {".py", ".toml", ".json", ".jsonc", ".vars", ".example"}):
        rel = str(path.relative_to(workspace)).replace("\\", "/")
        if cfg.is_excluded(rel) or is_test_path(rel) or not path.resolve().is_relative_to(root):
            continue  # a symlink to a file outside the workspace documents nothing
        suffix = path.suffix.lower()
        stem = path.name.lower()
        if stem.startswith(".dev.vars"):
            if (text := _read(path, rel)) is not None:
                names |= _dotenv_keys(text)
        elif stem in ("wrangler.json", "wrangler.jsonc"):
            if (text := _read(path, rel)) is not None:
                try:
                    names |= wrangler_json_vars(text)
                except ValueError as e:
                    _warn(rel, f"invalid JSON: {e}")
        elif stem == "wrangler.toml":
            if (text := _read(path, rel)) is not None:
                names |= wrangler_toml_vars(text)
        elif suffix in (".toml", ".json", ".jsonc", ".vars", ".example"):
            continue
        elif suffix in _JS_SUFFIXES:
            if "env" in stem and (text := _read(path, rel)) is not None:
                names |= zod_env_vars(text)
        elif suffix == ".py":
            if any(h in stem for h in _PY_NAME_HINTS) and (text := _read(path, rel)) is not None:
                names |= pydantic_env_vars(text)
        elif _is_helm_template(rel):
            if (text := _read(path, rel)) is not None:
                names |= set(_HELM_ENV_NAME_RE.findall(text))
        elif _is_yaml_source(rel) and yaml is None:
            _warn(rel, "PyYAML is not installed")
        elif _is_yaml_source(rel) and (text := _read(path, rel)) is not None:
            before = len(sink["env_files"])
            try:
                complete = all(_walk(doc, sink) for doc in yaml.safe_load_all(text))
            except yaml.YAMLError as e:
                _warn(rel, f"invalid YAML: {str(e).splitlines()[0]}")
                continue
            except RecursionError:
                complete = False
            if not complete:
                _warn(rel, "YAML too large or too deeply nested; partly read")
            compose_env_files += [(path.parent, f) for f in sink["env_files"][before:]]

    names |= sink["names"]
    # envFrom documents the keys of a ConfigMap/Secret defined in the repository; an unresolved one documents nothing.
    for source, prefix in sink["env_from"]:
        names |= {prefix + k for k in sink["sources"].get(source, ())}
    for base, ref in compose_env_files:
        target = (base / ref).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            continue
        rel = str(target.relative_to(root)).replace("\\", "/")
        if not cfg.is_excluded(rel) and (text := _read(target, rel)) is not None:
            names |= _dotenv_keys(text)
    return {n for n in names if _ENV_NAME_RE.match(n)}
