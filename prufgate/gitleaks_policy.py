"""Materialize Gitleaks configuration from the trusted comparison base."""

from __future__ import annotations

import datetime
import json
import posixpath
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from prufgate.config import GitDiffError, _diff_base, _git, git_blob, repo_prefix  # noqa: E402
from prufgate.safe_fs import safe_read_text, safe_write_text  # noqa: E402


def _loads(text: str) -> dict:
    try:
        import tomllib
    except ImportError:  # Python 3.9/3.10: declared conditional dependency
        import tomli as tomllib
    return tomllib.loads(text)


def _value(value: object) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(json.dumps(key) + " = " + _value(item) for key, item in value.items()) + " }"
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    raise ValueError("unsupported Gitleaks configuration value")


def _dump(data: dict) -> str:
    return "".join(json.dumps(key) + " = " + _value(value) + "\n" for key, value in data.items())


def materialize(workspace: Path, output: Path, shipped: Path, base: str = "HEAD") -> Path:
    workspace = workspace.resolve()
    try:
        _git(["rev-parse", "--is-inside-work-tree"], workspace)
    except GitDiffError:
        commit = None  # directory-only scans have no versioned comparison base
    else:
        commit = _diff_base(base, workspace)
    prefix = repo_prefix(workspace) if commit else ""

    def read(rel: str) -> str | None:
        if commit:
            return git_blob(commit, prefix + rel, workspace)
        path = workspace / rel
        return safe_read_text(path, root=workspace) if path.is_file() else None

    def snapshot(rel: str, seen: tuple[str, ...] = ()) -> Path | None:
        if rel in seen or len(seen) > 2:
            raise ValueError("cyclic or excessively nested Gitleaks configuration")
        text = read(rel)
        if text is None:
            return None
        data = _loads(text)
        keys = [key for key in data if key.lower() == "extend"]
        if len(keys) > 1:
            raise ValueError("ambiguous Gitleaks extend tables")
        section = data[keys[0]] if keys else {}
        if not isinstance(section, dict):
            raise ValueError("Gitleaks extend must be a table")
        paths = [key for key in section if key.lower() == "path"]
        if len(paths) > 1:
            raise ValueError("ambiguous Gitleaks include paths")
        if len(seen) == 2 and (paths or section.get("useDefault")):
            raise ValueError("Gitleaks inheritance exceeds its supported depth")
        if paths:
            target = section[paths[0]]
            if not isinstance(target, str) or "\\" in target or posixpath.isabs(target):
                raise ValueError("Gitleaks extend.path must be a local path")
            # Gitleaks resolves every include against its invocation workspace,
            # including includes written inside another configuration file.
            target = posixpath.normpath(target)
            if target == ".." or target.startswith("../"):
                raise ValueError("Gitleaks extend.path must stay inside the workspace")
            nested = snapshot(target, (*seen, rel))
            if nested is None:
                raise ValueError("Gitleaks extended configuration is absent at the comparison base")
            section[paths[0]] = str(nested)
        text = _dump(data)
        destination = output / f"gitleaks.base-{len(seen)}.toml"
        safe_write_text(destination, text)
        return destination

    project = snapshot(".gitleaks.toml")
    if project is None:
        return shipped
    # Add exclusions to the project root itself. An extra [extend] wrapper
    # consumes Gitleaks' inheritance budget and silently drops deeper rules.
    data = _loads(safe_read_text(project))
    allowlists = data.get("allowlists", [])
    if not isinstance(allowlists, list):
        raise ValueError("Gitleaks allowlists must be an array")
    legacy = data.pop("allowlist", None)
    if legacy is not None:
        if not isinstance(legacy, dict):
            raise ValueError("Gitleaks allowlist must be a table")
        allowlists = [legacy, *allowlists]
    data["allowlists"] = [*allowlists, _loads(safe_read_text(shipped))["allowlist"]]
    safe_write_text(project, _dump(data))
    return project


def main() -> int:
    try:
        print(materialize(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]))
    except (ImportError, OSError, ValueError, GitDiffError):
        print("prufgate: could not read trusted Gitleaks configuration", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
