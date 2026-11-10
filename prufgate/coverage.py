"""Observe successful scanner input reads without retaining their contents."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Iterator, Optional

_active: ContextVar[Optional["Coverage"]] = ContextVar("prufgate_coverage", default=None)


class Coverage:
    def __init__(self, root: Path, scope: str = "workspace", base: Optional[str] = None):
        self.root = root.resolve()
        self.scope, self.base = scope, base
        self.files: dict[str, int] = {}
        self.engines: list[dict[str, Any]] = []
        self.exclusions: list[dict[str, str]] = []
        self.ranges: Optional[dict] = None

    def read(self, path: Path, content: bytes) -> None:
        try:
            rel = path.resolve().relative_to(self.root).as_posix()
        except (OSError, ValueError):
            return
        if rel.startswith((".git/", "reports/")):
            return
        self.files[rel] = len(content.splitlines())

    def step(self, engine: str, reason: str = "", skipped: bool = False) -> None:
        self.finish()
        self.engines.append({"engine": engine, "status": "skipped" if skipped else "running", "reason": reason})

    def finish(self, error: Optional[str] = None) -> None:
        if self.engines and self.engines[-1]["status"] == "running":
            self.engines[-1].update(status="error" if error else "completed", reason=error or "")

    def to_dict(self) -> dict:
        selected = None
        if self.ranges is not None:
            selected = sum(len({n for start, end in self.ranges.get(path, [])
                                for n in range(max(1, start), min(end, count) + 1)})
                           for path, count in self.files.items())
        return {"scope": self.scope, "base_ref": self.base, "files_checked": len(self.files),
                "lines_checked": sum(self.files.values()), "lines_in_scope": selected,
                "files": [{"file": key, "lines": value} for key, value in sorted(self.files.items())],
                "exclusions": self.exclusions, "engines": self.engines,
                "measurement": "Successful file reads by Python engines, including context and manifests; not runtime test coverage."}


def current() -> Optional[Coverage]:
    return _active.get()


def step(engine: str, reason: str = "", skipped: bool = False) -> None:
    trace = current()
    if trace is not None:
        trace.step(engine, reason, skipped)


def observe(path: Path, content: bytes) -> bytes:
    trace = current()
    if trace is not None:
        trace.read(path, content)
    return content


@contextmanager
def recording(trace: Coverage) -> Iterator[Coverage]:
    token = _active.set(trace)
    try:
        yield trace
    except BaseException as exc:
        trace.finish(exc.__class__.__name__)
        raise
    else:
        trace.finish()
    finally:
        _active.reset(token)


def unavailable(scope: str = "unknown", reason: str = "This integration did not report measured coverage.") -> dict:
    return {"scope": scope, "files_checked": None, "lines_checked": None, "lines_in_scope": None,
            "files": [], "exclusions": [], "engines": [], "measurement": reason}


def merge(reports: list[dict], engines: Optional[list[dict]] = None) -> dict:
    if not reports:
        result = unavailable()
    else:
        result = dict(reports[0])
        files = {entry["file"]: entry for report in reports for entry in report.get("files", [])}
        result.update(files=list(files.values()), files_checked=len(files),
                      lines_checked=sum(entry["lines"] for entry in files.values()), lines_in_scope=None,
                      exclusions=[entry for report in reports for entry in report.get("exclusions", [])],
                      engines=[entry for report in reports for entry in report.get("engines", [])])
    if engines is not None:
        result["engines"] = engines
    return result
