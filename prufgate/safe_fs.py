"""File access that does not follow repository-controlled links.

Reads reject symlinks in every component by default. An explicit trusted root
allows links only when their resolved target stays inside it. Writes replace
the destination atomically (including a planted file link or hard link), and
never follow directory links. POSIX uses directory descriptors to prevent
directory substitution races; other systems verify the opened file before read.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from prufgate.coverage import observe

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIR_FD = bool(_NOFOLLOW) and os.open in os.supports_dir_fd and hasattr(os, "O_DIRECTORY")


def _absolute(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    # macOS exposes the system temporary directory through /var -> /private/var.
    # Trust that OS-selected prefix, never a repository-controlled suffix.
    tmp = Path(tempfile.gettempdir()).absolute()
    if path.is_relative_to(tmp):
        path = tmp.resolve() / path.relative_to(tmp)
    return path


def output_path(path: Path, workspace: Path) -> Path:
    """Physical form of an operator-chosen output path.

    Links above the workspace, or anywhere on a path outside it, belong to the
    operator (macOS /tmp, /home -> /var/home) and are resolved. From the first
    directory that resolves into the workspace on, components are kept as
    written, so the writer (which never follows links) refuses links there.
    """
    if ".." in Path(path).parts:
        raise OSError("refusing '..' in an output path")
    path, real = Path(os.path.abspath(path)), Path(workspace).resolve()
    if path.is_symlink():
        raise OSError("refusing to write through a symlink")
    for i in range(1, len(path.parts)):
        prefix = Path(os.path.realpath(Path(*path.parts[:i])))
        if prefix.is_relative_to(real):
            return prefix.joinpath(*path.parts[i:])
    return Path(os.path.realpath(path.parent)) / path.name


@contextmanager
def _parent(path: Path, create: bool = False) -> Iterator[tuple[Path, Optional[int]]]:
    path = _absolute(path)
    if _DIR_FD:
        fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                if create:
                    try:
                        os.mkdir(part, mode=0o755, dir_fd=fd)
                    except FileExistsError:
                        pass
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = nxt
            yield path, fd
        finally:
            os.close(fd)
    else:
        current = Path(path.anchor)
        for part in path.parts[1:-1]:
            current /= part
            if current.is_symlink():
                raise OSError("refusing a symlinked directory")
            if create:
                current.mkdir(exist_ok=True)
        yield path, None


def safe_read_bytes(path: Path, *, root: Optional[Path] = None) -> bytes:
    path = _absolute(path)
    if root is not None:
        base = Path(root).resolve(strict=True)
        path = path.resolve(strict=True)
        if not path.is_relative_to(base):
            raise OSError("refusing to read outside the workspace")
    with _parent(path) as (target, parent):
        if target.is_symlink():
            raise OSError("refusing to read a symlink")
        flags = os.O_RDONLY | _NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(target.name if parent is not None else target, flags,
                     **({"dir_fd": parent} if parent is not None else {}))
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode):
                raise OSError("refusing to read a non-regular file")
            if parent is None:
                real = target.resolve(strict=True)
                there = target.stat()
                if real != target or (opened.st_dev, opened.st_ino) != (there.st_dev, there.st_ino):
                    raise OSError("file changed while opening")
            with os.fdopen(fd, "rb") as fh:
                fd = -1
                return observe(path, fh.read())
        finally:
            if fd >= 0:
                os.close(fd)


def safe_read_text(path: Path, encoding: str = "utf-8", errors: str = "strict", *,
                   root: Optional[Path] = None) -> str:
    # Match Path.read_text's universal newline handling on every platform.
    return safe_read_bytes(path, root=root).decode(encoding, errors).replace("\r\n", "\n").replace("\r", "\n")


def safe_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    with _parent(path, create=True) as (target, parent):
        name = ".prufgate-" + secrets.token_hex(12)
        kwargs = {"dir_fd": parent} if parent is not None else {}
        temporary = name if parent is not None else target.parent / name
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, **kwargs)
        try:
            with os.fdopen(fd, "w", encoding=encoding) as fh:
                fh.write(text)
            if parent is not None:
                os.replace(name, target.name, src_dir_fd=parent, dst_dir_fd=parent)
            else:
                if target.parent.resolve() != target.parent:
                    raise OSError("refusing a symlinked directory")
                os.replace(temporary, target)
        finally:
            try:
                os.unlink(temporary, **kwargs)
            except FileNotFoundError:
                pass


def safe_remove_tree(path: Path) -> None:
    """Remove an artifact directory without following directory or file links."""
    def remove(name: str, parent: int) -> None:
        try:
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(info.st_mode):
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW, dir_fd=parent)
            try:
                for child in os.listdir(fd):
                    remove(child, fd)
            finally:
                os.close(fd)
            os.rmdir(name, dir_fd=parent)
        else:
            os.unlink(name, dir_fd=parent)

    try:
        with _parent(path) as (target, parent):
            if parent is not None:
                remove(target.name, parent)
            elif target.is_symlink():
                target.unlink()
            elif target.exists():
                shutil.rmtree(target)
    except FileNotFoundError:
        pass


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    """An exclusive local mutation lock; existing locks are never silently removed."""
    with _parent(path, create=True) as (target, parent):
        options = {"dir_fd": parent} if parent is not None else {}
        name = target.name if parent is not None else target
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, **options)
        try:
            yield
        finally:
            os.close(fd)
            os.unlink(name, **options)
