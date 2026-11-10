"""Read-only Python import/call and literal-route change impact graph."""
from __future__ import annotations

import ast
from collections import deque
from pathlib import Path

from prufgate import diff_scope
from prufgate.config import _diff_base, _git
from prufgate.safe_fs import safe_read_text

LIMIT = 500


def analyze(root: Path, base: str):
    root = root.resolve()
    if _git(['rev-parse', '--show-prefix'], root).strip():
        raise ValueError('impact requires a repository root')
    changed = set(diff_scope.changed_lines(base, root))
    base = _diff_base(base, root)
    changed.update(_git(['diff', '--name-only', '-z', base], root).split('\0'))
    changed.discard('')
    paths = sorted((set(_git(['ls-files', '-c', '-o', '--exclude-standard', '-z'], root).split('\0')) | changed) - {''})
    candidates = [p for p in paths if p.endswith('.py') and not any(part in {'.git', '.venv', 'venv', 'node_modules', 'vendor', 'reports', 'build', 'dist'} for part in Path(p).parts)]
    skipped, trees, modules, edges = [], {}, {}, []
    for path in candidates[:LIMIT]:
        name = path[:-3].replace('/', '.')
        if name.endswith('.__init__'):
            name = name[:-9]
        modules.setdefault(name, []).append(path)
        if name.startswith('src.'):
            modules.setdefault(name[4:], []).append(path)
        if not (root / path).exists() and not (root / path).is_symlink():
            continue  # A deleted tracked module remains a known dependency target.
        try:
            if (root / path).is_symlink():
                raise ValueError('symlink')
            text = safe_read_text(root / path, root=root)
            if len(text) > 1000000:
                skipped.append({'file': path, 'reason': 'Source exceeds 1 MB analysis limit'})
                continue
            trees[path] = ast.parse(text)
        except (OSError, ValueError, SyntaxError, RecursionError):
            skipped.append({'file': path, 'reason': 'Unreadable or unsupported Python syntax'})
            continue
    def resolve(name):
        choices = set(modules.get(name, []))
        return next(iter(choices)) if len(choices) == 1 else None
    def link(source, target, kind, symbol, line):
        if target and source != target:
            edges.append({'from': source, 'to': target, 'kind': kind, 'symbol': symbol, 'line': line})
    routes, clients = {}, []
    for path, tree in trees.items():
        bindings = {}
        package = path[:-3].replace('/', '.').split('.')[:-1]
        if path.endswith('/__init__.py'):
            package = path[:-12].replace('/', '.').split('.')
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    target = resolve(alias.name)
                    bindings[alias.asname or alias.name.split('.')[0]] = target
                    link(path, target, 'import', alias.name, node.lineno)
            elif isinstance(node, ast.ImportFrom):
                prefix = package[:len(package) - node.level + 1] if node.level else []
                module = '.'.join([*prefix, *([node.module] if node.module else [])])
                for alias in node.names:
                    target = resolve(module + '.' + alias.name) or resolve(module)
                    bindings[alias.asname or alias.name] = target
                    link(path, target, 'import', module + '.' + alias.name, node.lineno)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in ('route', 'get', 'post', 'put', 'patch', 'delete') and dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
                        routes.setdefault(dec.args[0].value, []).append(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            head = func
            while isinstance(head, ast.Attribute):
                head = head.value
            if isinstance(head, ast.Name):
                link(path, bindings.get(head.id), 'call', ast.unparse(func), node.lineno)
            if isinstance(func, ast.Attribute) and func.attr in ('get', 'post', 'put', 'patch', 'delete') and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                clients.append((path, node.args[0].value, node.lineno))
            if isinstance(func, ast.Name) and func.id == 'open' and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                name = node.args[0].value
                if name in paths and Path(name).suffix in ('.json', '.yaml', '.yml', '.toml', '.ini'):
                    link(path, name, 'configuration', name, node.lineno)
    for path, route, line in clients:
        # Static same-path relationships only; no URL normalization or dynamic templates.
        for target in routes.get(route, []):
            link(path, target, 'route', route, line)
    reverse = {}
    for edge in edges:
        reverse.setdefault(edge['to'], set()).add(edge['from'])
    queue, affected = deque(sorted(changed)), set(changed)
    while queue:
        for caller in sorted(reverse.get(queue.popleft(), [])):
            if caller not in affected:
                affected.add(caller)
                queue.append(caller)
    incomplete = bool(skipped or len(candidates) > LIMIT)
    return {'schema_version': '1.0', 'analysis_status': 'incomplete' if incomplete else 'complete',
            'changed': sorted(changed), 'affected': sorted(affected - changed),
            'relationships': sorted(edges, key=lambda e: (e['from'], e['line'], e['to'], e['kind'])),
            'coverage': {'python_files_analyzed': len(trees), 'python_files_discovered': len(candidates), 'limit': LIMIT,
                         'skipped': skipped, 'truncated': len(candidates) > LIMIT},
            'limitations': ['Static relationships are review leads, not proof of a runtime defect.',
                            'Python only; dynamic imports, alias shadowing, runtime dispatch and generated code are unresolved.',
                            'Tests and schema classes connect through imports; literal routes ignore methods and dynamic path parameters.',
                            'Configuration relationships cover literal open calls; paths are workspace-relative, runtime CWD is unknown.']}
