"""Bounded intraprocedural Python exception-return analysis. Never executes source."""
from __future__ import annotations

import ast


def _returns(body):
    """Yield reachable returns; report whether every path terminates."""
    found = []
    for node in body:
        if isinstance(node, ast.Return):
            return [*found, node], True
        if isinstance(node, (ast.Raise, ast.Break, ast.Continue)):
            return found, True
        if isinstance(node, ast.If):
            if isinstance(node.test, ast.Constant):
                branches = [node.body if node.test.value else node.orelse]
            else:
                branches = [node.body, node.orelse]
            outcomes = [_returns(branch) for branch in branches]
            found.extend(ret for returns, _ in outcomes for ret in returns)
            if all(terminal for _, terminal in outcomes):
                return found, True
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            returns, terminal = _returns(node.body)
            found.extend(returns)
            if terminal:
                return found, True
        # Loops and nested try/finally require richer flow. Do not speculate.
    return found, False


def canned_handlers(text: str):
    """Map except lines to full spans with reachable literal success returns.

    None means unsupported syntax: callers retain their existing fallback.
    Calls, nested functions, loops and exception side effects are not modeled.
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None
    matches = {}
    for handler in (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)):
        returns, _ = _returns(handler.body)
        for node in returns:
            value = node.value
            if not isinstance(value, ast.Dict):
                continue
            pairs = [(key.value, val.value) for key, val in zip(value.keys, value.values)
                     if isinstance(key, ast.Constant) and isinstance(val, ast.Constant)]
            if any((key in ('ok', 'success', 'status') and (val is True or isinstance(val, str) and val in ('ok', 'success')))
                   or (key in ('approved', 'authorized', 'authorised', 'verified', 'valid', 'allowed', 'passed') and val is True) for key, val in pairs):
                matches[handler.lineno] = handler.end_lineno
    return matches
