"""Rebuild externally labeled cases offline without executing upstream code."""
from __future__ import annotations

import ast
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

from prufgate.bench import CaseError
from prufgate.safe_fs import safe_read_text


def _read(root, relative):
    if not isinstance(relative, str) or Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise CaseError('invalid corpus evidence path')
    return safe_read_text(root / relative, root=root)


def _digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _samples(source, text):
    """Yield (selector, code, expected, framework, profile, rule, explanation)."""
    if source['id'] == 'bandit-pass':
        # The fixture's own good/bad comments are independent of PrufGate.
        for i, match in enumerate(re.finditer(r'^# (bad|good|silly, but ok)\n(.*?)(?=^# |\Z)', text, re.M | re.S), 1):
            yield (f'example block {i}: {match[1]}', match[2].strip() + '\n', match[1] == 'bad', 'none', 'core', 'unhandled-empty-catch',
                   'Bandit B110 fixture comments; typed exceptions follow its check_typed_exception=True interpretation. Case-rule presence, not finding counts.')
    elif source['id'] == 'eslint-empty':
        valid, invalid = text.split('valid: [', 1)[1].split('invalid: [', 1)
        # Only standalone default-option valid strings. Object cases with
        # allowEmptyCatch are excluded before any detector output is observed.
        index = 0
        for line in valid.splitlines():
            match = re.fullmatch(r'\s*("(?:[^"\\]|\\.)*"),\s*', line)
            if match:
                code = json.loads(match[1])
                if 'catch' in code:
                    index += 1
                    yield (f'valid default string {index}', code + '\n', False, 'none', 'core', 'unhandled-empty-catch',
                           'ESLint no-empty valid fixture, default options; comment-only recovery is accepted upstream.')
        # Find each top-level invalid case object with balanced braces, ignoring
        # braces in quoted strings. No evaluation of JS and no require/import.
        depth, start, quote, escape = 0, None, None, False
        for pos, char in enumerate(invalid):
            if quote:
                if escape:
                    escape = False
                elif char == '\\':
                    escape = True
                elif char == quote:
                    quote = None
                continue
            if char in '\"\'`':
                quote = char
            elif char == '{':
                if depth == 0:
                    start = pos
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0 and start is not None:
                    block = invalid[start:pos + 1]
                    match = re.search(r'\bcode:\s*("(?:[^"\\]|\\.)*")', block)
                    if match and 'options:' not in block:
                        code = json.loads(match[1])
                        # Other no-empty failures (empty try/finally) do not
                        # supply ground truth for this catch-specific rule.
                        if re.search(r'catch\s*\([^)]*\)\s*\{\s*\}', code):
                            index += 1
                            yield (f'invalid default catch {index}', code + '\n', True, 'none', 'core', 'unhandled-empty-catch',
                                   'ESLint no-empty invalid fixture with an empty catch under default options.')
    elif source['id'] == 'pmd-empty':
        tree = ET.fromstring(text)
        ns = {'p': 'http://pmd.sourceforge.net/rule-tests'}
        fragments = {node.attrib['id']: node.text for node in tree.findall('p:code-fragment', ns)}
        for i, node in enumerate(tree.findall('p:test-code', ns), 1):
            if node.find('p:rule-property', ns) is not None:
                continue
            code_node = node.find('p:code', ns)
            code = code_node.text if code_node is not None else fragments[node.find('p:code-ref', ns).attrib['id']]
            count = int(node.findtext('p:expected-problems', namespaces=ns))
            desc = node.findtext('p:description', namespaces=ns)
            yield (f'test-code {i}: {desc}', code.strip() + '\n', count > 0, 'none', 'core', 'unhandled-empty-catch',
                   'PMD EmptyCatchBlock expected-problems with default properties; upstream naming/comment exceptions are retained. Case-rule presence only.')
    elif source['id'] == 'bandit-tls':
        tree = ast.parse(text)
        for node in tree.body:
            if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                continue
            call = node.value
            if not isinstance(call.func, ast.Attribute) or not isinstance(call.func.value, ast.Name):
                raise CaseError('unrecognized upstream TLS fixture form')
            framework = call.func.value.id
            verify = next((kw.value for kw in call.keywords if kw.arg == 'verify'), None)
            if verify is not None and not isinstance(verify, ast.Constant):
                raise CaseError('TLS verification label is not literal')
            expected = verify is not None and verify.value is False
            code = f'import {framework}\n' + ast.get_source_segment(text, node) + '\n'
            yield (f'call at archived line {node.lineno}', code, expected, framework, 'review', 'pr-disabled-tls-certificate-verification',
                   'Bandit B501 independently authored predicate: supported requests/httpx calls with literal verify=False are positive; enabled/default verification is negative. No comment-group label is inferred.')


def build(root: Path):
    manifest = json.loads(_read(root, 'manifest.json'))
    if manifest.get('version') != 1 or not isinstance(manifest.get('sources'), list):
        raise CaseError('invalid independent corpus manifest')
    outputs, seen = {}, {}
    for source in manifest['sources']:
        text = _read(root, source['archive'])
        license_text = _read(root, source['license_file'])
        if _digest(text) != source['archive_sha256'] or _digest(license_text) != source['license_sha256']:
            raise CaseError('independent corpus source/license digest mismatch')
        if not re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', source['revision']) or not source['url'].startswith('https://github.com/'):
            raise CaseError('independent corpus sources require pinned public revisions')
        for index, (selector, code, positive, framework, profile, rule, mapping) in enumerate(_samples(source, text), 1):
            suffix = 'js' if source['id'].startswith('eslint') else 'java' if source['id'].startswith('pmd') else 'py'
            key = (profile, rule, _digest(code.strip()))
            if key in seen:
                if seen[key] != positive:
                    raise CaseError('contradictory duplicate upstream labels')
                continue
            seen[key] = positive
            case_id = f"{source['id']}-{index:03d}"
            label = {'category': 'clean' if not positive else 'fabrication', 'description': mapping,
                     'must_fire': [rule] if positive else [], 'must_not_fire': [] if positive else [rule],
                     'evaluation': {'language': {'py': 'python', 'js': 'javascript', 'java': 'java'}[suffix],
                                    'framework': framework, 'profile': profile, 'origin': 'open-source', 'split': 'holdout',
                                    'author': 'PrufGate corpus adapter', 'reviewers': [],
                                    'label_basis': 'upstream-specification' if source['id'] == 'bandit-tls' else 'upstream-fixture',
                                    'label_scope': 'explicit', 'upstream_labels': {'manifest': 'manifest.json', 'case': case_id,
                                                                             'selector': selector, 'source_id': source['id']},
                                    'source': {'url': source['url'], 'revision': source['revision'], 'path': source['path'],
                                               'license': source['license'], 'permission': f"Pinned upstream license; retained in {source['license_file']}",
                                               'modifications': [*source['modifications'], 'Extracted standalone example into an added-file diff; labels mapped to PrufGate rule IDs.'],
                                               'archive_sha256': source['archive_sha256'], 'license_sha256': source['license_sha256']}}}
            label['evaluation']['source']['upstream_sha256'] = source['upstream_sha256']
            notice = '# Extracted/modified for PrufGate evaluation; upstream notices and licenses are retained beside this corpus.\n'
            outputs[case_id + '.txt'] = notice + '-- label.yaml --\n' + yaml.safe_dump(label, sort_keys=False, width=1000) + f'-- head/src/example.{suffix} --\n' + code
    if not outputs:
        raise CaseError('no independently labeled examples were extracted')
    return outputs


def verify_case(path: Path):
    expected = build(path.parent).get(path.name)
    if expected is None or safe_read_text(path) != expected:
        raise CaseError('independent case differs from its frozen upstream derivation')
    return True
