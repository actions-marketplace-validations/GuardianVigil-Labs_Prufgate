"""Offline evaluation with explicit provenance and independently reviewed strata."""
from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path

import yaml

from prufgate import __version__, bench
from prufgate.privacy import redact_data
from prufgate.safe_fs import safe_read_text, safe_write_text


def metadata(path):
    text = safe_read_text(path)
    label = text.split('-- label.yaml --', 1)[-1].split('\n-- ', 1)[0]
    raw = yaml.safe_load(label) or {}
    value = raw.get('evaluation', {})
    if not isinstance(value, dict):
        raise bench.CaseError('evaluation metadata must be a mapping')
    out = {'language': value.get('language', 'unspecified'), 'framework': value.get('framework', 'unspecified'),
           'origin': value.get('origin', 'maintainer'), 'author': value.get('author'),
           'reviewers': value.get('reviewers', []), 'split': value.get('split', 'regression'),
           'profile': value.get('profile', 'core'), 'label_scope': value.get('label_scope', 'complete'),
           'label_basis': value.get('label_basis', 'declared-review')}
    if out['profile'] not in ('core', 'review') or out['label_scope'] not in ('complete', 'explicit'):
        raise bench.CaseError('invalid evaluation profile or label scope')
    for key in ('language', 'framework', 'origin', 'split'):
        if not isinstance(out[key], str) or not out[key].strip():
            raise bench.CaseError('evaluation dimensions must be nonempty strings')
    if out['origin'] not in ('maintainer', 'synthetic', 'open-source') or out['split'] not in ('regression', 'holdout'):
        raise bench.CaseError('invalid evaluation origin or split')
    reviewers = out['reviewers']
    if not isinstance(reviewers, list) or not all(isinstance(x, str) and x.strip() for x in reviewers):
        raise bench.CaseError('reviewers must be explicit review labels')
    author = out['author']
    if author is not None and (not isinstance(author, str) or not author.strip()):
        raise bench.CaseError('author must be an explicit label')
    out['independent'] = bool(author and any(x.strip().casefold() != author.strip().casefold() for x in reviewers))
    if out['label_basis'] in ('upstream-fixture', 'upstream-specification'):
        from prufgate.evaluation_corpus import verify_case
        if out['origin'] != 'open-source' or out['split'] != 'holdout':
            raise bench.CaseError('upstream labels require open-source holdout provenance')
        verify_case(path)
        out['independent'] = True
        out['upstream_labels'] = value['upstream_labels']
        out['evidence_manifest_sha256'] = hashlib.sha256(safe_read_text(path.parent / 'manifest.json').encode()).hexdigest()
    elif out['label_basis'] != 'declared-review' or out['label_scope'] != 'complete':
        raise bench.CaseError('partial labels require reproducible upstream evidence')
    if out['origin'] == 'open-source':
        source = value.get('source', {})
        if not isinstance(source, dict) or not all(isinstance(source.get(k), str) and source[k].strip() for k in ('url', 'revision', 'license', 'permission', 'path')):
            raise bench.CaseError('open-source examples require URL, revision, path, license and permission evidence')
        if not source['url'].startswith('https://') or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', source['revision']):
            raise bench.CaseError('open-source origin requires HTTPS and a pinned full revision')
        out['source'] = source
    out['project'] = out.get('source', {}).get('url', 'local-corpus').removeprefix('https://github.com/')
    out['digest'] = hashlib.sha256(text.encode()).hexdigest()
    if out['language'] == 'unspecified':
        names = re.findall(r'^-- (?:base|head)/(.*?) --$', text, re.MULTILINE)
        languages = { {'.py': 'python', '.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.go': 'go', '.rs': 'rust', '.java': 'java', '.rb': 'ruby', '.cs': 'csharp', '.php': 'php'}.get(Path(name).suffix, 'configuration-or-other') for name in names}
        out['language'] = '+'.join(sorted(languages))
    return out


def metrics(results):
    unscored = []
    scored = []
    for case in results:
        labels = {bench.canon(r) for r in case['must_fire'] + case['must_not_fire']}
        if case.get('label_scope') == 'explicit':
            unscored += [{'case': case['id'], 'rule': r} for r in case['fired'] if bench.canon(r) not in labels]
            case = {**case, 'fired': [r for r in case['fired'] if bench.canon(r) in labels]}
        scored.append(case)
    results = scored
    report = bench.score(results)
    report['unscored_findings'] = unscored
    # Explicit negative opportunities only; absent labels are not true negatives.
    for rule in {bench.canon(r) for c in results for r in c['must_not_fire']}:
        key = next((r for r in report['rules'] if bench.canon(r) == rule), rule)
        row = report['rules'].setdefault(key, {'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None})
        negatives = [c for c in results if rule in {bench.canon(r) for r in c['must_not_fire']}]
        false = sum(rule in {bench.canon(r) for r in c['fired']} for c in negatives)
        row.update(negative_cases=len(negatives), tn=len(negatives) - false,
                   false_positive_rate=bench._ratio(false, len(negatives)))
    for row in report['rules'].values():
        row.setdefault('negative_cases', 0)
        row.setdefault('tn', 0)
        row.setdefault('false_positive_rate', None)
    from prufgate.rules import CONFIDENCE
    positives = {bench.canon(r) for c in results for r in c['must_fire']}
    negatives = {bench.canon(r) for c in results for r in c['must_not_fire']}
    catalog = {bench.canon(r) for r in CONFIDENCE}
    report['coverage'] = {'catalog_rules': len(catalog), 'rules_with_positive_labels': len(positives),
                          'rules_with_negative_labels': len(negatives), 'untested_rules': sorted(catalog - (positives | negatives))}
    return report


def evaluate(directory: Path, independent_only=False):
    cases = bench.load_cases(directory)
    provenance = {c['id']: metadata(directory / (c['id'] + '.txt')) for c in cases}
    if independent_only:
        cases = [c for c in cases if provenance[c['id']]['independent'] and provenance[c['id']]['split'] == 'holdout']
        if not cases:
            raise bench.CaseError('no independently reviewed holdout cases; no independent accuracy claim is available')
    with bench._no_network(), bench._safe_git_env():
        results = [{**c, 'label_scope': provenance[c['id']]['label_scope'],
                    'fired': sorted(bench.fired_rules(c) if provenance[c['id']]['profile'] == 'core'
                                    else bench.fired_rules(c, profile=provenance[c['id']]['profile']))} for c in cases]
    groups = {}
    for dimension in ('language', 'framework', 'origin', 'split', 'independent', 'profile', 'label_basis', 'project'):
        values = sorted({str(provenance[c['id']][dimension]) for c in cases})
        groups[dimension] = {value: metrics([c for c in results if str(provenance[c['id']][dimension]) == value]) for value in values}
    profiles = {provenance[c['id']]['profile'] for c in cases}
    implementation = hashlib.sha256()
    package = Path(__file__).resolve().parent
    for source in sorted(package.rglob('*.py')):
        implementation.update(str(source.relative_to(package)).encode())
        implementation.update(hashlib.sha256(source.read_bytes()).digest())
    report = redact_data({'schema_version': '1.0', 'tool_version': __version__, 'profile': next(iter(profiles)) if len(profiles) == 1 else 'mixed',
                        'method': 'case-rule micro averages; explicit negative denominators; partial upstream labels score only named rules; labels are not authenticated human reviews',
                        'summary': metrics(results), 'groups': groups,
                        'provenance': {c['id']: provenance[c['id']] for c in cases},
                        'limitations': ['Small non-random samples do not establish deployment accuracy.',
                                        'Declared reviewers require human verification; upstream-derived labels verify local evidence, not new human review.',
                                        'Once evaluated, these examples are an exposed external validation set, not a blind holdout for future tuning.',
                                        'No project code, source snippets or absolute workspace paths are exported.']})
    for case in cases:
        report['provenance'][case['id']]['digest'] = provenance[case['id']]['digest']
        if 'source' in provenance[case['id']]:
            report['provenance'][case['id']]['source']['revision'] = provenance[case['id']]['source']['revision']
        if 'evidence_manifest_sha256' in provenance[case['id']]:
            report['provenance'][case['id']]['evidence_manifest_sha256'] = provenance[case['id']]['evidence_manifest_sha256']
    report['implementation_sha256'] = implementation.hexdigest()
    return report


def render(report, fmt):
    if fmt == 'json':
        return json.dumps(report, indent=2)
    rows = []
    for dimension, groups in report['groups'].items():
        for value, group in groups.items():
            for rule, row in group['rules'].items():
                rows.append([dimension, value, rule, group['cases'], row['tp'], row['fp'], row['fn'],
                             row['precision'], row['recall'], row['false_positive_rate'], row['negative_cases']])
    headers = ['Dimension', 'Group', 'Rule', 'Group cases', 'TP', 'FP', 'FN', 'Precision', 'Recall', 'FPR', 'Negative cases']
    note = ('Labels are declared reviews or reproducible upstream evidence, not authenticated new human reviews. '
            'Unmeasured rates are n/a. Coverage means corpus cases, not production coverage. '
            'Explicit-label cases score only named rules; unrelated findings are unscored in JSON.')
    coverage = json.dumps(report.get('summary', {}).get('coverage', {}), indent=2)
    if fmt == 'markdown':
        def cell(value):
            return str(value if value is not None else 'n/a').replace('|', '&#124;').replace('\n', ' ')
        return '\n'.join(['# Rule accuracy', '', note, '', 'Corpus rule coverage:', '', '```json', coverage, '```', '', '| ' + ' | '.join(headers) + ' |', '|' + '---|' * len(headers),
                          *['| ' + ' | '.join(map(cell, row)) + ' |' for row in rows]])
    def cells(row, tag):
        return ''.join(f'<{tag}>{html.escape(str(v if v is not None else "n/a"))}</{tag}>' for v in row)
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
            '<title>PrufGate rule accuracy</title><style>body{font:16px system-ui;margin:2rem}table{border-collapse:collapse}td,th{padding:.5rem;border:1px solid #bbb}input{padding:.5rem;width:22rem}</style>'
            '<h1>Rule accuracy</h1><p>' + html.escape(note) + '</p><details><summary>Corpus rule coverage and untested rules</summary><pre>' + html.escape(coverage) + '</pre></details><label>Filter by rule, language or framework <input id="filter" type="search"></label>'
            '<table><thead><tr>' + cells(headers, 'th') + '</tr></thead><tbody>' + ''.join('<tr>' + cells(row, 'td') + '</tr>' for row in rows) + '</tbody></table>'
            '<script>document.getElementById("filter").addEventListener("input",e=>{const q=e.target.value.toLowerCase();document.querySelectorAll("tbody tr").forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(q))})</script></html>')


def main(args):
    import sys
    try:
        report = evaluate(Path(args.cases), args.independent_only)
        text = render(report, args.format)
        if args.output:
            safe_write_text(Path(args.output), text + '\n')
        else:
            print(text)
        return 0
    except Exception as exc:
        print(f'prufgate evaluate: evaluation failed ({type(exc).__name__})', file=sys.stderr)
        return 2
