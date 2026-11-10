"""Evidence integrity, syntax near misses and static cross-file relationships."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_review_workflow import commit, git

from prufgate import bench, cli, evaluation, repo_runner
from prufgate.anti_fabrication import detector
from prufgate.change_impact import analyze
from prufgate.python_flow import canned_handlers


class PythonFlow(unittest.TestCase):
    def test_multiline_and_async_returns_have_full_spans(self):
        text = 'async def run():\n    try:\n        return await work()\n    except ValueError:\n        return {\n            "ok": True\n        }\n'
        self.assertEqual(canned_handlers(text), {4: 7})
        self.assertIn('canned-error-fallback', [f.rule for f in detector.scan_text('app.py', '.py', text)])
        multiline = text.replace('except ValueError:', 'except (\n        ValueError,\n        RuntimeError,\n    ):')
        self.assertIn('canned-error-fallback', [f.rule for f in detector.scan_text('app.py', '.py', multiline)])

    def test_strings_nested_functions_and_unreachable_returns_are_not_success(self):
        for body in ('raise\n        return {"ok": True}', 'def helper():\n            return {"ok": True}\n        raise',
                     'if False:\n            return {"ok": True}\n        raise',
                     'message = \'return {"ok": True}\'\n        raise RuntimeError(message)'):
            text = 'def run():\n    try:\n        return work()\n    except ValueError:\n        ' + body + '\n'
            with self.subTest(body=body):
                self.assertEqual(canned_handlers(text), {})
                self.assertNotIn('canned-error-fallback', [f.rule for f in detector.scan_text('app.py', '.py', text)])

    def test_both_terminal_branches_end_flow_but_conditional_returns_are_detected(self):
        text = 'try:\n    work()\nexcept ValueError:\n    if condition:\n        raise\n    else:\n        raise\n    return {"ok": True}\n'
        self.assertEqual(canned_handlers(text), {})
        self.assertEqual(canned_handlers(text.replace('        raise\n    else:', '        return {"ok": True}\n    else:')), {3: 8})
        self.assertIsNone(canned_handlers('try:'))


class Evaluation(unittest.TestCase):
    def test_independent_holdout_filter_uses_declared_review_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            text = Path('bench/evaluation/async-reraise.txt').read_text()
            text = text.replace('reviewers: []', 'reviewers: [independent-reviewer-role]').replace('split: regression', 'split: holdout')
            (Path(tmp) / 'reviewed-fixture.txt').write_text(text)
            with patch.object(bench, 'fired_rules', return_value=set()):
                report = evaluation.evaluate(Path(tmp), independent_only=True)
            self.assertEqual(report['groups']['independent']['True']['cases'], 1)
            self.assertEqual(len(report['provenance']['reviewed-fixture']['digest']), 64)

    def test_explicit_negative_denominators_and_unmeasured_rates(self):
        report = evaluation.metrics([{'id': 'fixture', 'category': 'clean', 'must_fire': [], 'must_not_fire': ['rule'], 'fired': []}])
        self.assertEqual(report['rules']['rule']['tn'], 1)
        self.assertEqual(report['rules']['rule']['false_positive_rate'], 0)
        self.assertIsNone(report['rules']['rule']['precision'])
        self.assertIsNone(report['rules']['rule']['recall'])

    def test_seed_corpus_is_not_presented_as_independent(self):
        with self.assertRaises(bench.CaseError):
            evaluation.evaluate(Path('bench/evaluation'), independent_only=True)

    def test_corpus_runs_offline_and_has_language_framework_and_rule_groups(self):
        report = evaluation.evaluate(Path('bench/evaluation'))
        self.assertEqual(report['summary']['cases'], 12)
        self.assertEqual(set(report['groups']['language']), {'python', 'javascript', 'typescript'})
        self.assertEqual(report['groups']['independent']['False']['cases'], 12)
        self.assertNotIn('base', report['provenance']['async-success'])
        self.assertEqual(report['summary']['overall']['fp'], 0)
        self.assertEqual(report['summary']['overall']['fn'], 0)
        page = evaluation.render(report, 'html')
        self.assertIn('type="search"', page)
        self.assertNotIn('https://', page)

    def test_open_source_permission_fields_and_reviewer_identity_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'case.txt'
            path.write_text('-- label.yaml --\nevaluation:\n  origin: open-source\n-- head/app.py --\nx = 1\n')
            with self.assertRaises(bench.CaseError):
                evaluation.metadata(path)
            path.write_text('-- label.yaml --\nevaluation:\n  author: reviewer-role\n  reviewers: [" REVIEWER-ROLE "]\n  split: holdout\n-- head/app.py --\nx = 1\n')
            self.assertFalse(evaluation.metadata(path)['independent'])

    def test_html_escapes_label_values(self):
        report = {'groups': {'language': {'<script>': {'cases': 1, 'rules': {'<img>': {'tp': 0, 'fp': 0, 'fn': 0, 'precision': None, 'recall': None, 'false_positive_rate': None, 'negative_cases': 0}}}}}}
        page = evaluation.render(report, 'html')
        self.assertIn('&lt;img&gt;', page)
        self.assertNotIn('<img>', page)

    def test_cli_engine_crashes_are_errors_and_reports_have_no_source(self):
        with patch.object(bench, 'fired_rules', side_effect=RuntimeError('fixture')), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['evaluate', '--cases', 'bench/evaluation']), 2)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['evaluate', '--cases', 'bench/evaluation', '--independent-only']), 2)


class Impact(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        git(self.root, 'init', '-q')
        for name, text in {'schema.py': 'class Record:\n    pass\n', 'service.py': 'from schema import Record\ndef run():\n    return Record()\n',
                           'caller.py': 'import service as worker\nworker.run()\n',
                           'test_service.py': 'from caller import worker\n',
                           'settings.json': '{}\n', 'config_reader.py': 'open("settings.json")\n',
                           'route.py': '@app.get("/items")\ndef items():\n    return []\n',
                           'client.py': 'client.get("/items")\n'}.items():
            (self.root / name).write_text(text)
        self.base = commit(self.root)

    def test_schema_changes_reach_implementation_callers_and_tests(self):
        (self.root / 'schema.py').write_text('class Record:\n    field: int\n')
        result = analyze(self.root, self.base)
        self.assertEqual(result['analysis_status'], 'complete')
        self.assertTrue({'service.py', 'caller.py', 'test_service.py'} <= set(result['affected']))
        self.assertTrue(any(e['kind'] == 'call' and e['symbol'] == 'worker.run' for e in result['relationships']))
        self.assertNotIn(str(self.root), json.dumps(result))

    def test_literal_routes_and_configuration_changes_reach_their_consumers(self):
        (self.root / 'route.py').write_text('@app.get("/items")\ndef items():\n    return [1]\n')
        (self.root / 'settings.json').write_text('{"mode": "selected"}\n')
        result = analyze(self.root, self.base)
        self.assertIn('client.py', result['affected'])
        self.assertIn('config_reader.py', result['affected'])

    def test_deleted_implementation_still_reaches_importing_callers(self):
        (self.root / 'service.py').unlink()
        result = analyze(self.root, self.base)
        self.assertIn('service.py', result['changed'])
        self.assertIn('caller.py', result['affected'])
        git(self.root, 'add', '-A')
        self.assertIn('caller.py', analyze(self.root, self.base)['affected'])

    def test_parse_errors_and_limits_are_explicitly_incomplete(self):
        (self.root / 'caller.py').write_text('def broken(')
        result = analyze(self.root, self.base)
        self.assertEqual(result['analysis_status'], 'incomplete')
        self.assertTrue(result['coverage']['skipped'])
        with patch('prufgate.change_impact.LIMIT', 1):
            self.assertTrue(analyze(self.root, self.base)['coverage']['truncated'])

    def test_symlinks_are_never_followed(self):
        (self.root / 'link.py').symlink_to(self.root / 'service.py')
        self.assertEqual(analyze(self.root, self.base)['analysis_status'], 'incomplete')


class ProcfsCompatibility(unittest.TestCase):
    def test_missing_task_children_falls_back_to_kernel_parent_ids(self):
        def read(path, **kwargs):
            if path.endswith('/children'):
                raise FileNotFoundError('alternate procfs')
            return io.StringIO('Name:\tfixture\nPPid:\t' + ('42' if '/43/' in path else '1') + '\n')
        with patch.object(repo_runner.os, 'listdir', side_effect=[['42'], ['42', '43', 'self']]), patch('builtins.open', side_effect=read):
            self.assertEqual(repo_runner._children(42), {43})
