"""External labels, licensing provenance, reproducibility and partial-label scoring."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prufgate import bench, cli, evaluation
from prufgate.evaluation_corpus import build

ROOT = Path(__file__).resolve().parents[1] / 'bench' / 'testdata' / 'independent'


class IndependentCorpus(unittest.TestCase):
    def test_every_case_reproduces_from_pinned_sources_without_running_them(self):
        expected = build(ROOT)
        self.assertEqual(len(expected), 58)
        self.assertEqual(set(expected), {p.name for p in ROOT.glob('*.txt')})
        for name, text in expected.items():
            self.assertEqual((ROOT / name).read_text(), text)
            self.assertTrue(all(path.startswith('src/example.') for path in bench.parse_case(ROOT / name)['head']))
            meta = evaluation.metadata(ROOT / name)
            self.assertTrue(meta['independent'])
            self.assertEqual(meta['reviewers'], [])
            self.assertEqual(meta['label_scope'], 'explicit')
            self.assertEqual(meta['origin'], 'open-source')
            self.assertEqual(len(meta['evidence_manifest_sha256']), 64)

    def test_metadata_keeps_upstream_fixtures_distinct_from_specification_labels(self):
        self.assertEqual(evaluation.metadata(ROOT / 'bandit-pass-001.txt')['label_basis'], 'upstream-fixture')
        self.assertEqual(evaluation.metadata(ROOT / 'bandit-tls-001.txt')['label_basis'], 'upstream-specification')

    def test_changed_code_label_or_profile_cannot_retain_upstream_validation(self):
        for old, new in [('pass\n', 'raise\n'), ('must_fire:', 'removed_label:'), ('profile: core', 'profile: review')]:
            with self.subTest(change=old), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'corpus'
                shutil.copytree(ROOT, root)
                path = root / 'bandit-pass-001.txt'
                path.write_text(path.read_text().replace(old, new))
                with self.assertRaises(bench.CaseError):
                    evaluation.metadata(path)

    def test_license_and_source_tampering_fail_before_scanning(self):
        for relative in ('upstream/bandit-pass.txt', 'licenses/eslint_license.txt'):
            with self.subTest(path=relative), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'corpus'
                shutil.copytree(ROOT, root)
                (root / relative).write_text('Replaced evidence')
                with patch.object(bench, 'fired_rules') as scan, self.assertRaises(bench.CaseError):
                    evaluation.evaluate(root, independent_only=True)
                scan.assert_not_called()

    def test_evidence_path_traversal_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'corpus'
            shutil.copytree(ROOT, root)
            manifest = json.loads((root / 'manifest.json').read_text())
            manifest['sources'][0]['archive'] = '../outside.txt'
            (root / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(bench.CaseError):
                build(root)

    def test_no_fake_reviewer_labels_can_substitute_for_missing_upstream_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'case.txt'
            path.write_text('-- label.yaml --\nevaluation:\n  origin: open-source\n  split: holdout\n  label_basis: upstream-fixture\n-- head/app.py --\nx = 1\n')
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(['evaluate', '--cases', tmp, '--independent-only']), 2)

    def test_upstream_scans_use_the_declared_core_and_review_profiles(self):
        with patch.object(bench, 'fired_rules', return_value=set()) as scan:
            report = evaluation.evaluate(ROOT, independent_only=True)
        self.assertEqual(report['summary']['cases'], 58)
        self.assertEqual(report['profile'], 'mixed')
        self.assertEqual(set(report['groups']['profile']), {'core', 'review'})
        self.assertEqual(set(report['groups']['project']), {'PyCQA/bandit', 'eslint/eslint', 'pmd/pmd'})
        self.assertEqual(sum(bool(c.kwargs) for c in scan.call_args_list), 36)
        self.assertEqual(len(report['implementation_sha256']), 64)
        self.assertNotIn('-- head/', json.dumps(report))

    def test_unlabeled_rules_are_unscored_and_explicit_negatives_still_count(self):
        rows = [{'id': 'fixture', 'category': 'clean', 'must_fire': [], 'must_not_fire': ['target-rule'],
                 'fired': ['other-rule', 'target-rule'], 'label_scope': 'explicit'}]
        report = evaluation.metrics(rows)
        self.assertEqual(report['overall']['fp'], 1)
        self.assertEqual(report['rules']['target-rule']['false_positive_rate'], 1)
        self.assertEqual(report['unscored_findings'], [{'case': 'fixture', 'rule': 'other-rule'}])
        rows[0]['label_scope'] = 'complete'
        self.assertEqual(evaluation.metrics(rows)['overall']['fp'], 2)

    def test_review_profile_runs_deterministic_code_only(self):
        case = bench.parse_case(ROOT / 'bandit-tls-002.txt')
        with bench._no_network(), bench._safe_git_env(), patch('prufgate.review.reviewer.review_diff_with_ai') as ai:
            fired = bench.fired_rules(case, profile='review')
        self.assertIn('pr-disabled-tls-certificate-verification', fired)
        ai.assert_not_called()
        with self.assertRaises(bench.CaseError):
            bench.fired_rules(case, profile='unknown')
