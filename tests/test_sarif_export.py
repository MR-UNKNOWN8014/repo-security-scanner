import json
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from repo_scanner.models.scan_result import Finding, ScanSummary
from repo_scanner.report.exporters import ReportExporter


def _summary(findings=None, cautions=None, scan_root=''):
    return ScanSummary(
        repo_name='demo', repo_url='.', total_files=1, files_analyzed=1, files_skipped=0,
        high_risk_files=0, medium_risk_files=0, low_risk_files=1, safe_files=0,
        overall_risk_score=50.0, findings=findings or [], cautions=cautions or [],
        scan_root=scan_root,
        start_time=datetime.now(), end_time=datetime.now(), scan_duration=0.1, error_count=0,
    )


class TestSarifExport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = str(Path(self.tmp.name) / 'results.sarif')

    def tearDown(self):
        self.tmp.cleanup()

    def _export(self, summary):
        ReportExporter.export_sarif(summary, self.out)
        return json.loads(Path(self.out).read_text(encoding='utf-8'))

    def test_produces_valid_sarif_envelope(self):
        data = self._export(_summary([Finding(file_path='a.py', severity='high', category='secret', description='AWS key', line=4)]))
        self.assertEqual(data['version'], '2.1.0')
        self.assertIn('$schema', data)
        self.assertEqual(data['runs'][0]['tool']['driver']['name'], 'repo-security-scanner')

    def test_severity_maps_to_sarif_level(self):
        data = self._export(_summary([
            Finding(file_path='a.py', severity='critical', category='secret', description='key'),
            Finding(file_path='b.py', severity='medium', category='encoding', description='b64'),
            Finding(file_path='c.py', severity='low', category='dangerous_function', description='eval'),
        ]))
        levels = [r['level'] for r in data['runs'][0]['results']]
        self.assertEqual(levels, ['error', 'warning', 'note'])

    def test_line_number_becomes_a_region(self):
        data = self._export(_summary([Finding(file_path='a.py', severity='high', category='secret', description='key', line=42)]))
        region = data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['region']
        self.assertEqual(region['startLine'], 42)

    def test_missing_line_omits_region_but_keeps_the_file(self):
        data = self._export(_summary([Finding(file_path='a.py', severity='high', category='size', description='too big')]))
        physical = data['runs'][0]['results'][0]['locations'][0]['physicalLocation']
        self.assertNotIn('region', physical)
        self.assertEqual(physical['artifactLocation']['uri'], 'a.py')

    def test_backslashes_are_normalized_on_every_platform(self):
        # PurePath only treats a backslash as a separator on Windows, so this
        # has to be normalized by hand or CI on Linux emits broken URIs
        data = self._export(_summary([Finding(file_path='repo\\sub\\a.py', severity='low', category='network', description='http')]))
        self.assertEqual(data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'], 'repo/sub/a.py')

    def test_absolute_paths_are_made_repo_relative(self):
        # GitHub Code Scanning cannot match an absolute path to a repo file
        root = os.path.join(os.sep, 'tmp', 'clone123')
        data = self._export(_summary(
            [Finding(file_path=os.path.join(root, 'src', 'app.py'), severity='high', category='secret', description='key', line=7)],
            scan_root=root,
        ))
        uri = data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
        self.assertEqual(uri, 'src/app.py')

    def test_path_outside_the_scan_root_is_left_alone(self):
        root = os.path.join(os.sep, 'tmp', 'clone123')
        outside = os.path.join(os.sep, 'etc', 'passwd')
        data = self._export(_summary([Finding(file_path=outside, severity='low', category='size', description='big')], scan_root=root))
        uri = data['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri']
        self.assertTrue(uri.endswith('etc/passwd'))

    def test_cautions_are_included_as_notes(self):
        data = self._export(_summary(cautions=[Finding(file_path='README.md', severity='info', category='long_line', description='long', line=3)]))
        results = data['runs'][0]['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['level'], 'note')

    def test_rule_level_reflects_the_worst_case_not_the_first_finding(self):
        data = self._export(_summary([
            Finding(file_path='a.py', severity='low', category='secret', description='first seen'),
            Finding(file_path='b.py', severity='critical', category='secret', description='worse'),
        ]))
        rule = data['runs'][0]['tool']['driver']['rules'][0]
        self.assertEqual(rule['defaultConfiguration']['level'], 'error')

    def test_each_category_becomes_one_rule(self):
        data = self._export(_summary([
            Finding(file_path='a.py', severity='high', category='secret', description='one'),
            Finding(file_path='b.py', severity='high', category='secret', description='two'),
        ]))
        rules = data['runs'][0]['tool']['driver']['rules']
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['id'], 'secret')


if __name__ == '__main__':
    unittest.main()
