import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from main import export_reports
from repo_scanner.models.scan_result import Finding, ScanSummary


def _summary():
    return ScanSummary(
        repo_name='demo', repo_url='.', total_files=1, files_analyzed=1, files_skipped=0,
        high_risk_files=0, medium_risk_files=0, low_risk_files=1, safe_files=0,
        overall_risk_score=30.0,
        findings=[Finding(file_path='a.py', severity='medium', category='secret', description='key', line=3)],
        total_findings=1, scan_root='',
        start_time=datetime.now(), end_time=datetime.now(), scan_duration=0.1, error_count=0,
    )


class TestExportReports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_paths_writes_nothing(self):
        self.assertEqual(export_reports(_summary(), None), [])
        self.assertEqual(export_reports(_summary(), []), [])

    def test_one_scan_writes_every_requested_format(self):
        # the action needs JSON for its outputs and SARIF for Code Scanning,
        # from a single scan rather than cloning the repo twice
        paths = [self.dir / 'r.json', self.dir / 'r.sarif', self.dir / 'r.csv']
        messages = export_reports(_summary(), [str(p) for p in paths])
        self.assertEqual(len(messages), 3)
        for p in paths:
            self.assertTrue(p.exists(), p)
        self.assertEqual(json.loads(paths[1].read_text(encoding='utf-8'))['version'], '2.1.0')

    def test_unsupported_extension_is_reported_not_silent(self):
        messages = export_reports(_summary(), [str(self.dir / 'r.txt')])
        self.assertEqual(len(messages), 1)
        self.assertIn('Unsupported output format', messages[0])
        self.assertFalse((self.dir / 'r.txt').exists())

    def test_extension_matching_is_case_insensitive(self):
        out = self.dir / 'R.JSON'
        messages = export_reports(_summary(), [str(out)])
        self.assertIn('Report saved to', messages[0])
        self.assertTrue(out.exists())

    def test_one_bad_path_does_not_stop_the_others(self):
        good = self.dir / 'good.json'
        bad = self.dir / 'missing-dir' / 'bad.json'
        messages = export_reports(_summary(), [str(bad), str(good)])
        self.assertIn('Failed to save report', messages[0])
        self.assertIn('Report saved to', messages[1])
        self.assertTrue(good.exists())


if __name__ == '__main__':
    unittest.main()
