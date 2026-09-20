import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from repo_scanner.config import CAUTION_SEVERITY
from repo_scanner.models.scan_result import FileScanResult, Finding
from repo_scanner.report.formatter import ReportFormatter
from repo_scanner.scanner.core import RepoScanner


class TestCautionSplit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scanner = RepoScanner(repo_url=self.tmp.name, scan_mode='balanced')

    def tearDown(self):
        self.tmp.cleanup()

    def _summarize(self, findings):
        self.scanner.results = [FileScanResult('a.py', risk_score=0, findings=findings)]
        return self.scanner._generate_summary(datetime.now())

    def test_info_findings_go_to_cautions_not_findings(self):
        summary = self._summarize([
            Finding(file_path='a.py', severity='low', category='network', description='HTTP request'),
            Finding(file_path='docs.md', severity=CAUTION_SEVERITY, category='long_line', description='long line: 900 chars'),
        ])
        self.assertEqual(len(summary.findings), 1)
        self.assertEqual(len(summary.cautions), 1)
        self.assertEqual(summary.cautions[0].category, 'long_line')

    def test_cautions_do_not_consume_the_findings_budget(self):
        noise = [Finding(file_path=f'd{i}.md', severity=CAUTION_SEVERITY, category='long_line', description='long') for i in range(60)]
        real = [Finding(file_path='a.py', severity='critical', category='secret', description='AWS key')]
        summary = self._summarize(noise + real)
        self.assertEqual(len(summary.findings), 1)
        self.assertEqual(summary.findings[0].category, 'secret')

    def test_to_dict_counts_them_separately(self):
        summary = self._summarize([
            Finding(file_path='a.py', severity='low', category='network', description='HTTP request'),
            Finding(file_path='docs.md', severity=CAUTION_SEVERITY, category='long_line', description='long'),
        ])
        data = summary.to_dict()
        self.assertEqual(data['findings_count'], 1)
        self.assertEqual(data['cautions_count'], 1)

    def test_detailed_report_shows_a_separate_cautions_section(self):
        summary = self._summarize([
            Finding(file_path='docs.md', severity=CAUTION_SEVERITY, category='long_line', description='long line: 900 chars', line=3),
        ])
        out = ReportFormatter.format_detailed(summary, show_findings=True)
        self.assertIn('CAUTIONS', out)
        self.assertIn('docs.md:3', out)
        self.assertNotIn('TOP FINDINGS', out)


class TestVersionSource(unittest.TestCase):
    def test_version_comes_from_package_metadata_not_a_hardcoded_string(self):
        # config must not drift from pyproject.toml, so it reads dist metadata
        source = Path('repo_scanner/config.py').read_text(encoding='utf-8')
        self.assertIn('importlib.metadata', source)
        from repo_scanner.config import __version__
        self.assertTrue(__version__)


if __name__ == '__main__':
    unittest.main()
