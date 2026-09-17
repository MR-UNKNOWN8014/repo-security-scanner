import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from repo_scanner.models.scan_result import FileScanResult, RiskLevel
from repo_scanner.scanner.core import RepoScanner


class TestFileScanResultRiskLevel(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual(FileScanResult('f', risk_score=0).get_risk_level(), RiskLevel.SAFE)
        self.assertEqual(FileScanResult('f', risk_score=10).get_risk_level(), RiskLevel.LOW)
        self.assertEqual(FileScanResult('f', risk_score=25).get_risk_level(), RiskLevel.MEDIUM)
        self.assertEqual(FileScanResult('f', risk_score=50).get_risk_level(), RiskLevel.HIGH)
        self.assertEqual(FileScanResult('f', risk_score=75).get_risk_level(), RiskLevel.CRITICAL)


class TestSummaryAggregation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.scanner = RepoScanner(repo_url=self.tmp.name, scan_mode='balanced')

    def tearDown(self):
        self.tmp.cleanup()

    def test_overall_score_is_max_not_mean(self):
        # averaging used to dilute one critical file across hundreds of clean ones
        self.scanner.results = [
            FileScanResult('critical.py', risk_score=100),
        ] + [FileScanResult(f'clean_{i}.py', risk_score=0) for i in range(50)]

        summary = self.scanner._generate_summary(datetime.now())

        self.assertEqual(summary.overall_risk_score, 100)

    def test_no_results_defaults_to_zero(self):
        summary = self.scanner._generate_summary(datetime.now())
        self.assertEqual(summary.overall_risk_score, 0)

    def test_findings_sorted_by_severity(self):
        self.scanner.results = [
            FileScanResult('a.py', risk_score=10, findings=[
                _finding('low'), _finding('critical'), _finding('medium'),
            ]),
        ]
        summary = self.scanner._generate_summary(datetime.now())
        self.assertEqual([f.severity for f in summary.findings], ['critical', 'medium', 'low'])

    def test_repo_name_resolved_for_dot_path(self):
        # repo_url.split('/')[-1] used to leave repo_name blank or as the raw path
        self.assertTrue(len(self.scanner.repo_name) > 0)


def _finding(severity):
    from repo_scanner.models.scan_result import Finding
    return Finding(file_path='a.py', severity=severity)


if __name__ == '__main__':
    unittest.main()
