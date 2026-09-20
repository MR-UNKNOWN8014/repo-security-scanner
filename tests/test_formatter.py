import unittest
from datetime import datetime
from repo_scanner.models.scan_result import Finding, ScanSummary
from repo_scanner.report.formatter import ReportFormatter


def _summary(findings):
    return ScanSummary(
        repo_name='demo', repo_url='.', total_files=1, files_analyzed=1, files_skipped=0,
        high_risk_files=0, medium_risk_files=0, low_risk_files=1, safe_files=0,
        overall_risk_score=10.0, findings=findings, start_time=datetime.now(),
        end_time=datetime.now(), scan_duration=0.1, error_count=0,
    )


class TestFindingLocationDisplay(unittest.TestCase):
    def test_file_path_shows_even_without_a_line_number(self):
        # the guard used to be "if finding.line", which dropped the path too
        s = _summary([Finding(file_path='repo/app.py', category='encoding', description='Base64 strings: 4')])
        out = ReportFormatter.format_detailed(s, show_findings=True)
        self.assertIn('repo/app.py', out)

    def test_file_and_line_show_together_when_line_is_present(self):
        s = _summary([Finding(file_path='repo/app.py', category='secret', description='AWS key', line=42)])
        out = ReportFormatter.format_detailed(s, show_findings=True)
        self.assertIn('repo/app.py:42', out)


if __name__ == '__main__':
    unittest.main()
