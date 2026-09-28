import unittest
from repo_scanner.models.scan_result import RiskLevel, risk_level_for
from repo_scanner.report.formatter import ReportFormatter


class TestProgressBarIsAscii(unittest.TestCase):
    def test_bar_is_ascii_only(self):
        # block characters crashed a cp1252 Windows console, so every scan
        # exited as a tool error on a default terminal
        for score in (0, 1, 23.5, 50, 99.9, 100):
            bar = ReportFormatter._get_progress_bar(score, 20)
            bar.encode('ascii')
            self.assertEqual(len(bar), 20)

    def test_bar_handles_out_of_range_scores(self):
        self.assertEqual(len(ReportFormatter._get_progress_bar(150, 20)), 20)
        self.assertEqual(len(ReportFormatter._get_progress_bar(-5, 20)), 20)


class TestStatusAndRecommendationAgree(unittest.TestCase):
    def test_low_risk_is_not_advertised_as_safe_to_clone(self):
        # the recommendation ladder used to be one band off, so a LOW RISK
        # repository was labelled SAFE TO CLONE
        self.assertEqual(risk_level_for(15), RiskLevel.LOW)
        self.assertEqual(ReportFormatter._get_status(15), 'LOW RISK')
        self.assertEqual(ReportFormatter._get_recommendation(15), 'REVIEW BEFORE CLONING')

    def test_medium_risk_gets_its_own_recommendation(self):
        self.assertEqual(ReportFormatter._get_status(30), 'MEDIUM RISK')
        self.assertEqual(ReportFormatter._get_recommendation(30), 'EXERCISE CAUTION')

    def test_every_band_has_a_distinct_status_and_recommendation(self):
        scores = {RiskLevel.SAFE: 0, RiskLevel.LOW: 10, RiskLevel.MEDIUM: 25, RiskLevel.HIGH: 50, RiskLevel.CRITICAL: 75}
        statuses = {ReportFormatter._get_status(s) for s in scores.values()}
        recommendations = {ReportFormatter._get_recommendation(s) for s in scores.values()}
        self.assertEqual(len(statuses), 5)
        self.assertEqual(len(recommendations), 5)

    def test_status_matches_the_shared_band_definition(self):
        for score in (0, 9, 10, 24, 25, 49, 50, 74, 75, 100):
            level = risk_level_for(score)
            expected = {'safe': 'SAFE', 'low': 'LOW RISK', 'medium': 'MEDIUM RISK', 'high': 'HIGH RISK', 'critical': 'CRITICAL'}[level.value]
            self.assertEqual(ReportFormatter._get_status(score), expected)


if __name__ == '__main__':
    unittest.main()
