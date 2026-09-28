import unittest
from main import exceeds_threshold
from repo_scanner.config import EXIT_ERROR, EXIT_OK, EXIT_THRESHOLD, RISK_THRESHOLDS
from repo_scanner.models.scan_result import RiskLevel, risk_level_for


class TestFailOnThreshold(unittest.TestCase):
    def test_none_never_fails(self):
        self.assertFalse(exceeds_threshold(100.0, 'none'))
        self.assertFalse(exceeds_threshold(0.0, 'none'))

    def test_score_at_the_threshold_fails(self):
        # the band is inclusive, matching risk_level_for
        self.assertTrue(exceeds_threshold(50.0, 'high'))
        self.assertTrue(exceeds_threshold(75.0, 'critical'))

    def test_score_below_the_threshold_passes(self):
        self.assertFalse(exceeds_threshold(49.9, 'high'))
        self.assertFalse(exceeds_threshold(74.9, 'critical'))

    def test_stricter_threshold_fails_earlier(self):
        score = 30.0
        self.assertTrue(exceeds_threshold(score, 'low'))
        self.assertTrue(exceeds_threshold(score, 'medium'))
        self.assertFalse(exceeds_threshold(score, 'high'))
        self.assertFalse(exceeds_threshold(score, 'critical'))

    def test_default_high_preserves_the_old_hardcoded_behavior(self):
        # before --fail-on existed the exit code was score >= 50
        for score in (0, 25, 49, 50, 75, 100):
            self.assertEqual(exceeds_threshold(float(score), 'high'), score >= 50)

    def test_thresholds_match_the_reported_risk_level(self):
        for name in ('low', 'medium', 'high', 'critical'):
            score = float(RISK_THRESHOLDS[name])
            self.assertEqual(risk_level_for(score), RiskLevel(name))


class TestExitCodes(unittest.TestCase):
    def test_threshold_and_error_are_distinguishable(self):
        # CI must be able to tell a risky repo from a crashed scanner
        self.assertEqual(EXIT_OK, 0)
        self.assertEqual(EXIT_THRESHOLD, 1)
        self.assertEqual(EXIT_ERROR, 2)
        self.assertNotEqual(EXIT_THRESHOLD, EXIT_ERROR)


class TestRiskBandsHaveOneDefinition(unittest.TestCase):
    def test_bands_come_from_config(self):
        self.assertEqual(risk_level_for(RISK_THRESHOLDS['critical']), RiskLevel.CRITICAL)
        self.assertEqual(risk_level_for(RISK_THRESHOLDS['low'] - 1), RiskLevel.SAFE)


if __name__ == '__main__':
    unittest.main()
