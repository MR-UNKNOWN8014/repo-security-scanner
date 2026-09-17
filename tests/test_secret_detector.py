import unittest
from repo_scanner.scanner.secret_detector import SecretDetector


class TestSecretDetector(unittest.TestCase):
    def setUp(self):
        self.detector = SecretDetector()

    def test_aws_example_key_is_filtered_as_placeholder(self):
        score, findings = self.detector.detect_secrets('key = "AKIAIOSFODNN7EXAMPLE"')
        self.assertEqual(score, 0)  # AWS's own docs example key, filtered as placeholder

    def test_real_looking_aws_key_is_detected(self):
        score, findings = self.detector.detect_secrets('key = "AKIAZZZZZZZZZZZZWXYZ"')
        self.assertGreater(score, 0)
        self.assertEqual(findings[0][0], 'AWS Access Key ID')

    def test_secret_value_is_redacted(self):
        score, findings = self.detector.detect_secrets('key = "AKIAZZZZZZZZZZZZWXYZ"')
        redacted = findings[0][1]
        self.assertNotIn('ZZZZZZZZZZZZ', redacted)
        self.assertIn('*', redacted)

    def test_line_number_is_reported(self):
        content = 'line one\nline two\nkey = "AKIAZZZZZZZZZZZZWXYZ"\n'
        score, findings = self.detector.detect_secrets(content)
        self.assertEqual(findings[0][2], 3)

    def test_github_token_is_detected(self):
        score, findings = self.detector.detect_secrets('token = "ghp_' + 'a' * 36 + '"')
        self.assertGreater(score, 0)

    def test_clean_content_has_no_findings(self):
        score, findings = self.detector.detect_secrets('def add(a, b):\n    return a + b\n')
        self.assertEqual(score, 0)
        self.assertEqual(findings, [])

    def test_placeholder_password_is_not_flagged(self):
        score, findings = self.detector.detect_secrets('password = "changeme123"')
        self.assertEqual(score, 0)

    def test_real_looking_password_is_flagged(self):
        score, findings = self.detector.detect_secrets('password = "tr0ub4dor&3xyz"')
        self.assertGreater(score, 0)


if __name__ == '__main__':
    unittest.main()
