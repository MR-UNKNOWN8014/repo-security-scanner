import unittest
from repo_scanner.scanner.pattern_matcher import PatternMatcher


class TestPatternMatcher(unittest.TestCase):
    def setUp(self):
        self.matcher = PatternMatcher()

    def test_detects_backdoor_pattern(self):
        score, findings = self.matcher.detect_malicious_patterns("os.system('rm -rf /')")
        self.assertGreater(score, 0)
        self.assertTrue(any(cat == 'backdoor' for cat, _ in findings))

    def test_clean_content_has_no_findings(self):
        score, findings = self.matcher.detect_malicious_patterns('def add(a, b):\n    return a + b\n')
        self.assertEqual(score, 0)
        self.assertEqual(findings, [])

    def test_duplicate_pattern_across_categories_is_not_double_counted(self):
        # os.system/exec/eval used to live in both backdoor and shell_commands
        score, findings = self.matcher.detect_malicious_patterns("os.system('id')")
        matches = [f for f in findings if 'os.system' in f[1] or f[1] == r'system\(']
        self.assertEqual(len(matches), 1)

    def test_bash_dot_source_shorthand_is_not_flagged(self):
        # '.' used to match almost every bash file via substring check
        score, funcs = self.matcher.detect_dangerous_functions('# version 1.2.3\necho hi\n', '.sh')
        self.assertNotIn('.', funcs)

    def test_bash_source_keyword_is_flagged(self):
        score, funcs = self.matcher.detect_dangerous_functions('source ./env.sh', '.sh')
        self.assertIn('source', funcs)

    def test_hex_git_sha_is_not_flagged_as_base64(self):
        content = 'commit ' + ('a1b2c3d4' * 5)
        score, findings = self.matcher.detect_base64_encoding(content)
        self.assertEqual(score, 0)

    def test_base64_decode_call_is_flagged(self):
        score, findings = self.matcher.detect_base64_encoding('base64.b64decode(payload)')
        self.assertGreater(score, 0)

    def test_network_pattern_detection(self):
        findings = self.matcher.detect_network_connections('requests.get(url)')
        self.assertTrue(any('HTTP request' in f for f in findings))


if __name__ == '__main__':
    unittest.main()
