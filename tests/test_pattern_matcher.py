import unittest
from repo_scanner.config import EXTREMELY_LONG_LINE_CHARS, LONG_LINE_CHARS
from repo_scanner.scanner.pattern_matcher import PatternMatcher


class TestPatternMatcher(unittest.TestCase):
    def setUp(self):
        self.matcher = PatternMatcher()

    def test_detects_backdoor_pattern(self):
        score, findings = self.matcher.detect_malicious_patterns("os.system('rm -rf /')")
        self.assertGreater(score, 0)
        self.assertTrue(any(cat == 'backdoor' for cat, _, _ in findings))

    def test_clean_content_has_no_findings(self):
        score, findings = self.matcher.detect_malicious_patterns('def add(a, b):\n    return a + b\n')
        self.assertEqual(score, 0)
        self.assertEqual(findings, [])

    def test_duplicate_pattern_across_categories_is_not_double_counted(self):
        # os.system/exec/eval used to live in both backdoor and shell_commands
        score, findings = self.matcher.detect_malicious_patterns("os.system('id')")
        matches = [f for f in findings if 'os.system' in f[1] or f[1] == r'system\(']
        self.assertEqual(len(matches), 1)

    def test_pattern_finding_reports_its_line_number(self):
        content = 'clean line\nanother clean line\nos.system("id")\n'
        score, findings = self.matcher.detect_malicious_patterns(content)
        backdoor = [f for f in findings if f[0] == 'backdoor']
        self.assertTrue(backdoor)
        self.assertEqual(backdoor[0][2], 3)

    def test_long_line_is_reported_but_scores_zero(self):
        content = 'x' * (LONG_LINE_CHARS + 10)
        score, findings = self.matcher.detect_malicious_patterns(content)
        self.assertEqual(score, 0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0][0], 'long_line')

    def test_extremely_long_line_also_scores_zero(self):
        content = 'x' * (EXTREMELY_LONG_LINE_CHARS + 10)
        score, findings = self.matcher.detect_malicious_patterns(content)
        self.assertEqual(score, 0)
        self.assertIn('extremely long line', findings[0][1])

    def test_long_line_reports_its_line_number(self):
        content = 'short\n' + 'x' * (LONG_LINE_CHARS + 10) + '\n'
        score, findings = self.matcher.detect_malicious_patterns(content)
        self.assertEqual(findings[0][2], 2)

    def test_long_prose_line_is_reported_on_any_file_type(self):
        # markdown paragraphs are long for legitimate reasons, so this still
        # reports but must not add score
        content = 'A long documentation paragraph. ' * 40
        score, findings = self.matcher.detect_malicious_patterns(content)
        self.assertEqual(score, 0)
        self.assertTrue(any(f[0] == 'long_line' for f in findings))

    def test_bash_dot_source_shorthand_is_not_flagged(self):
        # '.' used to match almost every bash file via substring check
        score, funcs = self.matcher.detect_dangerous_functions('# version 1.2.3\necho hi\n', '.sh')
        self.assertNotIn('.', [name for name, _ in funcs])

    def test_bash_source_keyword_is_flagged(self):
        score, funcs = self.matcher.detect_dangerous_functions('source ./env.sh', '.sh')
        self.assertIn('source', [name for name, _ in funcs])

    def test_dangerous_function_reports_its_line_number(self):
        score, funcs = self.matcher.detect_dangerous_functions('echo hi\nsource ./env.sh\n', '.sh')
        found = dict(funcs)
        self.assertEqual(found['source'], 2)

    def test_hex_git_sha_is_not_flagged_as_base64(self):
        content = 'commit ' + ('a1b2c3d4' * 5)
        score, findings = self.matcher.detect_base64_encoding(content)
        self.assertEqual(score, 0)

    def test_base64_decode_call_is_flagged(self):
        score, findings = self.matcher.detect_base64_encoding('base64.b64decode(payload)')
        self.assertGreater(score, 0)

    def test_base64_finding_reports_its_line_number(self):
        score, findings = self.matcher.detect_base64_encoding('x = 1\nbase64.b64decode(payload)\n')
        self.assertEqual(findings[0][1], 2)

    def test_network_pattern_detection(self):
        findings = self.matcher.detect_network_connections('requests.get(url)')
        self.assertTrue(any('HTTP request' in description for description, _ in findings))

    def test_network_finding_reports_its_line_number(self):
        findings = self.matcher.detect_network_connections('import requests\nrequests.get(url)\n')
        self.assertEqual(findings[0][1], 2)


if __name__ == '__main__':
    unittest.main()
