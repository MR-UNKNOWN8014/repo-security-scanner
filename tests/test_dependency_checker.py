import json
import tempfile
import unittest
from pathlib import Path
from repo_scanner.scanner.dependency_checker import DependencyChecker


class TestDependencyChecker(unittest.TestCase):
    def setUp(self):
        self.checker = DependencyChecker()
        self.tmp = tempfile.TemporaryDirectory()
        self.repo_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_requirements(self, text):
        (self.repo_path / 'requirements.txt').write_text(text)

    def _write_package_json(self, dependencies):
        (self.repo_path / 'package.json').write_text(json.dumps({'dependencies': dependencies}))

    def test_old_pinned_version_is_flagged(self):
        self._write_requirements('requests==2.20.0\n')
        score, findings = self.checker.check_dependencies(self.repo_path)
        self.assertGreater(score, 0)
        self.assertTrue(any('requests' in f.description for f in findings))

    def test_new_pinned_version_is_not_flagged(self):
        self._write_requirements('requests==2.31.0\n')
        score, findings = self.checker.check_dependencies(self.repo_path)
        self.assertEqual(score, 0)
        self.assertEqual(findings, [])

    def test_unpinned_version_is_not_flagged(self):
        # old behavior flagged this unconditionally, guaranteeing false positives
        self._write_requirements('requests\n')
        score, findings = self.checker.check_dependencies(self.repo_path)
        self.assertEqual(score, 0)
        self.assertEqual(findings, [])

    def test_unlisted_package_is_never_flagged(self):
        self._write_requirements('flask==0.1\n')
        score, findings = self.checker.check_dependencies(self.repo_path)
        self.assertEqual(score, 0)

    def test_no_requirements_file_returns_no_findings(self):
        score, findings = self.checker.check_dependencies(self.repo_path)
        self.assertEqual(score, 0)
        self.assertEqual(findings, [])

    def test_npm_old_caret_pinned_version_is_flagged(self):
        self._write_package_json({'axios': '^0.21.1'})
        score, findings = self.checker.check_dependencies(self.repo_path)
        self.assertGreater(score, 0)
        self.assertTrue(any('axios' in f.description for f in findings))

    def test_npm_new_pinned_version_is_not_flagged(self):
        self._write_package_json({'axios': '^0.21.2'})
        score, findings = self.checker.check_dependencies(self.repo_path)
        self.assertEqual(score, 0)

    def test_npm_unparseable_version_range_is_not_flagged(self):
        # a range/latest spec used to be treated as "can't verify = vulnerable",
        # flagging almost every npm dependency regardless of actual version
        self._write_package_json({'axios': '>=0.20.0 <1.0.0', 'lodash': 'latest'})
        score, findings = self.checker.check_dependencies(self.repo_path)
        self.assertEqual(score, 0)
        self.assertEqual(findings, [])


if __name__ == '__main__':
    unittest.main()
