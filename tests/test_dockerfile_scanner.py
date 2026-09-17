import unittest
from pathlib import Path
from repo_scanner.scanner.dockerfile_scanner import DockerfileScanner, is_dockerfile


class TestIsDockerfile(unittest.TestCase):
    def test_matches_plain_dockerfile(self):
        self.assertTrue(is_dockerfile(Path('Dockerfile')))

    def test_matches_suffixed_dockerfile(self):
        self.assertTrue(is_dockerfile(Path('Dockerfile.prod')))

    def test_matches_dockerfile_extension(self):
        self.assertTrue(is_dockerfile(Path('app.dockerfile')))

    def test_does_not_match_unrelated_file(self):
        self.assertFalse(is_dockerfile(Path('main.py')))


class TestDockerfileScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = DockerfileScanner()

    def test_latest_tag_is_flagged(self):
        score, findings = self.scanner.scan('FROM python:latest\nUSER app\n')
        self.assertTrue(any(f[0] == 'unpinned_base_image' for f in findings))

    def test_pinned_tag_is_not_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nUSER app\n')
        self.assertFalse(any(f[0] == 'unpinned_base_image' for f in findings))

    def test_missing_user_instruction_is_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nCMD ["python", "app.py"]\n')
        self.assertTrue(any(f[0] == 'root_user' for f in findings))

    def test_explicit_root_user_is_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nUSER root\n')
        root_findings = [f for f in findings if f[0] == 'root_user']
        self.assertEqual(len(root_findings), 1)

    def test_non_root_user_is_not_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nUSER app\n')
        self.assertFalse(any(f[0] == 'root_user' for f in findings))

    def test_add_local_file_is_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nUSER app\nADD app.py /app/\n')
        self.assertTrue(any(f[0] == 'add_vs_copy' for f in findings))

    def test_add_url_is_not_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nUSER app\nADD https://example.com/f.tar.gz /app/\n')
        self.assertFalse(any(f[0] == 'add_vs_copy' for f in findings))

    def test_curl_pipe_bash_is_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nUSER app\nRUN curl https://get.example.com | bash\n')
        self.assertTrue(any(f[0] == 'pipe_to_shell' for f in findings))

    def test_insecure_curl_is_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nUSER app\nRUN curl -k https://example.com\n')
        self.assertTrue(any(f[0] == 'insecure_tls' for f in findings))

    def test_hardcoded_env_secret_is_flagged(self):
        score, findings = self.scanner.scan('FROM python:3.12-slim\nUSER app\nENV DB_PASSWORD=supersecret123\n')
        self.assertTrue(any(f[0] == 'hardcoded_secret' for f in findings))

    def test_clean_dockerfile_has_minimal_findings(self):
        content = 'FROM python:3.12-slim\nUSER app\nCOPY app.py /app/\nCMD ["python", "app.py"]\n'
        score, findings = self.scanner.scan(content)
        self.assertEqual(findings, [])


if __name__ == '__main__':
    unittest.main()
