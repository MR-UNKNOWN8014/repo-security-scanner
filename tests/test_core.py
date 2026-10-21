import tempfile
import unittest
from pathlib import Path
from repo_scanner.scanner.core import RepoScanner


class TestRepoScanner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _files(repo):
        scanner = RepoScanner(str(repo))
        scanner.repo_path = Path(repo)
        return scanner._get_files_to_scan()

    def test_repo_name_strips_only_trailing_git_suffix(self):
        self.assertEqual(RepoScanner('https://github.com/me/my.github.io.git').repo_name, 'my.github.io')
        self.assertEqual(RepoScanner('https://github.com/me/repo').repo_name, 'repo')

    def test_repo_inside_skip_named_directory_is_scanned(self):
        repo = self.root / 'build' / 'repo'
        repo.mkdir(parents=True)
        (repo / 'a.py').write_text('print(1)\n')
        self.assertEqual(len(self._files(repo)), 1)

    def test_skip_dir_inside_repo_is_still_pruned(self):
        repo = self.root / 'repo'
        (repo / 'node_modules').mkdir(parents=True)
        (repo / 'node_modules' / 'a.py').write_text('print(1)\n')
        self.assertEqual(self._files(repo), [])

    def test_symlinked_file_is_not_scanned(self):
        outside = self.root / 'secret.txt'
        outside.write_text('outside the repo\n')
        repo = self.root / 'repo'
        repo.mkdir()
        (repo / 'real.py').write_text('print(1)\n')
        try:
            (repo / 'link.txt').symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest('symlinks unavailable')
        names = [p.name for p in self._files(repo)]
        self.assertEqual(names, ['real.py'])


if __name__ == '__main__':
    unittest.main()
