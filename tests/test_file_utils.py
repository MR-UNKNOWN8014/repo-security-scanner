import tempfile
import unittest
from pathlib import Path
from repo_scanner.utils.file_utils import FileUtils


class TestFileUtils(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo_path = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, data):
        path = self.repo_path / name
        path.write_bytes(data)
        return path

    def test_utf8_text_is_not_binary(self):
        path = self._write('a.txt', 'hello world'.encode('utf-8'))
        self.assertFalse(FileUtils.is_binary(path))

    def test_utf16_text_is_not_binary(self):
        # old null-byte heuristic misclassified this as binary, skipping it for scanning
        path = self._write('a.txt', 'hello world'.encode('utf-16'))
        self.assertFalse(FileUtils.is_binary(path))

    def test_null_byte_data_is_binary(self):
        path = self._write('a.bin', b'\x00\x01\x02random binary')
        self.assertTrue(FileUtils.is_binary(path))

    def test_empty_file_is_not_binary(self):
        path = self._write('empty.txt', b'')
        self.assertFalse(FileUtils.is_binary(path))

    def test_load_ignore_patterns_missing_file(self):
        self.assertEqual(FileUtils.load_ignore_patterns(self.repo_path), [])

    def test_load_ignore_patterns_skips_comments_and_blanks(self):
        (self.repo_path / '.reposecurityignore').write_text('# comment\n\n*.log\nfixtures/*\n')
        patterns = FileUtils.load_ignore_patterns(self.repo_path)
        self.assertEqual(patterns, ['*.log', 'fixtures/*'])

    def test_is_ignored_matches_filename_pattern(self):
        file_path = self.repo_path / 'debug.log'
        self.assertTrue(FileUtils.is_ignored(file_path, self.repo_path, ['*.log']))

    def test_is_ignored_no_match(self):
        file_path = self.repo_path / 'main.py'
        self.assertFalse(FileUtils.is_ignored(file_path, self.repo_path, ['*.log']))


if __name__ == '__main__':
    unittest.main()
