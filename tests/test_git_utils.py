import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from repo_scanner.utils.git_utils import GitUtils


class TestCloneRepo(unittest.TestCase):
    def _clone_with(self, **run_kwargs):
        made = []
        real_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(*args, **kwargs):
            made.append(real_mkdtemp(*args, **kwargs))
            return made[-1]

        with mock.patch('repo_scanner.utils.git_utils.tempfile.mkdtemp', tracking_mkdtemp), \
                mock.patch('repo_scanner.utils.git_utils.subprocess.run', **run_kwargs) as run:
            result = GitUtils().clone_repo('https://example.invalid/r.git')
        return result, made, run

    def test_timeout_removes_temp_dir(self):
        result, made, _ = self._clone_with(side_effect=subprocess.TimeoutExpired('git', 120))
        self.assertIsNone(result)
        self.assertFalse(Path(made[0]).exists())

    def test_failed_clone_removes_temp_dir(self):
        result, made, _ = self._clone_with(return_value=mock.Mock(returncode=128))
        self.assertIsNone(result)
        self.assertFalse(Path(made[0]).exists())

    def test_clone_never_prompts_and_disables_hooks(self):
        result, made, run = self._clone_with(return_value=mock.Mock(returncode=0))
        self.assertEqual(result, Path(made[0]))
        args, kwargs = run.call_args
        self.assertEqual(kwargs['env']['GIT_TERMINAL_PROMPT'], '0')
        self.assertEqual(kwargs['stdin'], subprocess.DEVNULL)
        self.assertIn('core.hooksPath=/dev/null', args[0])
        self.assertIn('--no-recurse-submodules', args[0])
        self.assertNotIn('shell', kwargs)
        Path(made[0]).rmdir()


if __name__ == '__main__':
    unittest.main()
