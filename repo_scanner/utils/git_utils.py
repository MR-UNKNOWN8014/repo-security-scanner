"""Git operations utilities"""

import os
import tempfile
import subprocess
from pathlib import Path
from typing import Optional
from repo_scanner.utils.file_utils import FileUtils

class GitUtils:
    def clone_repo(self, repo_url: str, depth: int = 1) -> Optional[Path]:
        temp_dir = tempfile.mkdtemp(prefix='repo_scan_')
        try:
            # the repo is hostile: no hooks, no fsmonitor, no ext:: transport, no
            # submodules, and never block on a credential prompt
            cmd = [
                'git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                '-c', 'protocol.ext.allow=never',
                'clone', '--depth', str(depth), '--no-recurse-submodules', '--quiet',
                '--', repo_url, temp_dir,
            ]
            env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                stdin=subprocess.DEVNULL, env=env,
            )
            if result.returncode == 0:
                return Path(temp_dir)
        except Exception:
            pass
        FileUtils.force_rmtree(temp_dir)
        return None
