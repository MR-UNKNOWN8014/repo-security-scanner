"""Git operations utilities"""

import tempfile
import subprocess
from pathlib import Path
from typing import Optional
from repo_scanner.utils.file_utils import FileUtils

class GitUtils:
    def clone_repo(self, repo_url: str, depth: int = 1) -> Optional[Path]:
        try:
            temp_dir = tempfile.mkdtemp(prefix='repo_scan_')

            cmd = ['git', 'clone', '--depth', str(depth), '--quiet', '--', repo_url, temp_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode != 0:
                FileUtils.force_rmtree(temp_dir)
                return None

            return Path(temp_dir)
        except Exception:
            return None
