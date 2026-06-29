"""Git operations utilities"""

import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Optional

class GitUtils:
    def clone_repo(self, repo_url: str, depth: int = 1) -> Optional[Path]:
        try:
            temp_dir = tempfile.mkdtemp(prefix='repo_scan_')
            
            cmd = ['git', 'clone', '--depth', str(depth), '--quiet', repo_url, temp_dir]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                shutil.rmtree(temp_dir)
                return None
            
            return Path(temp_dir)
        except Exception:
            return None