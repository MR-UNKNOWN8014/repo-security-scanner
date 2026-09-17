"""File utility functions"""

from pathlib import Path
import fnmatch
import os
import shutil
import stat
from typing import List
from repo_scanner.config import SKIP_DIRS

IGNORE_FILENAME = '.reposecurityignore'

class FileUtils:
    @staticmethod
    def is_local_path(path: str) -> bool:
        return os.path.exists(path) and os.path.isdir(path)

    @staticmethod
    def should_scan_file(file_path: Path, scan_mode: str) -> bool:
        for parent in file_path.parents:
            if parent.name in SKIP_DIRS:
                return False

        if scan_mode == 'quick':
            try:
                if file_path.stat().st_size > 1024 * 1024:
                    return False
            except OSError:
                return False

        return True

    @staticmethod
    def get_file_size_mb(file_path: Path) -> float:
        return file_path.stat().st_size / (1024 * 1024)

    @staticmethod
    def is_binary(file_path: Path) -> bool:
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
            if not chunk:
                return False
            # BOM-marked UTF-16 (common from Windows tools) is legitimate text
            # despite being full of null bytes; without a BOM, null bytes still
            # mean binary since UTF-16 decoding is too permissive to trust blind
            if chunk.startswith((b'\xff\xfe', b'\xfe\xff')):
                try:
                    chunk.decode('utf-16')
                    return False
                except UnicodeDecodeError:
                    return True
            if b'\0' in chunk:
                return True
            try:
                chunk.decode('utf-8')
                return False
            except UnicodeDecodeError:
                return True
        except Exception:
            return True

    @staticmethod
    def force_rmtree(path):
        # clears read-only bit git leaves on .git/objects before deleting
        def _clear_readonly(func, p, exc_info):
            os.chmod(p, stat.S_IWRITE)
            func(p)
        shutil.rmtree(path, onerror=_clear_readonly)

    @staticmethod
    def load_ignore_patterns(repo_path: Path) -> List[str]:
        ignore_file = repo_path / IGNORE_FILENAME
        if not ignore_file.exists():
            return []
        try:
            lines = ignore_file.read_text(encoding='utf-8', errors='ignore').splitlines()
            return [line.strip() for line in lines if line.strip() and not line.startswith('#')]
        except OSError:
            return []

    @staticmethod
    def is_ignored(file_path: Path, repo_path: Path, patterns: List[str]) -> bool:
        try:
            rel_path = file_path.relative_to(repo_path).as_posix()
        except ValueError:
            rel_path = file_path.as_posix()
        return any(
            fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(file_path.name, pattern)
            for pattern in patterns
        )
