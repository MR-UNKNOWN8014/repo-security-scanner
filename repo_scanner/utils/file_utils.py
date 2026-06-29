"""File utility functions"""

from pathlib import Path
import os

class FileUtils:
    @staticmethod
    def is_local_path(path: str) -> bool:
        return os.path.exists(path) and os.path.isdir(path)
    
    @staticmethod
    def should_scan_file(file_path: Path, scan_mode: str) -> bool:
        skip_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'dist', 'build'}
        
        for parent in file_path.parents:
            if parent.name in skip_dirs:
                return False
        
        if scan_mode == 'quick':
            if file_path.stat().st_size > 1024 * 1024:
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
                if b'\0' in chunk:
                    return True
                text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)))
                if any(b not in text_chars for b in chunk):
                    return True
                return False
        except Exception:
            return True