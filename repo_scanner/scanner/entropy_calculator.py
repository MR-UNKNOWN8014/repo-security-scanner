"""Entropy calculation for detecting obfuscation"""

import math
from pathlib import Path
from typing import Optional

class EntropyCalculator:
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def calculate_file_entropy(file_path: Path, sample_size: int = 8192) -> Optional[float]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)

                if not data:
                    return 0.0

                return EntropyCalculator.calculate_entropy(data)
        except Exception:
            return None
    
    @staticmethod
    def is_high_entropy(entropy: float, threshold: float = 7.5) -> bool:
        return entropy > threshold