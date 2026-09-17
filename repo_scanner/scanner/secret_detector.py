"""Credential and secret detection (API keys, tokens, passwords, private keys)"""

import re
from typing import List, Tuple
from repo_scanner.config import SECRET_PATTERNS, SECRET_PLACEHOLDER_MARKERS, SCORE_SECRET_DETECTED

_COMPILED_PATTERNS = [(name, re.compile(pattern)) for name, pattern in SECRET_PATTERNS.items()]


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SECRET_PLACEHOLDER_MARKERS)


def _redact(value: str) -> str:
    if len(value) <= 8:
        return '*' * len(value)
    return f'{value[:4]}{"*" * (len(value) - 8)}{value[-4:]}'


class SecretDetector:
    def detect_secrets(self, content: str) -> Tuple[float, List[Tuple[str, str, int]]]:
        score = 0.0
        findings = []

        for line_number, line in enumerate(content.split('\n'), start=1):
            for name, pattern in _COMPILED_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                value = match.group(1)
                if _is_placeholder(value):
                    continue
                findings.append((name, _redact(value), line_number))
                score += SCORE_SECRET_DETECTED

        return min(score, 100), findings
