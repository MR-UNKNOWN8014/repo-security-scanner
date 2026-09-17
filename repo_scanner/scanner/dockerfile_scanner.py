"""Security linting for Dockerfiles"""

import fnmatch
import re
from pathlib import Path
from typing import List, Optional, Tuple
from repo_scanner.config import (
    DOCKERFILE_NAME_PATTERNS,
    SCORE_DOCKER_LATEST_TAG, SCORE_DOCKER_ROOT_USER, SCORE_DOCKER_ADD_VS_COPY,
    SCORE_DOCKER_PIPE_SHELL, SCORE_DOCKER_INSECURE_TLS, SCORE_DOCKER_HARDCODED_SECRET,
)

_FROM_RE = re.compile(r'^\s*FROM\s+(\S+)', re.IGNORECASE)
_ADD_RE = re.compile(r'^\s*ADD\s+(\S+)', re.IGNORECASE)
_USER_ROOT_RE = re.compile(r'^\s*USER\s+root\b', re.IGNORECASE)
_USER_RE = re.compile(r'^\s*USER\s+\S+', re.IGNORECASE)
_PIPE_SHELL_RE = re.compile(r'(curl|wget)\s+.*\|\s*(sudo\s+)?(sh|bash)\b', re.IGNORECASE)
_INSECURE_TLS_RE = re.compile(r'--no-check-certificate|curl\s+.*(-k\b|--insecure)', re.IGNORECASE)
_HARDCODED_SECRET_RE = re.compile(
    r'(?i)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|API_KEY)\w*[= ]+(\S{8,})'
)


def is_dockerfile(file_path: Path) -> bool:
    return any(fnmatch.fnmatch(file_path.name, p) for p in DOCKERFILE_NAME_PATTERNS)


class DockerfileScanner:
    def scan(self, content: str) -> Tuple[float, List[Tuple[str, str, Optional[int]]]]:
        score = 0.0
        findings = []
        has_user_instruction = False

        for line_number, line in enumerate(content.split('\n'), start=1):
            from_match = _FROM_RE.match(line)
            if from_match:
                image = from_match.group(1)
                if image.lower() not in ('scratch',) and (':' not in image or image.endswith(':latest')):
                    findings.append(('unpinned_base_image', f'Base image not pinned to a specific version: {image}', line_number))
                    score += SCORE_DOCKER_LATEST_TAG

            if _USER_ROOT_RE.match(line):
                has_user_instruction = True
                findings.append(('root_user', 'Explicitly runs as root', line_number))
                score += SCORE_DOCKER_ROOT_USER
            elif _USER_RE.match(line):
                has_user_instruction = True

            add_match = _ADD_RE.match(line)
            if add_match:
                source = add_match.group(1)
                is_url = source.startswith(('http://', 'https://'))
                is_archive = source.endswith(('.tar', '.tar.gz', '.tgz', '.tar.bz2', '.zip'))
                if not is_url and not is_archive:
                    findings.append(('add_vs_copy', 'ADD used where COPY would suffice (no auto-extraction/URL fetch needed)', line_number))
                    score += SCORE_DOCKER_ADD_VS_COPY

            if _PIPE_SHELL_RE.search(line):
                findings.append(('pipe_to_shell', 'Pipes a remote download directly into a shell', line_number))
                score += SCORE_DOCKER_PIPE_SHELL

            if _INSECURE_TLS_RE.search(line):
                findings.append(('insecure_tls', 'Disables TLS certificate verification', line_number))
                score += SCORE_DOCKER_INSECURE_TLS

            secret_match = _HARDCODED_SECRET_RE.match(line)
            if secret_match:
                findings.append(('hardcoded_secret', 'Hardcoded credential in ENV/ARG instruction', line_number))
                score += SCORE_DOCKER_HARDCODED_SECRET

        if not has_user_instruction:
            findings.append(('root_user', 'No USER instruction: container runs as root by default', None))
            score += SCORE_DOCKER_ROOT_USER

        return min(score, 100), findings
