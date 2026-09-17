"""Dependency vulnerability checking"""

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional, Tuple
from repo_scanner.models.scan_result import Finding
from repo_scanner.config import SCORE_VULNERABLE_DEPENDENCY, SCORE_VULNERABLE_DEPENDENCY_CONFIRMED

OSV_API_URL = 'https://api.osv.dev/v1/query'
OSV_TIMEOUT_SECONDS = 5
OSV_MAX_PACKAGES = 50

def _parse_version(version: str) -> Optional[Tuple[int, ...]]:
    try:
        return tuple(int(part) for part in version.split('.'))
    except ValueError:
        return None

def _query_osv(name: str, version: str, ecosystem: str) -> List[dict]:
    payload = json.dumps({
        'package': {'name': name, 'ecosystem': ecosystem},
        'version': version,
    }).encode('utf-8')
    request = urllib.request.Request(
        OSV_API_URL, data=payload, headers={'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:
        data = json.loads(response.read())
    return data.get('vulns', [])

class DependencyChecker:
    def check_dependencies(self, repo_path: Path, online: bool = False) -> Tuple[float, List[Finding]]:
        findings = []
        total_score = 0.0

        package_json = repo_path / 'package.json'
        if package_json.exists():
            score, pkg_findings = self._check_package_json(package_json, online)
            total_score += score
            findings.extend(pkg_findings)

        requirements = repo_path / 'requirements.txt'
        if requirements.exists():
            score, req_findings = self._check_requirements_txt(requirements, online)
            total_score += score
            findings.extend(req_findings)

        return min(total_score, 100), findings

    def _check_package_json(self, file_path: Path, online: bool) -> Tuple[float, List[Finding]]:
        findings = []
        score = 0.0

        # "fixed in" floor: flagged only if a pinned version is below this
        risky_npm = {
            'crypto-js': ('4.2.0', 'Known cryptographic vulnerabilities'),
            'node-fetch': ('2.6.7', 'SSRF vulnerabilities in older versions'),
            'axios': ('0.21.2', 'Prototype pollution risks'),
            'lodash': ('4.17.21', 'Prototype pollution vulnerabilities'),
            'request': ('9999.0.0', 'Deprecated with known issues'),
        }

        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                deps = data.get('dependencies', {})

                checked = 0
                for dep, pinned in deps.items():
                    version_str = str(pinned).lstrip('^~=')
                    version = _parse_version(version_str)

                    if dep in risky_npm:
                        floor, reason = risky_npm[dep]
                        if version is not None and version < _parse_version(floor):
                            findings.append(Finding(
                                file_path=str(file_path),
                                severity="medium",
                                category="vulnerable_dependency",
                                description=f"NPM package '{dep}': {reason}"
                            ))
                            score += SCORE_VULNERABLE_DEPENDENCY

                    if online and version is not None and checked < OSV_MAX_PACKAGES:
                        checked += 1
                        score += self._check_osv(dep, version_str, 'npm', file_path, findings)
        except Exception:
            pass

        return score, findings

    def _check_requirements_txt(self, file_path: Path, online: bool) -> Tuple[float, List[Finding]]:
        findings = []
        score = 0.0

        # "fixed in" floor: flagged only if a pinned version is below this
        risky_pip = {
            'requests': ('2.31.0', 'SSL/TLS vulnerabilities in older versions'),
            'urllib3': ('1.26.18', 'Security issues in older versions'),
            'paramiko': ('2.10.1', 'Authentication bypass in some versions'),
            'cryptography': ('39.0.1', 'Padding oracle vulnerabilities'),
            'pyyaml': ('5.4', 'Arbitrary code execution in vulnerable versions'),
        }

        try:
            with open(file_path, 'r') as f:
                checked = 0
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    match = re.match(r'([a-zA-Z0-9_-]+)(?:==([0-9.]+))?', line)
                    if not match:
                        continue
                    package = match.group(1).lower()
                    pinned = match.group(2)
                    version = _parse_version(pinned) if pinned else None

                    if package in risky_pip:
                        floor, reason = risky_pip[package]
                        if version is not None and version < _parse_version(floor):
                            findings.append(Finding(
                                file_path=str(file_path),
                                severity="medium",
                                category="vulnerable_dependency",
                                description=f"Python package '{package}' pinned to {pinned}: {reason} (fixed in {floor})"
                            ))
                            score += SCORE_VULNERABLE_DEPENDENCY

                    if online and pinned and version is not None and checked < OSV_MAX_PACKAGES:
                        checked += 1
                        score += self._check_osv(package, pinned, 'PyPI', file_path, findings)
        except Exception:
            pass

        return score, findings

    def _check_osv(self, name: str, version: str, ecosystem: str, file_path: Path, findings: List[Finding]) -> float:
        # best-effort live lookup: network failures just mean no extra findings
        try:
            vulns = _query_osv(name, version, ecosystem)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return 0.0

        score = 0.0
        for vuln in vulns:
            vuln_id = vuln.get('id', 'unknown')
            summary = vuln.get('summary') or (vuln.get('details') or '')[:120] or 'no summary available'
            findings.append(Finding(
                file_path=str(file_path),
                severity="high",
                category="vulnerable_dependency",
                description=f"{ecosystem} package '{name}' {version}: {vuln_id} - {summary}"
            ))
            score += SCORE_VULNERABLE_DEPENDENCY_CONFIRMED
        return score
