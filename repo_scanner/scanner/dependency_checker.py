"""Dependency vulnerability checking"""

import json
import re
from pathlib import Path
from typing import List, Tuple
from repo_scanner.models.scan_result import Finding

class DependencyChecker:
    def check_dependencies(self, repo_path: Path) -> Tuple[float, List[Finding]]:
        findings = []
        total_score = 0.0
        
        package_json = repo_path / 'package.json'
        if package_json.exists():
            score, pkg_findings = self._check_package_json(package_json)
            total_score += score
            findings.extend(pkg_findings)
        
        requirements = repo_path / 'requirements.txt'
        if requirements.exists():
            score, req_findings = self._check_requirements_txt(requirements)
            total_score += score
            findings.extend(req_findings)
        
        return min(total_score, 100), findings
    
    def _check_package_json(self, file_path: Path) -> Tuple[float, List[Finding]]:
        findings = []
        score = 0.0
        
        risky_npm = {
            'crypto-js': 'Known cryptographic vulnerabilities',
            'node-fetch': 'SSRF vulnerabilities in older versions',
            'axios': 'Prototype pollution risks',
            'lodash': 'Prototype pollution vulnerabilities',
            'request': 'Deprecated with known issues'
        }
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                deps = data.get('dependencies', {})
                
                for dep in deps:
                    if dep in risky_npm:
                        findings.append(Finding(
                            file_path=str(file_path),
                            severity="medium",
                            category="vulnerable_dependency",
                            description=f"NPM package '{dep}': {risky_npm[dep]}"
                        ))
                        score += 15
        except Exception:
            pass
        
        return score, findings
    
    def _check_requirements_txt(self, file_path: Path) -> Tuple[float, List[Finding]]:
        findings = []
        score = 0.0
        
        risky_pip = {
            'requests': 'SSL/TLS vulnerabilities in older versions',
            'urllib3': 'Security issues in older versions',
            'paramiko': 'Authentication bypass in some versions',
            'cryptography': 'Padding oracle vulnerabilities',
            'pyyaml': 'Arbitrary code execution in vulnerable versions'
        }
        
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    match = re.match(r'([a-zA-Z0-9_-]+)(?:[=<>]+([0-9.]+))?', line)
                    if match:
                        package = match.group(1)
                        
                        if package in risky_pip:
                            findings.append(Finding(
                                file_path=str(file_path),
                                severity="medium",
                                category="vulnerable_dependency",
                                description=f"Python package '{package}': {risky_pip[package]}"
                            ))
                            score += 15
        except Exception:
            pass
        
        return score, findings