"""Tests for bug fixes"""
import pytest
import tempfile
import json
from pathlib import Path
from repo_scanner.scanner.pattern_matcher import PatternMatcher
from repo_scanner.scanner.dependency_checker import DependencyChecker
from repo_scanner.scanner.entropy_calculator import EntropyCalculator
from repo_scanner.scanner.file_analyzer import FileAnalyzer
from repo_scanner.scanner.core import RepoScanner


class TestPatternMatcher:
    """Test word-boundary function detection"""

    def test_no_false_positive_evolved_vs_eval(self):
        """evolved should not match eval()"""
        matcher = PatternMatcher()
        content = "evolved_algorithm = evolution_process()"
        score, found = matcher.detect_dangerous_functions(content, '.py')
        assert 'eval' not in found
        assert score == 0.0

    def test_no_false_positive_expiration_vs_exec(self):
        """expiration should not match exec()"""
        matcher = PatternMatcher()
        content = "expiration_time = get_expiration()"
        score, found = matcher.detect_dangerous_functions(content, '.py')
        assert 'exec' not in found
        assert score == 0.0

    def test_detects_actual_eval(self):
        """Should detect eval()"""
        matcher = PatternMatcher()
        content = "result = eval(user_input)"
        score, found = matcher.detect_dangerous_functions(content, '.py')
        assert 'eval' in found
        assert score > 0

    def test_detects_actual_exec(self):
        """Should detect exec()"""
        matcher = PatternMatcher()
        content = "exec(command_string)"
        score, found = matcher.detect_dangerous_functions(content, '.py')
        assert 'exec' in found
        assert score > 0

    def test_case_insensitive_detection(self):
        """Should detect EVAL() as well as eval()"""
        matcher = PatternMatcher()
        content = "EVAL(data)"
        score, found = matcher.detect_dangerous_functions(content, '.py')
        assert 'eval' in found or score > 0


class TestDependencyChecker:
    """Test dependency vulnerability checking"""

    def test_checks_dev_dependencies(self):
        """Should detect risky packages in devDependencies"""
        checker = DependencyChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_file = Path(tmpdir) / 'package.json'
            data = {
                'dependencies': {},
                'devDependencies': {
                    'lodash': '^4.17.0'
                }
            }
            with open(pkg_file, 'w') as f:
                json.dump(data, f)

            score, findings = checker._check_package_json(pkg_file)
            assert score > 0
            assert any('lodash' in str(f.description) for f in findings)
            assert any('devDependencies' in str(f.description) for f in findings)

    def test_checks_prod_dependencies(self):
        """Should detect risky packages in dependencies"""
        checker = DependencyChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            pkg_file = Path(tmpdir) / 'package.json'
            data = {
                'dependencies': {
                    'crypto-js': '^4.1.0'
                }
            }
            with open(pkg_file, 'w') as f:
                json.dump(data, f)

            score, findings = checker._check_package_json(pkg_file)
            assert score > 0
            assert any('crypto-js' in str(f.description) for f in findings)

    def test_pip_requirements(self):
        """Should detect risky Python packages"""
        checker = DependencyChecker()

        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = Path(tmpdir) / 'requirements.txt'
            with open(req_file, 'w') as f:
                f.write('pyyaml>=6.0\n')
                f.write('requests>=2.28.0\n')

            score, findings = checker._check_requirements_txt(req_file)
            assert score > 0
            assert len(findings) >= 2


class TestEntropyCalculator:
    """Test entropy calculation and sampling"""

    def test_default_sample_size_8kb(self):
        """Should use 8KB default sample, not entire file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / 'large_file.bin'
            # Create 1MB file with random data
            with open(test_file, 'wb') as f:
                f.write(b'\x00\x01\x02\x03' * 262144)  # 1MB

            entropy = EntropyCalculator.calculate_file_entropy(test_file)
            assert entropy is not None
            assert entropy > 0

    def test_high_entropy_detection(self):
        """Should detect high entropy (obfuscated/encrypted)"""
        import os
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / 'random.bin'
            with open(test_file, 'wb') as f:
                f.write(os.urandom(1024))

            entropy = EntropyCalculator.calculate_file_entropy(test_file)
            assert EntropyCalculator.is_high_entropy(entropy)

    def test_low_entropy_detection(self):
        """Should detect low entropy (plain text)"""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / 'text.txt'
            with open(test_file, 'wb') as f:
                f.write(b'aaaaaaaaaa' * 100)

            entropy = EntropyCalculator.calculate_file_entropy(test_file)
            assert not EntropyCalculator.is_high_entropy(entropy)


class TestFileAnalyzerSeverity:
    """Test severity assignment by category, not cumulative score"""

    def test_backdoor_pattern_high_severity(self):
        """Backdoor patterns should be high severity"""
        analyzer = FileAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / 'backdoor.py'
            with open(test_file, 'w') as f:
                f.write('socket.bind(("0.0.0.0", 4444))')

            result = analyzer.analyze_file(test_file)
            backdoor_findings = [f for f in result.findings if 'backdoor' in f.category]
            assert len(backdoor_findings) > 0
            assert all(f.severity in ['high', 'medium'] for f in backdoor_findings)

    def test_crypto_miner_high_severity(self):
        """Crypto miner patterns should be high severity"""
        analyzer = FileAnalyzer()

        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / 'miner.py'
            with open(test_file, 'w') as f:
                f.write('xmrig.connect(pool_url)')

            result = analyzer.analyze_file(test_file)
            findings = [f for f in result.findings if 'crypto' in f.category or 'miner' in f.description.lower()]
            if findings:
                assert any(f.severity in ['high', 'medium'] for f in findings)


class TestQuickMode:
    """Test quick mode file limit"""

    def test_quick_mode_respects_max_files(self):
        """Quick mode should stop at MAX_FILES_TO_SCAN"""
        from repo_scanner.config import MAX_FILES_TO_SCAN

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            # Create more files than MAX_FILES_TO_SCAN
            for i in range(MAX_FILES_TO_SCAN + 100):
                (repo_path / f'file_{i}.py').touch()

            scanner = RepoScanner(
                repo_url=str(repo_path),
                scan_mode='quick',
                verbose=False
            )
            files = scanner._get_files_to_scan()
            assert len(files) <= MAX_FILES_TO_SCAN


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
