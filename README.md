# Repository Security Scanner

![CI](https://github.com/MR-UNKNOWN8014/repo-security-scanner/actions/workflows/tests.yml/badge.svg)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![PyPI](https://img.shields.io/pypi/v/repo-security-scanner)
![Stars](https://img.shields.io/github/stars/MR-UNKNOWN8014/repo-security-scanner?style=social)

> A Python-based security tool that analyzes Git repositories for malicious code, backdoors, obfuscation, and suspicious patterns before you clone them. It provides risk scoring and actionable recommendations.

The scanner performs static analysis on repository files, detecting:
- Crypto miner patterns
- Backdoor signatures
- Data exfiltration code
- Obfuscation techniques
- Dangerous function calls
- Vulnerable dependencies
- High-entropy (encrypted/obfuscated) files
- Hardcoded secrets and API keys
- Insecure Dockerfile patterns

---

## Why?

Cloning a repo to audit it is already too late — `postinstall` scripts, 
Makefiles, and CI configs run before you ever open the code. This tool 
scans **before** `git clone` completes, so you know what you're pulling 
in before it can touch your machine.

Built because existing tools (gitleaks, trufflehog) focus on *secrets*, 
and SAST tools (semgrep, bandit) focus on *your* code. Neither answers 
the question: "is this random GitHub repo safe to run?"

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/MR-UNKNOWN8014/repo-security-scanner.git
cd repo-security-scanner

# Install dependencies
./setup.sh          # Linux/macOS
setup.bat           # Windows

# Scan a repository
python run_scanner.py https://github.com/user/repo.git

```

---
## 1. Installation:

**Needs Python 3.8 or Higher to work.**

### 1.2 Linux / macOS

```bash
# Linux/Mac
chmod +x setup.sh

# Windows
./setup.sh
```

**The installer will**:
- Verify Python version
- Install all required dependencies
- Create the run script

>[!TIP]
>If Python is not in your PATH, the installer will prompt you to install Python 3.8+ from [python.org](https://python.org/).
 

### 1.3 Manual Installation

```bash
# Create virtual environment (optional)
python -m venv venv

# Linux/Mac
source venv/bin/activate 

# Windows
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 1.4 Install as a Package

The project also ships a `pyproject.toml`, so it can be installed as an editable package instead of running the scripts directly:

```bash
pip install -e .

# now available as a command anywhere in the venv
repo-scanner https://github.com/user/repo.git
```

----
## 2. Usage

### 2.1 Basic Commands

```bash
# Scan remote repository
python run_scanner.py https://github.com/user/repo.git

# Scan local repository
python run_scanner.py /path/to/local/repo

# Quick scan (limited files)
python run_scanner.py https://github.com/user/repo.git --mode quick

# Thorough scan with detailed output
python run_scanner.py https://github.com/user/repo.git --mode thorough --detailed

# Export report to JSON
python run_scanner.py https://github.com/user/repo.git --output report.json

# Check every pinned dependency against OSV.dev's live vulnerability database
python run_scanner.py https://github.com/user/repo.git --check-vulns
```

### 2.2 Command Line Arguments

| Option            | Short | Description                                                                     | Default  |
| ----------------- | ----- | ------------------------------------------------------------------------------- | -------- |
| `--mode`          | `-m`  | Scan mode: quick, balanced, thorough, smart (detail below on types)             | balanced |
| `--output`        | `-o`  | Export report to JSON or CSV file                                               | None     |
| `--verbose`       | `-v`  | Display detailed scan progress                                                  | False    |
| `--detailed`      | `-d`  | Show detailed breakdown in report                                               | False    |
| `--format`        | -     | Report format: simple, multi, categories, detailed, all (detail below on types) | all      |
| `--keep-repo`     | -     | Keep cloned repository after scanning                                           | False    |
| `--auto-decision` | -     | Automatically decide based on risk score                                        | False    |
| `--check-vulns`   | -     | Query OSV.dev for live known vulnerabilities in every pinned dependency (sends dependency names/versions to a third-party service) | False    |

### 2.3 Scan Modes

| Mode         | Description                         | Files Scanned                                                                |
| ------------ | ----------------------------------- | ---------------------------------------------------------------------------- |
| **Quick**    | Fast scanning with size limits      | Files < 1MB, max 10,000                                                      |
| **Balanced** | Moderate coverage with good speed   | All valid files                                                              |
| **Thorough** | Complete scanning                   | All files without limits (will take some time if too many files or big size) |
| **Smart**    | Prioritizes executable/script files | Scripts, binaries, executables                                               |

>[!TIP]
>Use `--mode quick` for CI/CD pipelines and `--mode thorough` for security audits.

### 2.4 Ignoring Known False Positives

Drop a `.reposecurityignore` file in the root of the repository being scanned to skip specific files or paths, one glob pattern per line:

```
# skip test fixtures with fake credentials
tests/fixtures/*
*.sample.env
```

Lines starting with `#` and blank lines are ignored. Patterns match against both the file's path relative to the repo root and its filename.

----
## 3. Report Formats

The scanner supports four report formats, plus an "all" option that displays them sequentially.

### 3.1 Simple Format

Single percentage score with status bar and risk level.

```bash
============================================================
  REPOSITORY: awesome-project
  RISK SCORE: 23.5%  [████████░░░░░░░░░░░░]   LOW RISK
============================================================
```

### 3.2 Multi-Factor Format

Breaks down risk into four categories with individual scores.

```bash
============================================================
  REPOSITORY: awesome-project
  
  MULTI-FACTOR ANALYSIS
  Code Quality:  76.3%  [██████████░░░░░░]
  Security:      76.5%  [██████████░░░░░░]
  Obfuscation:   16.5%  [██░░░░░░░░░░░░░░]
  Malicious:     11.8%  [█░░░░░░░░░░░░░░░]
  
  OVERALL: 23.5%  LOW RISK
============================================================
```

### 3.3 Categories Format

Displays risk category with file breakdown and recommendation.

```bash
============================================================
  REPOSITORY: awesome-project
  
  [LOW] RISK
  
  Risk Level:    [LOW]
  Score:         23.5%
  Findings:      12 issues found
  Files:         0 high, 3 medium, 9 low
  Recommendation: REVIEW BEFORE CLONING
============================================================
```

### 3.4 Detailed Format

Complete report including all findings and statistics.

```bash
============================================================
  REPOSITORY: awesome-project
  
  [LOW] RISK
  
  Risk Level:    [LOW]
  Score:         23.5%
  Findings:      12 issues found
  Files:         0 high, 3 medium, 9 low
  Recommendation: REVIEW BEFORE CLONING
============================================================

FILE BREAKDOWN:
  Safe:        45
  Low Risk:    9
  Medium Risk: 3
  High Risk:   0

STATISTICS:
  Total Files:     57
  Scan Duration:   4.32s
  Findings Found:  12

TOP FINDINGS:
  1. [MEDIUM] encoding: Multiple base64 strings: 8
  2. [MEDIUM] vulnerable_dependency: NPM package 'lodash': Prototype pollution vulnerabilities
  3. [LOW] dangerous_function: Dangerous function: eval
  4. [LOW] network: Network activity: HTTP request
```

---

## 4. Risk Scoring

### 4.1 Risk Levels

|Score|Level|Recommendation|
|---|---|---|
|0-9|SAFE|Safe to clone|
|10-24|LOW RISK|Review before cloning|
|25-49|MEDIUM RISK|Exercise caution|
|50-74|HIGH RISK|Avoid cloning|
|75-100|CRITICAL|Do not clone|

### 4.2 Scoring Factors

|Factor|Maximum Points|Description|
|---|---|---|
|Malicious Patterns|100|Crypto miners, backdoors, exfiltration|
|Dangerous Functions|100|eval, exec, system, subprocess|
|Entropy Analysis|20|High entropy indicates encryption/obfuscation|
|Base64 Encoding|10|Large base64 strings may contain payloads|
|File Size|10|Large files may contain hidden payloads|
|Vulnerable Dependencies|15 per package (20 if confirmed via `--check-vulns`)|Known vulnerable packages|
|Secret Detection|80 per secret|Hardcoded API keys, tokens, passwords, private keys|
|Dockerfile Issues|3-20 per finding|Unpinned images, root user, curl-pipe-bash, hardcoded secrets|

---

## 5. Detection Capabilities

### 5.1 Malicious Pattern Categories

|Category|Example Patterns|
|---|---|
|Crypto Miners|cryptonight, stratum, xmrig, mining, cpuminer|
|Backdoors|socket.bind, socket.connect, base64.b64decode|
|Data Exfiltration|requests.post, discord webhook, smtplib, telegram|
|Obfuscation|base64, zlib, exec(decode), String.fromCharCode|
|Shell Commands|subprocess, os.system, popen, eval|
|Network Activity|socket, requests, urllib, websocket, ftp|
|File Operations|os.remove, shutil.rmtree, file.write, os.chmod|

### 5.2 Language-Specific Detection

|Language|Detected Functions|
|---|---|
|Python|exec, eval, compile, **import**, os.system, subprocess.call, subprocess.Popen, os.popen|
|JavaScript|eval, Function, setTimeout, setInterval, document.write, innerHTML|
|Bash|exec, eval, source, export, alias|
|PHP|eval, system, exec, passthru, shell_exec, assert|
|Ruby|eval, exec, system, ``, IO.popen, Open3|
|Go|os/exec, syscall, reflect, unsafe|
|Rust|std::process, std::fs, unsafe, std::mem|
|Java|Runtime.exec, ProcessBuilder, System.load, Class.forName|

### 5.3 Vulnerable Dependency Detection

Offline (default): checks pinned versions of the packages below against a known-bad floor. A package is only flagged if the pinned version is actually below the fixed version; unpinned or unparseable version specs are skipped rather than guessed at.

| Package Manager | Checked Packages                                  |
| --------------- | ------------------------------------------------- |
| npm             | crypto-js, node-fetch, axios, lodash, request     |
| pip             | requests, urllib3, paramiko, cryptography, pyyaml |

Online (`--check-vulns`): additionally queries the [OSV.dev](https://osv.dev/) API for every pinned dependency in `requirements.txt`/`package.json`, not just the packages above, against its live vulnerability database. Off by default since it sends dependency names and versions to a third-party service.

### 5.4 Secret Detection

Scans every text file for hardcoded credentials: AWS/GitHub/GitLab/Slack/Google/Stripe/Twilio/SendGrid keys, private key blocks, JWTs, and generic `api_key`/`secret`/`token`/`password` assignments. Matches are reported with a file and line number but the value itself is redacted (`AKIA************WXYZ`), never printed in full. Known placeholder values (`EXAMPLE`, `changeme`, `<your_key_here>`, etc.) are filtered out so docs and templates don't trip it. Any confirmed secret pushes that file's risk score into the CRITICAL range on its own.

Add real fixtures containing fake secrets you need to keep to `.reposecurityignore` (see 2.4) to suppress them.

### 5.5 Dockerfile Scanning

Any `Dockerfile`, `Dockerfile.*`, or `*.dockerfile` is additionally checked for:

| Check | What it catches |
|---|---|
| Unpinned base image | `FROM image:latest` or no tag at all |
| Root user | No `USER` instruction, or an explicit `USER root` |
| ADD vs COPY | `ADD` used for a local file instead of `COPY` (ADD's extra behavior is only needed for URLs/archives) |
| Pipe to shell | `curl \| bash`, `wget \| sh`, etc. |
| Insecure TLS | `curl -k`, `--no-check-certificate` |
| Hardcoded secret | `ENV`/`ARG` setting a `PASSWORD`/`SECRET`/`TOKEN`/`API_KEY` directly |

---

## 6. Project Structure

```bash
repo-security-scanner/
├── setup.sh                 # Linux/macOS installer
├── setup.bat                # Windows installer
├── requirements.txt         # Python dependencies
├── pyproject.toml          # Packaging (pip install -e .)
├── README.md                # Documentation
├── LICENSE                  # MIT License
├── .gitignore              # Git ignore file
├── run_scanner.py          # Entry point
├── main.py                 # CLI entry point (main())
│
├── .github/
│   └── workflows/
│       └── tests.yml       # CI: runs the test suite on push/PR
│
├── tests/                   # Unit tests (unittest)
│   ├── test_entropy_calculator.py
│   ├── test_pattern_matcher.py
│   ├── test_dependency_checker.py
│   ├── test_file_utils.py
│   ├── test_scoring.py
│   ├── test_secret_detector.py
│   └── test_dockerfile_scanner.py
│
└── repo_scanner/           # Main package
    ├── __init__.py
    ├── config.py           # Configuration and constants
    ├── cli/                # Command-line interface
    │   ├── __init__.py
    │   └── arguments.py    # Argument parsing
    │
    ├── scanner/            # Core scanning modules
    │   ├── __init__.py
    │   ├── core.py         # Scanner orchestrator
    │   ├── file_analyzer.py # Individual file analysis
    │   ├── pattern_matcher.py # Pattern detection engine
    │   ├── dependency_checker.py # Dependency scanning (offline + OSV.dev)
    │   ├── entropy_calculator.py # Entropy analysis
    │   ├── secret_detector.py # Credential/API key/token detection
    │   └── dockerfile_scanner.py # Dockerfile security linting
    │
    ├── report/             # Report generation
    │   ├── __init__.py
    │   ├── formatter.py    # Output formatting
    │   └── exporters.py    # JSON/CSV export
    │
    ├── models/             # Data models
    │   ├── __init__.py
    │   └── scan_result.py  # Result data structures
    │
    └── utils/              # Utility functions
        ├── __init__.py
        ├── file_utils.py   # File operations, .reposecurityignore
        └── git_utils.py    # Git operations
```

---

## 7. Troubleshooting

|Problem|Check|Solution|
|---|---|---|
|Python not found|Python installed?|Install Python 3.8+ from [python.org](https://python.org/)|
|ModuleNotFoundError|Dependencies installed?|Run `pip install -r requirements.txt`|
|Git clone failed|Git installed?|Install Git from [git-scm.com](https://git-scm.com/)|
|Permission denied|File permissions?|`chmod +x setup.sh` (Linux/macOS)|
|Scan takes too long|Large repository?|Use `--mode quick` or `--mode smart`|
|Report not generated|Output path valid?|Check write permissions for output directory|
|High entropy warnings|False positives?|Review the file manually, may be legitimate. Add it to `.reposecurityignore` to suppress it going forward|

---

## 8. Future Enhancements

- [x] Secret detection - API keys, passwords, tokens, credentials
- [x] Dockerfile scanning - insecure base images, root user, secrets in ENV/ARG, curl-pipe-bash
- [ ] Git history analysis - scan commit history for secrets and keys
- [ ] License checker - detect incompatible or restrictive licenses
- [ ] Binary signature analysis - verify binaries from trusted sources
- [ ] Database of known malicious repositories
- [ ] Package registry scanning (PyPI, npm, RubyGems)


-----

## 9. Contributing and Bugs

### 9.1 Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/AmazingFeature`
3. Run the test suite locally: `python -m unittest discover -s tests -v`
4. Commit your changes: `git commit -m 'Add some AmazingFeature'`
5. Push to the branch: `git push origin feature/AmazingFeature`
6. Submit a Pull Request

> [!note]  
> All pull requests must pass the CI checks (.github/workflows/tests.yml, run on Python 3.8 and 3.12) and maintain 100% compatibility with Python 3.8+.

### 9.2 Reporting Issues

When reporting issues on GitHub, include:

- Description of the issue
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (OS, Python version)
- Logs or screenshots (if applicable)

This all so I can work on those bugs and make the tool better.
