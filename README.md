# Repository Security Scanner

![CI](https://github.com/MR-UNKNOWN8014/repo-security-scanner/actions/workflows/tests.yml/badge.svg)
![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![PyPI](https://img.shields.io/pypi/v/repo-security-scanner?cacheSeconds=3600)
![Stars](https://img.shields.io/github/stars/MR-UNKNOWN8014/repo-security-scanner?style=social)

Scan a Git repository for malware, backdoors, and sketchy dependencies before you clone it. Static analysis, OSV.dev vulnerability checks, secret detection, entropy analysis, and Dockerfile linting in a single Python CLI.

The scanner flags:

- Crypto miner patterns
- Backdoor signatures
- Data exfiltration code
- Obfuscation techniques
- Dangerous function calls
- Vulnerable dependencies
- High-entropy (encrypted or obfuscated) files
- Hardcoded secrets and API keys
- Insecure Dockerfile patterns

## Why?

Cloning a repo to audit it is already too late. Postinstall scripts, Makefiles, and CI configs run before you ever open the code. This tool scans before `git clone` completes, so you know what you are pulling in before it touches your machine.

Existing tools split the problem. gitleaks and trufflehog focus on secrets. semgrep and bandit focus on your own code. Neither answers the question you actually have when you find a random repo: is this safe to run?

## How it compares

| Tool                  | Secrets | Malware | Deps | Entropy | Pre-clone |
| --------------------- | ------- | ------- | ---- | ------- | --------- |
| gitleaks              | Yes     | No      | No   | No      | No        |
| trufflehog            | Yes     | No      | No   | No      | Partial   |
| semgrep               | No      | Partial | No   | No      | No        |
| repo-security-scanner | Yes     | Yes     | Yes  | Yes     | Yes       |

## Quick Start

```bash
git clone https://github.com/MR-UNKNOWN8014/repo-security-scanner.git
cd repo-security-scanner

./setup.sh          # Linux/macOS
setup.bat           # Windows

python run_scanner.py https://github.com/user/repo.git
```

Or install straight from PyPI:

```bash
pip install repo-security-scanner
repo-scanner https://github.com/user/repo.git
```

## Installation

**Requires Python 3.8 or higher.**

### Automated installer

Linux and macOS:

```bash
chmod +x setup.sh
./setup.sh
```

Windows:

```bash
setup.bat
```

The installer verifies your Python version, installs dependencies, and creates the run script. If Python is not on your PATH, it will point you at 3.8+ from [python.org](https://python.org/).

### Manual install

```bash
python -m venv venv

source venv/bin/activate     # Linux/macOS
venv\Scripts\activate        # Windows

pip install -r requirements.txt
```

### As a package

The project ships a `pyproject.toml`, so you can install it as a CLI instead of running scripts directly:

```bash
pip install -e .
repo-scanner https://github.com/user/repo.git
```

## Usage

### Basic commands

```bash
# Remote repository
python run_scanner.py https://github.com/user/repo.git

# Local path
python run_scanner.py /path/to/local/repo

# Quick scan (size limited, good for CI)
python run_scanner.py https://github.com/user/repo.git --mode quick

# Thorough scan with detailed output
python run_scanner.py https://github.com/user/repo.git --mode thorough --detailed

# Export report to JSON
python run_scanner.py https://github.com/user/repo.git --output report.json

# Query OSV.dev for live dependency vulnerabilities
python run_scanner.py https://github.com/user/repo.git --check-vulns
```

### Arguments

| Option            | Short | Description                                                                           | Default  |
| ----------------- | ----- | ------------------------------------------------------------------------------------- | -------- |
| `--mode`          | `-m`  | Scan mode: quick, balanced, thorough, smart                                           | balanced |
| `--output`        | `-o`  | Export report to JSON or CSV                                                          | None     |
| `--verbose`       | `-v`  | Show detailed scan progress                                                           | False    |
| `--detailed`      | `-d`  | Show detailed breakdown in report                                                     | False    |
| `--format`        |       | Report format: simple, multi, categories, detailed, all                               | all      |
| `--keep-repo`     |       | Keep cloned repo after scanning. Only effective with `--auto-decision`; interactively, your answer decides. | False    |
| `--auto-decision` |       | Automatically decide based on risk score                                              | False    |
| `--check-vulns`   |       | Query OSV.dev for every pinned dependency. Sends names and versions to a third party. | False    |

### Scan modes

| Mode     | Behavior                    | Files scanned                             |
| -------- | --------------------------- | ----------------------------------------- |
| Quick    | Fast, size limited          | Files under 1 MB, max 10,000              |
| Balanced | Moderate coverage and speed | All valid files                           |
| Thorough | Everything                  | No limits. Will take time on large repos. |
| Smart    | Prioritizes executables     | Scripts, binaries, executables            |

For CI pipelines, `--mode quick` is usually enough. For a full audit, use `--mode thorough`.

### Ignoring known false positives

Drop a `.reposecurityignore` in the root of the repo being scanned. One glob pattern per line:

```
# skip test fixtures with fake credentials
tests/fixtures/*
*.sample.env
```

Lines starting with `#` and blank lines are ignored. Patterns match both the path relative to the repo root and the filename.

## Detection capabilities

### Malicious pattern categories

| Category          | Example patterns                                  |
| ----------------- | ------------------------------------------------- |
| Crypto miners     | cryptonight, stratum, xmrig, mining, cpuminer     |
| Backdoors         | socket.bind, socket.connect, base64.b64decode     |
| Data exfiltration | requests.post, discord webhook, smtplib, telegram |
| Obfuscation       | base64, zlib, exec(decode), String.fromCharCode   |
| Shell commands    | subprocess, os.system, popen, eval                |
| Network activity  | socket, requests, urllib, websocket, ftp          |
| File operations   | os.remove, shutil.rmtree, file.write, os.chmod    |

### Language-specific detection

| Language   | Detected functions                                                                        |
| ---------- | ----------------------------------------------------------------------------------------- |
| Python     | exec, eval, compile, `__import__`, os.system, subprocess.call, subprocess.Popen, os.popen |
| JavaScript | eval, Function, setTimeout, setInterval, document.write, innerHTML                        |
| Bash       | exec, eval, source, export, alias                                                         |
| PHP        | eval, system, exec, passthru, shell_exec, assert                                          |
| Ruby       | eval, exec, system, backticks, IO.popen, Open3                                            |
| Go         | os/exec, syscall, reflect, unsafe                                                         |
| Rust       | std::process, std::fs, unsafe, std::mem                                                   |
| Java       | Runtime.exec, ProcessBuilder, System.load, Class.forName                                  |

### Vulnerable dependencies

Offline (default): checks pinned versions of a curated list against known-bad floors. A package is only flagged if the pinned version is actually below the fixed version. Unpinned or unparseable specs are skipped rather than guessed at.

| Manager | Checked packages                                  |
| ------- | ------------------------------------------------- |
| npm     | crypto-js, node-fetch, axios, lodash, request     |
| pip     | requests, urllib3, paramiko, cryptography, pyyaml |

Online (`--check-vulns`): queries [OSV.dev](https://osv.dev/) for every pinned dependency in `requirements.txt` and `package.json`, not just the list above. Off by default because it sends dependency names and versions to a third party.

### Secret detection

Scans every text file for hardcoded credentials: AWS, GitHub, GitLab, Slack, Google, Stripe, Twilio, and SendGrid keys, private key blocks, JWTs, and generic `api_key` / `secret` / `token` / `password` assignments. Findings report a file and line number, but the value itself is redacted (first and last few characters only). Known placeholder values such as `EXAMPLE`, `changeme`, or `<your_key_here>` are filtered out so docs and templates do not trip it.

A single confirmed secret pushes that file's risk score into the CRITICAL range on its own.

### Dockerfile scanning

Any `Dockerfile`, `Dockerfile.*`, or `*.dockerfile` is additionally checked for:

| Check               | What it catches                                                               |
| ------------------- | ----------------------------------------------------------------------------- |
| Unpinned base image | `FROM image:latest` or no tag at all                                          |
| Root user           | No `USER` instruction, or explicit `USER root`                                |
| ADD vs COPY         | `ADD` used for a local file where `COPY` would work                           |
| Pipe to shell       | `curl \| bash`, `wget \| sh`, and similar                                     |
| Insecure TLS        | `curl -k`, `--no-check-certificate`                                           |
| Hardcoded secret    | `ENV` or `ARG` setting a `PASSWORD`, `SECRET`, `TOKEN`, or `API_KEY` directly |

## Risk scoring

Scores run 0 to 100. Higher means more risk.

| Score  | Level       | Recommendation        |
| ------ | ----------- | --------------------- |
| 0-9    | SAFE        | Safe to clone         |
| 10-24  | LOW RISK    | Review before cloning |
| 25-49  | MEDIUM RISK | Exercise caution      |
| 50-74  | HIGH RISK   | Avoid cloning         |
| 75-100 | CRITICAL    | Do not clone          |

The score is weighted by category. Malicious patterns and dangerous functions dominate. Entropy, base64, and file size are secondary signals. Vulnerable dependencies and Dockerfile findings add per-package or per-finding penalties. A confirmed secret can single-handedly push a file to CRITICAL.

Full breakdown: [docs/SCORING_AND_FORMATS.md](docs/SCORING_AND_FORMATS.md#risk-scoring).

## Report formats

Four formats, plus an `all` option that prints them in sequence:

- **simple**: one line with risk score, bar, and level
- **multi**: four-factor breakdown (code quality, security, obfuscation, malicious)
- **categories**: risk level, score, and file breakdown by severity
- **detailed**: everything above, plus file stats and top findings

```bash
repo-scanner https://github.com/user/repo.git --format simple
repo-scanner https://github.com/user/repo.git --format detailed
```

Sample output for each format lives in [docs/SCORING_AND_FORMATS.md](docs/SCORING_AND_FORMATS.md#report-formats).

JSON and CSV export are separate from the display format:

```bash
repo-scanner https://github.com/user/repo.git --output report.json
repo-scanner https://github.com/user/repo.git --output report.csv
```

## Limitations

- Static analysis only. Obfuscated or packed payloads can evade detection.
- Pattern based detection produces false positives. Always review flagged files.
- Not a replacement for sandboxing or VM isolation when running untrusted code.
- Entropy detection is tuned to be sensitive. High entropy is a signal, not proof.
- Offline dependency checks cover a small curated list. Use `--check-vulns` for full coverage.

## Project structure

```
repo-security-scanner/
├── setup.sh                     # Linux/macOS installer
├── setup.bat                    # Windows installer
├── requirements.txt             # Python dependencies
├── pyproject.toml               # Packaging
├── README.md
├── LICENSE
├── run_scanner.py               # Entry point
├── main.py                      # CLI entry point
│
├── .github/
│   ├── SECURITY.md               # Vulnerability reporting policy
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   ├── feature_request.md
│   │   ├── false_positive.md
│   │   └── config.yml
│   └── workflows/
│       ├── tests.yml            # CI: test suite on push/PR
│       └── publish.yml          # Publish to PyPI on GitHub Release
│
├── docs/
│   └── SCORING_AND_FORMATS.md   # Risk scoring and report format docs
│
├── tests/
│   ├── test_entropy_calculator.py
│   ├── test_pattern_matcher.py
│   ├── test_dependency_checker.py
│   ├── test_file_utils.py
│   ├── test_scoring.py
│   ├── test_secret_detector.py
│   └── test_dockerfile_scanner.py
│
└── repo_scanner/
    ├── __init__.py
    ├── config.py
    ├── cli/
    │   └── arguments.py
    ├── scanner/
    │   ├── core.py
    │   ├── file_analyzer.py
    │   ├── pattern_matcher.py
    │   ├── dependency_checker.py
    │   ├── entropy_calculator.py
    │   ├── secret_detector.py
    │   └── dockerfile_scanner.py
    ├── report/
    │   ├── formatter.py
    │   └── exporters.py
    ├── models/
    │   └── scan_result.py
    └── utils/
        ├── file_utils.py
        └── git_utils.py
```

## Troubleshooting

| Problem              | Check                   | Solution                                                              |
| -------------------- | ----------------------- | --------------------------------------------------------------------- |
| Python not found     | Python installed?       | Install Python 3.8+ from [python.org](https://python.org/)            |
| ModuleNotFoundError  | Dependencies installed? | Run `pip install -r requirements.txt`                                 |
| Git clone failed     | Git installed?          | Install Git from [git-scm.com](https://git-scm.com/)                  |
| Permission denied    | File permissions?       | `chmod +x setup.sh` (Linux/macOS)                                     |
| Scan takes too long  | Large repository?       | Use `--mode quick` or `--mode smart`                                  |
| Report not generated | Output path valid?      | Check write permissions for the output directory                      |
| Entropy warnings     | False positives?        | Review the file. If it is legitimate, add it to `.reposecurityignore` |

## Contributing

Pull requests welcome.

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Run the tests: `python -m unittest discover -s tests -v`
4. Commit: `git commit -m 'Add my feature'`
5. Push: `git push origin feature/my-feature`
6. Open a Pull Request

All PRs must pass CI (`.github/workflows/tests.yml`, Python 3.8 and 3.12) and stay compatible with Python 3.8+.

## Reporting issues

When filing a bug, include:

- What you expected
- What actually happened
- Steps to reproduce
- OS and Python version
- Relevant logs or screenshots

## License

MIT. See [LICENSE](LICENSE).
