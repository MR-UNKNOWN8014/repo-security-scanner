# Risk Scoring and Report Formats

Reference for how the scanner assigns risk scores and what each output format contains. The README only summarizes these. This file has the full detail.

## Contents

- [Risk Scoring](#risk-scoring)
- [Report Formats](#report-formats)

---

## Risk Scoring

Scores run from 0 to 100. Higher means more risk. The score aggregates weighted findings from every file, then maps to one of five risk levels.

### Risk levels

| Score  | Level       | Recommendation        |
| ------ | ----------- | --------------------- |
| 0-9    | SAFE        | Safe to clone         |
| 10-24  | LOW RISK    | Review before cloning |
| 25-49  | MEDIUM RISK | Exercise caution      |
| 50-74  | HIGH RISK   | Avoid cloning         |
| 75-100 | CRITICAL    | Do not clone          |

### Scoring factors

| Factor                  | Maximum points                                            | Description                                                         |
| ----------------------- | --------------------------------------------------------- | ------------------------------------------------------------------- |
| Malicious patterns      | 100                                                       | Crypto miners, backdoors, exfiltration signatures                   |
| Dangerous functions     | 100                                                       | eval, exec, system, subprocess, and language equivalents            |
| Entropy analysis        | 20                                                        | High entropy suggests encryption or obfuscation                     |
| Base64 encoding         | 10                                                        | Large base64 blocks may hide payloads                               |
| File size               | 10                                                        | Unusually large files can conceal appended payloads                 |
| Vulnerable dependencies | 15 per package (20 if confirmed live via `--check-vulns`) | Pinned versions below a known-bad floor, or matched against OSV.dev |
| Secret detection        | 80 per secret                                             | Any confirmed hardcoded credential                                  |
| Dockerfile issues       | 3 to 20 per finding                                       | Depends on severity of the specific check                           |

### How the factors combine

Each factor contributes independently, but they are not equally important.

Malicious patterns and dangerous functions are the heavy hitters. A single confirmed backdoor signature can push a repository into HIGH or CRITICAL on its own. Secret detection is a near-instant CRITICAL: 80 points from one hardcoded AWS key usually lands the file in the top band.

Entropy, base64, and file size are secondary signals. They rarely push a score past LOW by themselves, but they stack when a file looks suspicious in multiple ways. A file with high entropy, a large base64 blob, and an odd size is far more interesting than any one of those alone.

Vulnerable dependencies and Dockerfile issues are additive per finding. A Dockerfile with three separate issues (unpinned base image, root user, curl pipe bash) accumulates all three penalties. Ten vulnerable npm packages at 15 points each is 150 points before anything else is considered. That is why dependency hygiene matters.

### Interpretation tips

- Score under 10: no action needed. Standard `git clone`.
- Score 10 to 24: skim the flagged files before running anything.
- Score 25 to 49: treat as untrusted. Consider a sandbox or VM.
- Score 50 to 74: do not run on a primary machine. Use a disposable environment if you must.
- Score 75 and above: assume malicious until proven otherwise.

A high score driven by a single category, for example a pile of dependency findings in an otherwise clean repo, behaves differently from a high score spread across categories. Check the multi-factor report to see which side is doing the lifting.

---

## Report Formats

Four display formats plus `all`. Each one shows a different slice of the same underlying data.

Set with `--format`:

```bash
repo-scanner https://github.com/user/repo.git --format simple
repo-scanner https://github.com/user/repo.git --format multi
repo-scanner https://github.com/user/repo.git --format categories
repo-scanner https://github.com/user/repo.git --format detailed
repo-scanner https://github.com/user/repo.git --format all
```

`all` runs all four in sequence. Useful when you want the full picture in one shot.

### simple

One line summary. Score, bar, and level.

```
============================================================
  REPOSITORY: awesome-project
  RISK SCORE: 23.5%  [########------------]   LOW RISK
============================================================
```

Use this for CI output or when you only care about the headline number.

### multi

Four-factor breakdown. Shows how much of the score comes from each dimension of the analysis.

```
============================================================
  REPOSITORY: awesome-project

  MULTI-FACTOR ANALYSIS
  Code Quality:  76.3%  [##########------]
  Security:      76.5%  [##########------]
  Obfuscation:   16.5%  [##--------------]
  Malicious:     11.8%  [#---------------]

  OVERALL: 23.5%  LOW RISK
============================================================
```

Useful when a score is borderline. It tells you whether the repo looks dangerous because of intentional malice or because of poor hygiene.

- Code Quality covers file size, structure, and general smell.
- Security covers dangerous functions and dependency issues.
- Obfuscation covers entropy and base64 encoding.
- Malicious covers explicit malware and backdoor signatures.

### categories

Risk level, score, and a per-severity file breakdown.

```
============================================================
  REPOSITORY: awesome-project

  [LOW] RISK

  Risk Level:     [LOW]
  Score:          23.5%
  Findings:       12 issues found
  Files:          0 high, 3 medium, 9 low
  Recommendation: REVIEW BEFORE CLONING
============================================================
```

The per-severity counts give you a sense of how spread out the findings are. One high-risk file is a different story from twelve low-risk files.

### detailed

Everything from `categories` plus file statistics and the top findings.

```
============================================================
  REPOSITORY: awesome-project

  [LOW] RISK

  Risk Level:     [LOW]
  Score:          23.5%
  Findings:       12 issues found
  Files:          0 high, 3 medium, 9 low
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
  2. [MEDIUM] vulnerable_dependency: NPM package 'lodash': Prototype pollution
  3. [LOW] dangerous_function: Dangerous function: eval
  4. [LOW] network: Network activity: HTTP request
  5. [CRITICAL] app/config.py:42 secret: AWS Access Key ID detected: AKIA************WXYZ
```

This is the format to use when you are actually triaging. It gives the finding list without dumping every single match. Findings that carry a line number (secrets, Dockerfile issues) show it as a `file:line` prefix before the category; findings without one (most pattern/entropy/dependency checks) just show the category.

### JSON and CSV export

Display format and export format are independent. `--format` controls what prints to the terminal. `--output` writes a report to disk.

```bash
# JSON
repo-scanner https://github.com/user/repo.git --output report.json

# CSV
repo-scanner https://github.com/user/repo.git --output report.csv
```

JSON includes the full finding list with file paths, line numbers, categories, and severities. CSV flattens the same data into rows for spreadsheet review or downstream parsing.
