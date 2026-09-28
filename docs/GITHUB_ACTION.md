# GitHub Action

Run the scanner in CI. The action installs `repo-security-scanner` from PyPI, scans a repository, and exposes the result as step outputs.

## Contents

- [Quick use](#quick-use)
- [Scan a third party repository](#scan-a-third-party-repository)
- [Upload to GitHub Code Scanning](#upload-to-github-code-scanning)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Exit behavior](#exit-behavior)
- [Design notes](#design-notes)

---

## Quick use

Scan your own repository on every push:

```yaml
name: Security scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: MR-UNKNOWN8014/repo-security-scanner@v1
        with:
          mode: quick
          fail-on: high
```

With no `repository` input the action scans the checked out workspace, so `actions/checkout` has to run first.

## Scan a third party repository

Vet a dependency or a repository you are about to trust. No checkout needed, the scanner clones it itself:

```yaml
- id: scan
  uses: MR-UNKNOWN8014/repo-security-scanner@v1
  with:
    repository: https://github.com/some-user/some-repo
    mode: balanced
    fail-on: critical

- run: echo "score ${{ steps.scan.outputs.risk-score }} (${{ steps.scan.outputs.risk-level }})"
```

## Upload to GitHub Code Scanning

Request SARIF and hand it to the CodeQL upload action. Findings then appear in the repository Security tab with file and line links:

```yaml
- uses: MR-UNKNOWN8014/repo-security-scanner@v1
  with:
    output-sarif: results.sarif
    fail-on: none

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

`fail-on: none` is useful here, because you usually want the findings uploaded rather than the job stopped. Uploading SARIF needs `security-events: write` on the job.

Both reports come from a single scan. The JSON report is always written, because the outputs are read from it.

## Inputs

| Input            | Description                                                          | Default                    |
| ---------------- | -------------------------------------------------------------------- | -------------------------- |
| `repository`     | Repository URL or local path. Defaults to the checked out workspace   | `.`                        |
| `mode`           | Scan mode: `quick`, `balanced`, `thorough`, `smart`                  | `quick`                    |
| `fail-on`        | Fail the job at this level: `none`, `low`, `medium`, `high`, `critical` | `high`                   |
| `check-vulns`    | Query OSV.dev for live vulnerability data, sends dependency names and versions to a third party | `false` |
| `output-json`    | Path for the JSON report, always written                             | `repo-scanner-report.json` |
| `output-sarif`   | Path for a SARIF report, empty disables it                           | empty                      |
| `version`        | Scanner version to install, for example `0.3.0`. Empty installs the latest | empty                 |
| `python-version` | Python used to run the scanner                                       | `3.12`                     |

Pin `version` if you want reproducible CI. Leaving it empty picks up new releases automatically, including new detection patterns that may change your score.

## Outputs

| Output               | Description                                            |
| -------------------- | ------------------------------------------------------ |
| `risk-score`         | Numeric score, 0 to 100                                |
| `risk-level`         | `safe`, `low`, `medium`, `high`, `critical`             |
| `findings-count`     | Total findings, before the report truncates            |
| `cautions-count`     | Total best practice cautions, which never affect score |
| `threshold-exceeded` | `true` when the score reached `fail-on`                |
| `report-json`        | Path to the JSON report                                |

The action also writes a job summary with the score, the counts, and the top ten findings with their file and line.

## Exit behavior

| Situation                              | Job result                          |
| -------------------------------------- | ----------------------------------- |
| Score below `fail-on`                  | passes, `threshold-exceeded=false`  |
| Score at or above `fail-on`            | fails, `threshold-exceeded=true`    |
| `fail-on: none`                        | passes regardless of score          |
| Scan could not complete                | fails with an `::error::` annotation |

A scan failure and a threshold breach are different exits, 2 and 1, so a broken scan never reads as a clean repository. Use `fail-on: none` when you want reporting without gating, not as a way to ignore errors, since a genuine scan failure still fails the job.

## Design notes

Three choices worth knowing if you fork or modify this:

1. **Outputs are read from the JSON report, not parsed out of the terminal output.** Scraping `RISK SCORE:` with grep looks simpler but couples the action to report formatting, and `RISK LEVEL:` only appears in one of the five formats, so a grep for it silently yields an empty value.
2. **Inputs reach the shell through `env:`,** never interpolated as `${{ inputs.* }}` inside `run:`. Interpolation puts caller controlled text directly into a shell command.
3. **`--auto-decision` is always passed.** Without it the scanner would reach its interactive prompt and hang the job waiting for input that never arrives.
