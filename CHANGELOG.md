# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the version is below 1.0.0, a minor bump may contain breaking changes.

## [0.2.0] - 2026-09-20

### Added

- SARIF 2.1.0 export, selected by a `.sarif` extension on `--output`. GitHub Code Scanning renders it natively, so findings appear in the Security tab. Each category becomes a rule, each finding a result, with `region.startLine` where a line is known.
- Cautions: a separate channel for hygiene checks that never affects the risk score. Cautions print under their own heading, are counted separately, appear as a `cautions` array in JSON, and are appended to CSV.
- `CAUTION_CATEGORIES` in `config.py` as the single list controlling which checks are cautions. Moving a check in or out is a one line edit.
- File path and line number on every finding. Malicious patterns, dangerous functions, base64 findings, network calls and both dependency manifests now report a line. Previously only secrets and Dockerfile findings did.
- `scan_root` on `ScanSummary`, used to make SARIF paths relative to the scanned repository.
- `docs/DETECTION_CAPABILITIES.md` with the full pattern lists, package lists and per-check behavior, moved out of the README.
- Tests for cautions, the SARIF exporter, formatter location display, and long line handling. The suite went from 65 to 92 tests.

### Changed

- **Long lines are no longer scored.** They are reported as cautions on every file type. A long line in a prose paragraph, a minified asset or a single line JSON file is normal formatting, and scoring it produced false positives on docs and data files.
- **Unpinned base images and ADD vs COPY are no longer scored.** Both moved to cautions as reproducibility and style issues. Exploitable Dockerfile checks (curl piped to a shell, disabled TLS verification, a credential baked into `ENV` or `ARG`, running as root) still score.
- `network`, `size` and `error` findings moved to cautions.
- Version is read from package metadata with `importlib.metadata` instead of a hardcoded string, so `pyproject.toml` is the only place a release is bumped.
- README is PyPI first. Installation now covers `pip install repo-security-scanner` and a from source path, and usage examples call `repo-scanner` instead of `python run_scanner.py`.
- Detection capabilities in the README reduced to a summary table linking to the new reference doc.

### Fixed

- SARIF emitted absolute paths such as `C:/Users/.../Temp/tmp123/app.py`. GitHub Code Scanning matches results by repository relative path, so every result failed to link. Paths are now relative to the scan root.
- SARIF path separator normalization used `pathlib.PurePath`, which only treats a backslash as a separator on Windows. On Linux CI the backslashes survived into the output. Normalization is now explicit and platform independent.
- SARIF rule metadata took its level from whichever finding of that category was emitted first, so a category whose first instance was low advertised `note` even when a critical instance followed. The rule level is now the most severe level the category produces.
- A finding without a line number also lost its file path in the detailed report and the interactive findings list, because the guard was `if finding.line`. The path now always shows.
- A Dockerfile check scoring exactly 20, such as curl piped to a shell, was labelled low and exported as the quietest SARIF level. The threshold is now inclusive.

### Removed

- `setup.sh` and `setup.bat`. `pyproject.toml` declares `requires-python`, and pip enforces it, so the hand rolled version checks and dependency installs were duplicating packaging.
- `SCORE_LONG_LINE`, `SCORE_EXTREMELY_LONG_LINE`, `SCORE_DOCKER_LATEST_TAG` and `SCORE_DOCKER_ADD_VS_COPY`, now that those checks are cautions.
- An unused local variable in `format_simple` and an unused `Finding` import in `core.py`.

## [0.1.1] - 2026-09-17

### Fixed

- Multi stage Docker builds were falsely flagged. A `FROM builder` referring to an earlier `AS builder` stage was treated as an unpinned external image.
- `ADD --chown=user:group <url>` was falsely flagged as ADD vs COPY, because the regex captured the flag as the source instead of the real one.
- Hardcoded credentials on a multi variable `ENV` or `ARG` line were missed unless they were the first assignment on the line.
- `USER 0` and `USER 0:0`, the numeric root UID, were not recognized as running as root.
- `--keep-repo` ignored the interactive prompt's answer and could contradict it. The interactive decision is now authoritative, and `--keep-repo` applies when `--auto-decision` is set.
- Interactive prompts asked whether to clone a repository that was already a local path with nothing to clone.

### Added

- `.github/SECURITY.md` pointing at GitHub private vulnerability reporting, plus issue templates for bugs, features and false positives, and a pull request template.
- `docs/SCORING_AND_FORMATS.md` with the full scoring breakdown and report format samples.

## [0.1.0] - 2026-09-17

First PyPI release, published with Trusted Publishing.

### Added

- Secret detection for AWS, GitHub, GitLab, Slack, Google, Stripe, Twilio and SendGrid keys, private key blocks, JWTs and generic credential assignments. Values are redacted in every output path, and known placeholders such as `EXAMPLE` or `changeme` are filtered out.
- Dockerfile scanning for unpinned base images, root user, ADD vs COPY, remote downloads piped into a shell, disabled TLS verification and credentials in `ENV` or `ARG`.
- Line numbers on findings, carried through JSON and CSV export.
- `pyproject.toml` packaging with a `repo-scanner` console script, and a Trusted Publishing workflow.
- A unit test suite and a GitHub Actions workflow running it on Python 3.8 and 3.12.
- `.reposecurityignore` support for suppressing known false positives.
- Live dependency vulnerability lookups against OSV.dev behind the opt in `--check-vulns` flag.

### Fixed

- The overall risk score averaged every file, so one critical file in a large repository was diluted to a safe score. It now reports the maximum file score.
- Dependency checks flagged packages without reading the version, so any project listing `requests` or `axios` was reported as vulnerable regardless of the version installed.
- `git clone` was called without a `--` separator, allowing an argument starting with a dash to be parsed as a git option, and without a timeout.
- Cloned temporary directories leaked on Windows, because read only files under `.git` made `shutil.rmtree` fail silently.
- A broken symlink aborted the entire scan through an unguarded `stat()` call.
- Findings were truncated to 50 without sorting, so real findings could be crowded out by noise.
- `.` in the bash dangerous function list matched nearly every shell script.
- Duplicate patterns across categories scored the same match twice.
- Repository name parsing broke on Windows paths.
- An unsupported `--output` extension reported success while writing nothing.
- UTF-16 text files were classified as binary, which skipped secret and pattern matching on them.

### Changed

- Trimmed unused dependencies. Only `colorama` and `tqdm` remain.
- Replaced diagnostic `print` calls with `logging`, precompiled regex patterns, and moved file scanning onto a thread pool.

[0.2.0]: https://github.com/MR-UNKNOWN8014/repo-security-scanner/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/MR-UNKNOWN8014/repo-security-scanner/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/MR-UNKNOWN8014/repo-security-scanner/releases/tag/v0.1.0
