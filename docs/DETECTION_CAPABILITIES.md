# Detection Capabilities

What the scanner looks for, and how each check behaves. The README summarizes this; the full lists live here.

## Contents

- [Malicious pattern categories](#malicious-pattern-categories)
- [Language-specific detection](#language-specific-detection)
- [Vulnerable dependencies](#vulnerable-dependencies)
- [Secret detection](#secret-detection)
- [Dockerfile scanning](#dockerfile-scanning)
- [Long lines](#long-lines)

---

## Malicious pattern categories

| Category          | Example patterns                                  |
| ----------------- | ------------------------------------------------- |
| Crypto miners     | cryptonight, stratum, xmrig, mining, cpuminer     |
| Backdoors         | socket.bind, socket.connect, base64.b64decode     |
| Data exfiltration | requests.post, discord webhook, smtplib, telegram |
| Obfuscation       | base64, zlib, exec(decode), String.fromCharCode   |
| Shell commands    | subprocess, os.system, popen, eval                |
| Network activity  | socket, requests, urllib, websocket, ftp          |
| File operations   | os.remove, shutil.rmtree, file.write, os.chmod    |

Each pattern scores once per file, not once per occurrence, and reports the line of its first match.

## Language-specific detection

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

## Vulnerable dependencies

Offline (default): checks pinned versions of a curated list against known-bad floors. A package is only flagged if the pinned version is actually below the fixed version. Unpinned or unparseable specs are skipped rather than guessed at.

| Manager | Checked packages                                  |
| ------- | ------------------------------------------------- |
| npm     | crypto-js, node-fetch, axios, lodash, request     |
| pip     | requests, urllib3, paramiko, cryptography, pyyaml |

Online (`--check-vulns`): queries [OSV.dev](https://osv.dev/) for every pinned dependency in `requirements.txt` and `package.json`, not just the list above. Off by default because it sends dependency names and versions to a third party.

## Secret detection

Scans every text file for hardcoded credentials: AWS, GitHub, GitLab, Slack, Google, Stripe, Twilio, and SendGrid keys, private key blocks, JWTs, and generic `api_key` / `secret` / `token` / `password` assignments. Findings report a file and line number, but the value itself is redacted (first and last few characters only). Known placeholder values such as `EXAMPLE`, `changeme`, or `<your_key_here>` are filtered out so docs and templates do not trip it.

A single confirmed secret pushes that file's risk score into the CRITICAL range on its own.

## Dockerfile scanning

Any `Dockerfile`, `Dockerfile.*`, or `*.dockerfile` is additionally checked for:

| Check               | What it catches                                                               | Reported as |
| ------------------- | ----------------------------------------------------------------------------- | ----------- |
| Pipe to shell       | `curl \| bash`, `wget \| sh`, and similar                                     | Finding     |
| Insecure TLS        | `curl -k`, `--no-check-certificate`                                           | Finding     |
| Hardcoded secret    | `ENV` or `ARG` setting a `PASSWORD`, `SECRET`, `TOKEN`, or `API_KEY` directly | Finding     |
| Root user           | No `USER` instruction, explicit `USER root`, or the numeric root UID `USER 0` | Finding     |
| Unpinned base image | `FROM image:latest` or no tag at all                                          | Caution     |
| ADD vs COPY         | `ADD` used for a local file where `COPY` would work                           | Caution     |

The first four are exploitable, so they score. The last two are hygiene and reproducibility, so they are cautions and score zero.

Multi-stage builds are understood: a `FROM builder` that refers to an earlier `AS builder` stage is not treated as an unpinned external image.

## What counts as a caution

Cautions are hygiene notes, not exploitable problems. They score zero, print under their own `CAUTIONS` heading, and are counted separately. Current caution categories, listed in `CAUTION_CATEGORIES` in `config.py`:

| Category                         | Why it is a caution                                  |
| -------------------------------- | ---------------------------------------------------- |
| `long_line`                      | Prose, minified assets and single-line data are long |
| `network`                        | Making HTTP calls is normal in most code             |
| `size`                           | A large file is a fact, not a threat                 |
| `error`                          | A file that could not be read is an operational note |
| `dockerfile_unpinned_base_image` | Reproducibility, not an exploit                      |
| `dockerfile_add_vs_copy`         | Style preference                                     |

Moving a check in or out of this set is a one line edit.

## Long lines

Lines over 500 characters (and over 1000) are reported as `long_line` **cautions**, on every file type. They score zero and are listed separately from findings, under `CAUTIONS` in the detailed report. Prose paragraphs, minified assets and single-line JSON are legitimately long, so scoring them produced false positives on docs and data files. See [SCORING_AND_FORMATS.md](SCORING_AND_FORMATS.md#risk-scoring) for how cautions fit the overall score.
