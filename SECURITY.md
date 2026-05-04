# Security Policy

## Reporting Vulnerabilities

If you discover a security issue **in Cordyceps itself** (not in the WordPress
plugins it scans), please **do not open a public issue**. Email the maintainer
privately at `khangkito@gmail.com` with:

- A description of the issue
- Steps to reproduce
- Affected version (commit hash or tag)
- Your proposed fix, if any

You will receive an acknowledgement within 5 business days.

## Disclosure Timeline

We follow a 90-day coordinated disclosure timeline:

1. **Day 0** — Report received, acknowledgement sent.
2. **Day ≤30** — Triage complete, fix scoped.
3. **Day ≤60** — Fix implemented and merged to `main`.
4. **Day 90** — Public advisory published; credit given unless you opt out.

If a fix ships sooner, the advisory may be released earlier.

## Scope of Use

Cordyceps performs **static analysis on PHP source code** that you have
already downloaded. It does not execute plugin code. Even so, you should:

- Only scan code you own or have written authorization to test.
- Treat scan output as **indicators**, not proof. Manual review is mandatory
  before reporting findings to plugin authors.
- Follow [Patchstack disclosure guidelines](https://patchstack.com/disclosure)
  when reporting plugin-level issues to upstream maintainers.

## Out of Scope

- Vulnerabilities in WordPress core, plugins, or third-party tooling — please
  report those to the upstream project.
- Issues in the bundled Mycelium binary — see
  https://github.com/zhugez/Mycelium for its own security policy.
- Networks attacks against the GitHub API endpoint used by `install.sh` /
  `install.ps1` (these scripts only fetch release metadata and the
  Mycelium binary; they make no other outbound calls).
