# Contributing to Cordyceps

Thanks for helping make Cordyceps better.

## Development Setup

```bash
git clone https://github.com/zhugez/cordyceps.git
cd cordyceps
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate
pip install -e ".[dev]"
```

## Running the Test Suite

```bash
pytest -v
ruff check .
ruff format --check .
```

CI runs on Linux + Windows for Python 3.9 / 3.11 / 3.12 — make sure your
changes work on Python 3.9 (no `match` statements, no PEP 604 type unions in
runtime contexts, etc.).

## Adding a Vulnerability Pattern

The scanner is rule-based. New patterns go in `scanner.py`, in
`PatchstackScanner.VULN_PATTERNS`:

```python
"My Vuln Type": {
    "severity": "HIGH",
    "patterns": [
        (r"some_dangerous_function\s*\(\s*.*\$_(GET|POST|REQUEST)",
         "Brief explanation of why this is risky"),
    ],
},
```

For every new pattern, also:

1. Add a positive fixture in `tests/fixtures/vulnerable_plugin/<your-vuln>.php`
   that should match.
2. Add (or extend) a negative fixture in `tests/fixtures/safe_plugin/` that
   exercises the safe form (e.g., proper escape) and must NOT match.
3. Extend `tests/test_scanner.py` to assert the finding (or its absence).
4. Update `SKILL.md` with the new category in the knowledge base section.
5. Update `README.md` vulnerability coverage table.

## Pull Request Checklist

- [ ] Tests added/updated and passing locally
- [ ] `ruff check` clean
- [ ] `SKILL.md` and `README.md` updated if user-facing behavior changed
- [ ] `CHANGELOG.md` entry under `[Unreleased]`
- [ ] No bundled binaries committed (Mycelium is fetched at install time)

## Reporting Bugs

Use GitHub Issues for non-security bugs. For security issues, see
[SECURITY.md](SECURITY.md).
