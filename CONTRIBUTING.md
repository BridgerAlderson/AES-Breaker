# Contributing

## Setup

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pre-commit install
```

## Before opening a pull request

```bash
ruff check aesbreaker tests
ruff format --check aesbreaker tests
mypy aesbreaker
pytest -q --cov=aesbreaker --cov-report=term-missing --cov-fail-under=75
aesbreaker selftest
python -m build
twine check dist/*
```

## Correctness rules

- Never label a guess `confirmed`. A confirmed password needs a MAC, an AEAD
  tag, or at least 8 exact known plaintext bytes.
- Never add a mode, IV, or KDF fallback that tries multiple interpretations and
  picks the most readable output.
- Never silently pad, truncate, or strip a key or password.
- New format parsers require an exact wire-format description and at least one
  independent fixture or cross-implementation test.
- New spec fields must be validated strictly; unknown keys are rejected.
- Output must remain atomic for files and spooled for stdout until
  authentication/padding succeeds.

## Tests

Add tests for success, wrong password, malformed input, and any new CLI error
path. External-tool tests must skip cleanly when the binary is absent.
