## Summary

## Correctness / security impact

- [ ] Verification still requires a real MAC/tag/prefix.
- [ ] No guessing or silent key padding/truncation was introduced.
- [ ] New parser/spec fields are strictly validated.
- [ ] Tests cover success, rejection, and malformed input.
- [ ] `ruff check`, `ruff format --check`, `mypy`, `pytest`, and `selftest` pass.
