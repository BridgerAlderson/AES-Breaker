from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from aesbreaker.candidates import PlanOptions, build_plan
from aesbreaker.errors import InputError, UsageError
from aesbreaker.masks import parse_mask
from aesbreaker.rules import parse_rule_strings


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_wordlist_preserves_spaces_and_crlf(tmp_path: Path):
    wordlist = _write(tmp_path / "words.txt", b"pass \r\npass\r\nnotrailing")
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    assert plan.summary.total == 3
    assert list(plan.iter_candidates()) == [b"pass ", b"pass", b"notrailing"]


def test_blank_lines_skipped_by_default_and_includable(tmp_path: Path):
    wordlist = _write(tmp_path / "words.txt", b"a\n\nb\n")
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    assert list(plan.iter_candidates()) == [b"a", b"b"]
    plan = build_plan(PlanOptions(wordlist=str(wordlist), skip_empty=False))
    assert list(plan.iter_candidates()) == [b"a", b"", b"b"]


def test_rules_expand_total_and_upper_bound(tmp_path: Path):
    wordlist = _write(tmp_path / "words.txt", b"a\nb\n")
    rules = parse_rule_strings(["c", "$1"])
    plan = build_plan(PlanOptions(wordlist=str(wordlist), rules=rules))
    assert plan.summary.total == 4
    assert not plan.summary.total_is_upper
    assert list(plan.iter_candidates()) == [b"A", b"a1", b"B", b"b1"]

    rejecting = parse_rule_strings(["<2"])
    plan = build_plan(PlanOptions(wordlist=str(wordlist), rules=rejecting))
    assert plan.summary.total_is_upper
    assert list(plan.iter_candidates()) == [b"a", b"b"]


def test_hybrid_mask_append_and_prepend(tmp_path: Path):
    wordlist = _write(tmp_path / "words.txt", b"a\nb\n")
    digits = parse_mask("?d")
    plan = build_plan(PlanOptions(wordlist=str(wordlist), mask_append=digits))
    assert plan.summary.total == 20
    assert list(plan.iter_candidates())[:3] == [b"a0", b"a1", b"a2"]

    plan = build_plan(PlanOptions(wordlist=str(wordlist), mask_prepend=digits))
    assert list(plan.iter_candidates())[:3] == [b"0a", b"1a", b"2a"]


def test_combinator_and_separator(tmp_path: Path):
    first = _write(tmp_path / "first.txt", b"a\nb\n")
    second = _write(tmp_path / "second.txt", b"1\n2\n")
    plan = build_plan(PlanOptions(wordlist=str(first), combinator=str(second), separator=b"-"))
    assert plan.summary.total == 4
    assert list(plan.iter_candidates()) == [b"a-1", b"a-2", b"b-1", b"b-2"]


def test_dedupe(tmp_path: Path):
    wordlist = _write(tmp_path / "words.txt", b"a\na\nb\n")
    plan = build_plan(PlanOptions(wordlist=str(wordlist), dedupe=True))
    assert list(plan.iter_candidates()) == [b"a", b"b"]
    assert plan.summary.total_is_upper


def test_mask_plan_total_and_enumeration():
    mask = parse_mask("?l?d")
    plan = build_plan(PlanOptions(mask=mask))
    assert plan.summary.total == 260
    assert plan.summary.kind == "mask"
    values = list(plan.iter_candidates())
    assert values[0] == b"a0"
    assert values[-1] == b"z9"


def test_wordlist_compressed(tmp_path: Path):
    path = tmp_path / "words.txt.gz"
    with gzip.open(path, "wb") as handle:
        handle.write(b"alpha\nbeta\n")
    plan = build_plan(PlanOptions(wordlist=str(path)))
    assert list(plan.iter_candidates()) == [b"alpha", b"beta"]


def test_empty_wordlist_rejected(tmp_path: Path):
    path = _write(tmp_path / "empty.txt", b"")
    with pytest.raises(InputError):
        build_plan(PlanOptions(wordlist=str(path)))


def test_plan_validation_errors(tmp_path: Path):
    wordlist = _write(tmp_path / "words.txt", b"a\n")
    mask = parse_mask("?d")
    with pytest.raises(UsageError):
        build_plan(PlanOptions())
    with pytest.raises(UsageError):
        build_plan(PlanOptions(wordlist=str(wordlist), mask=mask))
    with pytest.raises(UsageError):
        build_plan(PlanOptions(wordlist=str(wordlist), mask_append=mask, mask_prepend=mask))
    with pytest.raises(UsageError):
        build_plan(PlanOptions(mask=mask, rules=parse_rule_strings(["c"])))
    with pytest.raises(UsageError):
        build_plan(PlanOptions(wordlist=str(wordlist), combinator=str(wordlist), mask_append=mask))


def test_no_count_gives_unknown_total(tmp_path: Path):
    path = _write(tmp_path / "words.txt", b"a\nb\n")
    plan = build_plan(PlanOptions(wordlist=str(path), count_lines=False))
    assert plan.summary.total is None
    assert list(plan.iter_candidates()) == [b"a", b"b"]
