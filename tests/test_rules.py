from __future__ import annotations

from pathlib import Path

import pytest

from aesbreaker.errors import InputError, UsageError
from aesbreaker.rules import (
    RuleSet,
    RuleSyntaxError,
    load_preset,
    load_rule_file,
    parse_rule,
    parse_rule_lines,
    parse_rule_strings,
)


@pytest.mark.parametrize(
    "rule,word,expected",
    [
        (":", b"hunter", b"hunter"),
        ("l", b"HuNtEr", b"hunter"),
        ("u", b"hunter", b"HUNTER"),
        ("c", b"hUNTER", b"Hunter"),
        ("C", b"Hunter", b"hUNTER"),
        ("t", b"HuNtEr", b"hUnTeR"),
        ("r", b"abc", b"cba"),
        ("d", b"ab", b"abab"),
        ("f", b"ab", b"abba"),
        ("{", b"abcd", b"bcda"),
        ("}", b"abcd", b"dabc"),
        ("$1", b"pass", b"pass1"),
        ("^1", b"pass", b"1pass"),
        ("[", b"pass", b"ass"),
        ("]", b"pass", b"pas"),
        ("D1", b"pass", b"pss"),
        ("x12", b"abcdef", b"bc"),
        ("i2X", b"abcd", b"abXcd"),
        ("sAa", b"pAss", b"pass"),
        ("@x", b"xaxbxc", b"abc"),
        ("p2", b"ab", b"ababab"),
        ("z2", b"ab", b"aaab"),
        ("Z3", b"ab", b"abbbb"),
        ("q", b"abc", b"aabbcc"),
        ("k", b"abcd", b"bacd"),
        ("K", b"abcd", b"abdc"),
        ("T1", b"ab", b"aB"),
        (r"$\x41", b"x", b"xA"),
        (r"$\n", b"x", b"x\n"),
        ("$é", b"x", "xé".encode("utf-8")),
    ],
)
def test_rule_transformations(rule, word, expected):
    assert parse_rule(rule).apply(word) == expected


def test_rejection_rules():
    assert parse_rule("<4").apply(b"abc") == b"abc"
    assert parse_rule("<4").apply(b"abcd") is None
    assert parse_rule(">3").apply(b"abcd") is None
    assert parse_rule(">3").apply(b"abc")
    assert parse_rule("_3").apply(b"abc")
    assert parse_rule("_3").apply(b"abcd") is None
    assert parse_rule("!x").apply(b"axb") is None
    assert parse_rule("!x").apply(b"abc")
    assert parse_rule("(x").apply(b"abc") is None
    assert parse_rule("(x").apply(b"axc")
    assert parse_rule(")a").apply(b"abc")
    assert parse_rule(")a").apply(b"xbc") is None


def test_rejection_applies_at_its_position():
    # A rejection before the extraction sees the original 4-byte word.
    assert parse_rule(">2x02").apply(b"abcd") is None
    # After x02 the word is 2 bytes, so >2 accepts it.
    assert parse_rule("x02>2").apply(b"abcd") == b"ab"
    # After x03 the word is 3 bytes, so >2 rejects it.
    assert parse_rule("x03>2").apply(b"abcd") is None


@pytest.mark.parametrize("rule", ["", "$", "^", "s", "sA", "x1", "i1", "p0", "Q", "T", "\\"])
def test_invalid_rules(rule):
    with pytest.raises(RuleSyntaxError):
        parse_rule(rule)


def test_rule_file_comments_and_deduplication(tmp_path: Path):
    path = tmp_path / "rules.txt"
    path.write_text("# comment\n\nc\nc\n$1\n", encoding="utf-8")
    rule_set = load_rule_file(path)
    assert len(rule_set) == 2
    assert rule_set.apply(b"abc")
    outputs = list(rule_set.apply(b"abc"))
    assert outputs == [b"Abc", b"abc1"]


def test_empty_rule_file_rejected(tmp_path: Path):
    path = tmp_path / "rules.txt"
    path.write_text("# nothing here\n", encoding="utf-8")
    with pytest.raises(InputError):
        load_rule_file(path)


def test_rule_set_identity_without_rules():
    assert list(RuleSet([]).apply(b"abc")) == [b"abc"]
    # An explicitly empty rule file is an error.
    with pytest.raises(InputError):
        parse_rule_lines([], source="empty")


def test_presets_load():
    for name in ("common", "leet", "digits", "years"):
        rule_set = load_preset(name)
        assert len(rule_set) > 0
        assert not rule_set.has_rejection
    with pytest.raises(UsageError):
        load_preset("does-not-exist")


def test_inline_rule_strings_dedupe():
    rule_set = parse_rule_strings(["c", "c", "$1"])
    assert len(rule_set) == 2
    assert [rule.text for rule in rule_set.rules] == ["c", "$1"]


def test_long_output_is_rejected():
    word = b"x" * 4096
    assert parse_rule("d").apply(word) is None
