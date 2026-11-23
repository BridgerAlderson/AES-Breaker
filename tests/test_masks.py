from __future__ import annotations

import pytest

from aesbreaker.errors import UsageError
from aesbreaker.masks import (
    MaskError,
    build_charset_plan,
    expand_charset,
    parse_mask,
)


def test_digit_mask_keyspace_order_and_index():
    plan = parse_mask("?d?d")
    assert plan.keyspace == 100
    assert len(plan.variants) == 1
    values = list(plan.iter_bytes())
    assert values[:3] == [b"00", b"01", b"02"]
    assert values[-1] == b"99"
    assert plan.index_to_bytes(0) == b"00"
    assert plan.index_to_bytes(42) == b"42"
    assert plan.index_to_bytes(99) == b"99"


def test_literal_and_question_mark():
    plan = parse_mask("??-?d")
    assert plan.keyspace == 10
    assert list(plan.iter_bytes())[0] == b"?-0"


def test_custom_charsets_and_references():
    plan = parse_mask("?1?2", custom={"1": "ab", "2": "?d"})
    assert plan.keyspace == 20
    values = list(plan.iter_bytes())
    assert values[0] == b"a0"
    assert values[-1] == b"b9"

    expansion = expand_charset("?l?d", {})
    assert len(expansion) == 36


def test_charset_cycle_and_unknown_placeholder():
    with pytest.raises(MaskError):
        parse_mask("?1", custom={"1": "?1"})
    with pytest.raises(MaskError):
        parse_mask("?z")
    with pytest.raises(MaskError):
        expand_charset("?1", {"1": "?2", "2": "?1"})


def test_increment_uses_leftmost_positions():
    plan = parse_mask("?u?l?d", increment=True, min_length=2, max_length=3)
    assert len(plan.variants) == 2
    assert plan.keyspace == 26 * 26 + 26 * 26 * 10
    first = list(plan.variants[0].iter_bytes())[:2]
    assert first == [b"Aa", b"Ab"]
    last = plan.index_to_bytes(plan.keyspace - 1)
    assert last == b"Zz9"


def test_charset_plan_lengths():
    plan = build_charset_plan("ab", min_length=1, max_length=3)
    assert plan.keyspace == 2 + 4 + 8
    values = list(plan.iter_bytes())
    assert values[:3] == [b"a", b"b", b"aa"]
    assert values[-1] == b"bbb"


def test_unicode_custom_charset_encodes_utf8():
    plan = parse_mask("?1", custom={"1": "é"})
    assert list(plan.iter_bytes()) == ["é".encode("utf-8")]


def test_duplicate_charset_characters_are_removed():
    plan = parse_mask("?1", custom={"1": "aab"})
    assert plan.keyspace == 2


@pytest.mark.parametrize(
    "mask,custom",
    [
        ("", {}),
        ("?", {}),
        ("?1", {}),
        ("?1", {"1": ""}),
    ],
)
def test_invalid_masks(mask, custom):
    with pytest.raises((MaskError, UsageError)):
        parse_mask(mask, custom)


def test_mask_index_out_of_range():
    plan = parse_mask("?d")
    with pytest.raises(IndexError):
        plan.index_to_bytes(10)
