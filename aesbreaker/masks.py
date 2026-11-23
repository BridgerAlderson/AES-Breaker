"""Mask / brute-force candidate generation.

Syntax
------
``?l`` lower, ``?u`` upper, ``?d`` digits, ``?s`` ASCII punctuation,
``?a`` all 95 printable ASCII, ``?h``/``?H`` lower/upper hex, ``?1``..``?4``
custom charsets, ``??`` a literal question mark.  Literal characters are
encoded with the selected encoding.

Increment mode keeps the *leftmost* N mask positions.  For example,
``?u?l?l?l?d`` with ``--increment-min 3`` tests ``?u?l?l``, then
``?u?l?l?l``, and so on.  This preserves a structured prefix; for a pure
``?d?d?d`` mask it is equivalent to shortening the number.

The enumeration order is mixed-radix with the rightmost position varying
fastest.  Indices are stable, which makes progress accounting and resume
support straightforward.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass
from typing import Iterator, Optional

from .errors import UsageError

PREDEFINED = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": string.punctuation,
    "a": "".join(chr(code) for code in range(32, 127)),
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
}
CUSTOM_KEYS = ("1", "2", "3", "4")


class MaskError(UsageError):
    pass


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def expand_charset(
    spec: str,
    custom: dict[str, str],
    *,
    stack: frozenset[str] = frozenset(),
    source: str = "charset",
) -> list[str]:
    """Expand placeholders inside a custom charset definition."""
    chars: list[str] = []
    index = 0
    while index < len(spec):
        char = spec[index]
        if char != "?":
            chars.append(char)
            index += 1
            continue
        if index + 1 >= len(spec):
            raise MaskError(f"{source}: trailing '?' in charset")
        code = spec[index + 1]
        if code == "?":
            chars.append("?")
        elif code in PREDEFINED:
            chars.extend(PREDEFINED[code])
        elif code in custom:
            if code in stack:
                raise MaskError(f"{source}: custom charset cycle involving ?{code}")
            chars.extend(
                expand_charset(
                    custom[code],
                    custom,
                    stack=stack | {code},
                    source=f"custom ?{code}",
                )
            )
        else:
            raise MaskError(f"{source}: unknown charset placeholder ?{code}")
        index += 2
    return _dedupe(chars)


def _encode_chars(chars: list[str], encoding: str) -> tuple[bytes, ...]:
    tokens: list[bytes] = []
    seen: set[bytes] = set()
    for char in chars:
        try:
            token = char.encode(encoding)
        except UnicodeEncodeError:
            raise MaskError(f"character {char!r} cannot be encoded with {encoding}") from None
        if token not in seen:
            seen.add(token)
            tokens.append(token)
    return tuple(tokens)


@dataclass(frozen=True)
class MaskVariant:
    tokens: tuple[tuple[bytes, ...], ...]
    text: str

    @property
    def keyspace(self) -> int:
        return math.prod(len(position) for position in self.tokens) if self.tokens else 0

    def iter_bytes(self) -> Iterator[bytes]:
        count = len(self.tokens)
        if count == 0:
            return
        if count == 1:
            for token in self.tokens[0]:
                yield token
            return
        sizes = [len(position) for position in self.tokens]
        indices = [0] * count
        while True:
            yield b"".join(self.tokens[position][indices[position]] for position in range(count))
            position = count - 1
            while position >= 0:
                indices[position] += 1
                if indices[position] < sizes[position]:
                    break
                indices[position] = 0
                position -= 1
            if position < 0:
                return

    def index_to_bytes(self, index: int) -> bytes:
        total = self.keyspace
        if not 0 <= index < total:
            raise IndexError("mask index out of range")
        parts = [b""] * len(self.tokens)
        for position in range(len(self.tokens) - 1, -1, -1):
            size = len(self.tokens[position])
            index, remainder = divmod(index, size)
            parts[position] = self.tokens[position][remainder]
        return b"".join(parts)


@dataclass(frozen=True)
class MaskPlan:
    variants: tuple[MaskVariant, ...]
    description: str

    @property
    def keyspace(self) -> int:
        return sum(variant.keyspace for variant in self.variants)

    def iter_bytes(self) -> Iterator[bytes]:
        for variant in self.variants:
            yield from variant.iter_bytes()

    def index_to_bytes(self, index: int) -> bytes:
        if not 0 <= index < self.keyspace:
            raise IndexError("mask index out of range")
        for variant in self.variants:
            if index < variant.keyspace:
                return variant.index_to_bytes(index)
            index -= variant.keyspace
        raise IndexError("mask index out of range")


def parse_mask(
    mask: str,
    custom: Optional[dict[str, str]] = None,
    *,
    encoding: str = "utf-8",
    increment: bool = False,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
) -> MaskPlan:
    custom = custom or {}
    try:
        "".encode(encoding)
    except LookupError:
        raise MaskError(f"unknown text encoding: {encoding}") from None
    if not mask:
        raise MaskError("mask is empty")

    positions: list[tuple[bytes, ...]] = []
    index = 0
    while index < len(mask):
        char = mask[index]
        if char != "?":
            try:
                positions.append((char.encode(encoding),))
            except UnicodeEncodeError:
                raise MaskError(f"character {char!r} cannot be encoded with {encoding}") from None
            index += 1
            continue
        if index + 1 >= len(mask):
            raise MaskError("mask ends with a bare '?' (use '??' for a literal)")
        code = mask[index + 1]
        if code == "?":
            positions.append((b"?",))
        elif code in PREDEFINED:
            tokens = _encode_chars(list(PREDEFINED[code]), encoding)
            positions.append(tokens)
        elif code in custom:
            chars = expand_charset(
                custom[code],
                custom,
                stack=frozenset({code}),
                source=f"custom charset ?{code}",
            )
            if not chars:
                raise MaskError(f"custom charset ?{code} is empty")
            positions.append(_encode_chars(chars, encoding))
        else:
            raise MaskError(
                f"unknown mask placeholder ?{code} at position {index}",
                hint="use ?l ?u ?d ?s ?a ?h ?H ?1..?4 or ?? for a literal '?'",
            )
        index += 2

    total_length = len(positions)
    if total_length == 0:
        raise MaskError("mask contains no positions")

    if increment or min_length is not None or max_length is not None:
        minimum = 1 if min_length is None else min_length
        maximum = total_length if max_length is None else max_length
        if minimum < 1:
            raise MaskError("increment minimum length must be at least 1")
        if maximum < minimum:
            raise MaskError("increment maximum length is smaller than the minimum")
        if maximum > total_length:
            raise MaskError(
                f"increment maximum length {maximum} exceeds mask length {total_length}"
            )
        variants = tuple(
            MaskVariant(tokens=tuple(positions[:length]), text=f"{mask} (length {length})")
            for length in range(minimum, maximum + 1)
        )
        description = f"{mask} increment {minimum}..{maximum}"
    else:
        variants = (MaskVariant(tokens=tuple(positions), text=mask),)
        description = mask
    return MaskPlan(variants=variants, description=description)


def build_charset_plan(
    charset: str,
    *,
    min_length: int = 1,
    max_length: int = 8,
    encoding: str = "utf-8",
    custom: Optional[dict[str, str]] = None,
) -> MaskPlan:
    custom = custom or {}
    if min_length < 1:
        raise MaskError("minimum length must be at least 1")
    if max_length < min_length:
        raise MaskError("maximum length is smaller than the minimum length")
    chars = expand_charset(charset, custom, source="--charset")
    if not chars:
        raise MaskError("--charset expands to an empty character set")
    tokens = _encode_chars(chars, encoding)
    variants = tuple(
        MaskVariant(tokens=tuple([tokens] * length), text=f"{charset} (length {length})")
        for length in range(min_length, max_length + 1)
    )
    return MaskPlan(
        variants=variants,
        description=f"charset {charset!r}, lengths {min_length}..{max_length}",
    )


def parse_custom_definitions(values: dict[str, str]) -> dict[str, str]:
    unknown = set(values) - set(CUSTOM_KEYS)
    if unknown:
        raise MaskError(f"unknown custom charset names: {sorted(unknown)}")
    return values
