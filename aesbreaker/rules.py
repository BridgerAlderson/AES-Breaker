"""Hashcat-style word mutation rules (documented subset).

A rule file contains one rule per line.  Every rule is an independent
transformation applied to each base word; several rules therefore produce
several candidates.  Blank lines and lines starting with ``#`` are ignored.
Spaces are significant, so ``$ `` appends a literal space.

Supported operations (applied left to right):

===============  ====================================================
``:``            no-op
``l`` ``u``      ASCII lower / upper-case
``c`` ``C``      capitalize / invert-capitalize
``t``            toggle ASCII case everywhere
``TN``           toggle case at index N
``r``            reverse
``d``            duplicate the word (word + word)
``f``            reflect (word + reversed word)
``{`` ``}``      rotate left / right by one byte
``$X`` ``^X``    append / prepend character X
``[`` ``]``      delete first / last byte
``DN``           delete byte at index N
``xNM``          extract substring start N, length M
``iNX``          insert character X at index N
``sXY``          replace all X with Y
``@X``           remove all X
``pN``           append the word N additional times
``zN`` ``ZN``    repeat the first / last byte N times at the front/back
``q``            duplicate every byte (abc -> aabbcc)
``k`` ``K``      swap the first / last two bytes
``<N`` ``>N``    reject when length >= N / > N
``_N``           reject unless length == N
``!X``           reject when the word contains X
``(X``           reject unless the word contains X
``)X``           reject unless the word starts with X
===============  ====================================================

Numeric positions are decimal digits (0-9) for ``T``, ``D``, ``x``, ``i``,
``p``, ``z``, and ``Z``.  Length limits accept multi-digit numbers.

Character arguments accept ``\\xNN``, ``\\\\``, ``\\n``, ``\\r``, and
``\\t`` escapes.  Case conversion is byte-wise ASCII, matching wordlist
semantics for non-ASCII data.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .errors import InputError, UsageError

MAX_OUTPUT = 4096
_ASCII_LOWER = bytes.maketrans(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", b"abcdefghijklmnopqrstuvwxyz")
_ASCII_UPPER = bytes.maketrans(b"abcdefghijklmnopqrstuvwxyz", b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")


class RuleSyntaxError(UsageError):
    pass


def _parse_escape(rule: str, index: int) -> tuple[bytes, int]:
    """Parse one character argument at *index*; return (bytes, next index)."""
    if index >= len(rule):
        raise RuleSyntaxError("rule is missing a character argument")
    char = rule[index]
    if char != "\\":
        return char.encode("utf-8"), index + 1
    if index + 1 >= len(rule):
        raise RuleSyntaxError("rule ends with a bare backslash")
    escape = rule[index + 1]
    if escape == "x":
        if index + 3 >= len(rule):
            raise RuleSyntaxError("\\x escape needs two hex digits")
        try:
            value = int(rule[index + 2 : index + 4], 16)
        except ValueError:
            raise RuleSyntaxError("invalid \\x escape") from None
        return bytes([value]), index + 4
    mapping = {"n": b"\n", "r": b"\r", "t": b"\t", "\\": b"\\"}
    if escape in mapping:
        return mapping[escape], index + 2
    raise RuleSyntaxError(f"unknown escape: \\{escape}")


def _parse_digit(rule: str, index: int, what: str) -> tuple[int, int]:
    if index >= len(rule) or not rule[index].isdigit():
        raise RuleSyntaxError(f"{what} needs a decimal digit at position {index}")
    return int(rule[index]), index + 1


def _parse_number(rule: str, index: int, what: str) -> tuple[int, int]:
    end = index
    while end < len(rule) and rule[end].isdigit():
        end += 1
    if end == index:
        raise RuleSyntaxError(f"{what} needs a decimal number")
    return int(rule[index:end]), end


def _toggle_byte(byte: int) -> int:
    if 65 <= byte <= 90:
        return byte + 32
    if 97 <= byte <= 122:
        return byte - 32
    return byte


def _apply(ops: tuple[tuple, ...], word: bytes) -> Optional[bytes]:
    current = word
    for op in ops:
        code = op[0]
        if code == "noop":
            pass
        elif code == "lower":
            current = current.translate(_ASCII_LOWER)
        elif code == "upper":
            current = current.translate(_ASCII_UPPER)
        elif code == "capitalize":
            if current:
                current = current[:1].translate(_ASCII_UPPER) + current[1:].translate(_ASCII_LOWER)
        elif code == "invert_capitalize":
            if current:
                current = current[:1].translate(_ASCII_LOWER) + current[1:].translate(_ASCII_UPPER)
        elif code == "toggle_all":
            current = bytes(_toggle_byte(byte) for byte in current)
        elif code == "toggle_at":
            index = op[1]
            if -len(current) <= index < len(current):
                position = index if index >= 0 else len(current) + index
                current = (
                    current[:position]
                    + bytes([_toggle_byte(current[position])])
                    + current[position + 1 :]
                )
        elif code == "reverse":
            current = current[::-1]
        elif code == "duplicate":
            current = current + current
        elif code == "reflect":
            current = current + current[::-1]
        elif code == "rotate_left":
            current = current[1:] + current[:1] if current else current
        elif code == "rotate_right":
            current = current[-1:] + current[:-1] if current else current
        elif code == "append":
            current = current + op[1]
        elif code == "prepend":
            current = op[1] + current
        elif code == "delete_first":
            current = current[1:] if current else current
        elif code == "delete_last":
            current = current[:-1] if current else current
        elif code == "delete_at":
            index = op[1]
            if -len(current) <= index < len(current):
                position = index if index >= 0 else len(current) + index
                current = current[:position] + current[position + 1 :]
        elif code == "extract":
            start, length = op[1], op[2]
            if start < 0:
                start = max(0, len(current) + start)
            current = current[start : start + length] if length else b""
        elif code == "insert":
            index, value = op[1], op[2]
            if index < 0:
                index = max(0, len(current) + index)
            index = min(index, len(current))
            current = current[:index] + value + current[index:]
        elif code == "replace":
            current = current.replace(op[1], op[2])
        elif code == "purge":
            current = current.replace(op[1], b"")
        elif code == "append_word":
            current = current + current * op[1]
        elif code == "prefix_char":
            if current:
                current = current[:1] * op[1] + current
        elif code == "suffix_char":
            if current:
                current = current + current[-1:] * op[1]
        elif code == "interleave":
            current = b"".join(bytes([byte, byte]) for byte in current)
        elif code == "swap_first":
            if len(current) >= 2:
                current = current[1:2] + current[:1] + current[2:]
        elif code == "swap_last":
            if len(current) >= 2:
                current = current[:-2] + current[-1:] + current[-2:-1]
        elif code == "reject_len_ge":
            if len(current) >= op[1]:
                return None
        elif code == "reject_len_gt":
            if len(current) > op[1]:
                return None
        elif code == "reject_len_ne":
            if len(current) != op[1]:
                return None
        elif code == "reject_contains":
            if op[1] in current:
                return None
        elif code == "reject_not_contains":
            if op[1] not in current:
                return None
        elif code == "reject_not_starts":
            if not current.startswith(op[1]):
                return None
        else:  # pragma: no cover - parser and executor must stay in sync
            raise AssertionError(f"unhandled rule operation: {code}")
        if len(current) > MAX_OUTPUT:
            return None
    return current


def parse_rule(text: str) -> "Rule":
    if not text:
        raise RuleSyntaxError("empty rule")
    ops: list[tuple] = []
    rejects = False
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char == ":":
            ops.append(("noop",))
            index += 1
        elif char == "l":
            ops.append(("lower",))
            index += 1
        elif char == "u":
            ops.append(("upper",))
            index += 1
        elif char == "c":
            ops.append(("capitalize",))
            index += 1
        elif char == "C":
            ops.append(("invert_capitalize",))
            index += 1
        elif char == "t":
            ops.append(("toggle_all",))
            index += 1
        elif char == "T":
            position, index = _parse_digit(text, index + 1, "T")
            ops.append(("toggle_at", position))
        elif char == "r":
            ops.append(("reverse",))
            index += 1
        elif char == "d":
            ops.append(("duplicate",))
            index += 1
        elif char == "f":
            ops.append(("reflect",))
            index += 1
        elif char == "{":
            ops.append(("rotate_left",))
            index += 1
        elif char == "}":
            ops.append(("rotate_right",))
            index += 1
        elif char == "$":
            value, index = _parse_escape(text, index + 1)
            ops.append(("append", value))
        elif char == "^":
            value, index = _parse_escape(text, index + 1)
            ops.append(("prepend", value))
        elif char == "[":
            ops.append(("delete_first",))
            index += 1
        elif char == "]":
            ops.append(("delete_last",))
            index += 1
        elif char == "D":
            position, index = _parse_digit(text, index + 1, "D")
            ops.append(("delete_at", position))
        elif char == "x":
            start, index = _parse_digit(text, index + 1, "x")
            count, index = _parse_digit(text, index, "x")
            ops.append(("extract", start, count))
        elif char == "i":
            position, index = _parse_digit(text, index + 1, "i")
            value, index = _parse_escape(text, index)
            ops.append(("insert", position, value))
        elif char == "s":
            source, index = _parse_escape(text, index + 1)
            target, index = _parse_escape(text, index)
            ops.append(("replace", source, target))
        elif char == "@":
            value, index = _parse_escape(text, index + 1)
            ops.append(("purge", value))
        elif char == "p":
            count, index = _parse_digit(text, index + 1, "p")
            if count < 1:
                raise RuleSyntaxError("pN requires N between 1 and 9")
            ops.append(("append_word", count))
        elif char == "z":
            count, index = _parse_digit(text, index + 1, "z")
            ops.append(("prefix_char", count))
        elif char == "Z":
            count, index = _parse_digit(text, index + 1, "Z")
            ops.append(("suffix_char", count))
        elif char == "q":
            ops.append(("interleave",))
            index += 1
        elif char == "k":
            ops.append(("swap_first",))
            index += 1
        elif char == "K":
            ops.append(("swap_last",))
            index += 1
        elif char == "<":
            limit, index = _parse_number(text, index + 1, "<")
            ops.append(("reject_len_ge", limit))
            rejects = True
        elif char == ">":
            limit, index = _parse_number(text, index + 1, ">")
            ops.append(("reject_len_gt", limit))
            rejects = True
        elif char == "_":
            limit, index = _parse_number(text, index + 1, "_")
            ops.append(("reject_len_ne", limit))
            rejects = True
        elif char == "!":
            value, index = _parse_escape(text, index + 1)
            ops.append(("reject_contains", value))
            rejects = True
        elif char == "(":
            value, index = _parse_escape(text, index + 1)
            ops.append(("reject_not_contains", value))
            rejects = True
        elif char == ")":
            value, index = _parse_escape(text, index + 1)
            ops.append(("reject_not_starts", value))
            rejects = True
        else:
            raise RuleSyntaxError(f"unknown rule operation {char!r} at position {index}")
    if not ops:
        raise RuleSyntaxError("rule contains no operations")
    return Rule(text=text, ops=tuple(ops), rejects=rejects)


@dataclass(frozen=True)
class Rule:
    text: str
    ops: tuple[tuple, ...]
    rejects: bool

    def apply(self, word: bytes) -> Optional[bytes]:
        return _apply(self.ops, word)


class RuleSet:
    def __init__(self, rules: Iterable[Rule]) -> None:
        self.rules = tuple(rules)

    def __len__(self) -> int:
        return len(self.rules)

    @property
    def has_rejection(self) -> bool:
        return any(rule.rejects for rule in self.rules)

    def apply(self, word: bytes) -> Iterator[bytes]:
        if not self.rules:
            yield word
            return
        for rule in self.rules:
            transformed = rule.apply(word)
            if transformed is not None:
                yield transformed

    def describe(self) -> list[str]:
        return [rule.text for rule in self.rules]


def parse_rule_lines(lines: Iterable[str], *, source: str = "rules") -> RuleSet:
    rules: list[Rule] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        if not line or line.startswith("#"):
            continue
        try:
            rule = parse_rule(line)
        except RuleSyntaxError as exc:
            raise RuleSyntaxError(f"{source}:{line_number}: {exc}") from None
        if rule.text not in seen:
            seen.add(rule.text)
            rules.append(rule)
    if not rules:
        raise InputError(f"{source} contains no usable rules")
    return RuleSet(rules)


def load_rule_file(path: str | Path) -> RuleSet:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"cannot read rules file {path}: {exc}") from None
    except UnicodeDecodeError:
        raise InputError(f"rules file is not valid UTF-8: {path}") from None
    return parse_rule_lines(text.splitlines(), source=str(path))


def parse_rule_strings(values: Iterable[str]) -> RuleSet:
    rules: list[Rule] = []
    seen: set[str] = set()
    for value in values:
        rule = parse_rule(value)
        if rule.text not in seen:
            seen.add(rule.text)
            rules.append(rule)
    if not rules:
        raise InputError("no --rule values were supplied")
    return RuleSet(rules)


# ---------------------------------------------------------------------------
# Built-in presets
# ---------------------------------------------------------------------------


def _append_rule(text: str) -> str:
    """Build a rule that appends a multi-character string."""
    return "".join("$" + char for char in text)


_COMMON_RULES = [
    ":",
    "c",
    "u",
    "l",
    "C",
    "r",
    "d",
    "f",
    "$1",
    "$2",
    "$3",
    "$4",
    "$5",
    "$6",
    "$7",
    "$8",
    "$9",
    "$0",
    "$!",
    "$!$!",
    _append_rule("123"),
    _append_rule("1234"),
    _append_rule("12345"),
    _append_rule("2020"),
    _append_rule("2021"),
    _append_rule("2022"),
    _append_rule("2023"),
    _append_rule("2024"),
    _append_rule("2025"),
    _append_rule("2026"),
    "c$1",
    "c$!",
    _append_rule("c123"),
    "l$1",
    "l$!",
    "u$1",
    "^1",
    "sa@",
    "se3",
    "si1",
    "so0",
    "ss$",
]

_LEET_RULES = [
    "sa@",
    "se3",
    "si1",
    "so0",
    "ss$",
    "sg9",
    "st7",
    "sb8",
    "sa@se3si1so0",
    "sa@se3si1so0ss$",
    "l",
    "u",
    "c",
    "sa@$1",
    "se3$1",
    "si1$1",
    "so0$1",
    "ss$$1",
    "sa@se3si1so0$1",
]

_YEAR_RULES = [_append_rule(str(year)) for year in range(1970, 2031)]


def _digit_rules() -> list[str]:
    rules = [f"${digit}" for digit in range(10)]
    rules += [_append_rule(f"{first}{second}") for first in range(10) for second in range(10)]
    return rules


PRESETS = {
    "common": _COMMON_RULES,
    "leet": _LEET_RULES,
    "digits": _digit_rules(),
    "years": _YEAR_RULES,
}

PRESET_NAMES = tuple(PRESETS)


def load_preset(name: str) -> RuleSet:
    normalized = name.strip().lower()
    if normalized not in PRESETS:
        raise UsageError(
            f"unknown rules preset: {name}",
            hint="available presets: " + ", ".join(PRESET_NAMES),
        )
    return parse_rule_lines(PRESETS[normalized], source=f"preset:{normalized}")


def rule_fingerprint(rule_set: RuleSet) -> str:
    digest = hashlib.sha256()
    for rule in rule_set.rules:
        digest.update(rule.text.encode("utf-8"))
        digest.update(b"\x00")
    return digest.hexdigest()[:16]
