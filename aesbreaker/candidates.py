"""Candidate sources and attack planning.

The planner is explicit about its totals.  Mask keyspaces and
wordlist counts are exact unless rules contain rejection operations or
deduplication is enabled, in which case the total is an upper bound and is
reported as such.  Candidates are raw bytes: wordlists are never silently
decoded or stripped of spaces.
"""

from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

from .errors import InputError, UsageError
from .masks import MaskPlan
from .rules import RuleSet
from .util import (
    count_wordlist,
    load_wordlist,
    open_wordlist,
    strip_line_ending,
)

DEFAULT_DEDUPE_LIMIT = 5_000_000
DEFAULT_COMBINATOR_MAX = 5_000_000


@dataclass(frozen=True)
class PlanSummary:
    kind: str
    total: Optional[int]
    total_is_upper: bool
    details: dict

    @property
    def has_total(self) -> bool:
        return self.total is not None

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "total": self.total,
            "total_is_upper": self.total_is_upper,
            **self.details,
        }


@dataclass
class PlanOptions:
    wordlist: Optional[str] = None
    stdin: bool = False
    rules: Optional[RuleSet] = None
    mask: Optional[MaskPlan] = None
    mask_append: Optional[MaskPlan] = None
    mask_prepend: Optional[MaskPlan] = None
    combinator: Optional[str] = None
    separator: bytes = b""
    encoding: str = "utf-8"
    skip_empty: bool = True
    dedupe: bool = False
    dedupe_limit: int = DEFAULT_DEDUPE_LIMIT
    count_lines: bool = True
    combinator_max: int = DEFAULT_COMBINATOR_MAX


class AttackPlan:
    def __init__(
        self,
        factory: Callable[[], Iterator[bytes]],
        summary: PlanSummary,
        warnings: Optional[list[str]] = None,
    ) -> None:
        self._factory = factory
        self.summary = summary
        self.warnings = warnings or []

    def iter_candidates(self) -> Iterator[bytes]:
        return self._factory()

    def skipped(self, count: int) -> "AttackPlan":
        """Return a deterministic view that starts after *count* candidates.

        The count is applied after rules/masks/deduplication, so resuming a
        deduplicated plan reproduces exactly the same candidate stream.
        """
        if count < 0:
            raise UsageError("resume position must not be negative")
        if count == 0:
            return self
        total = self.summary.total
        remaining = max(0, total - count) if total is not None else None
        details = dict(self.summary.details)
        details["resumed_from"] = count
        summary = PlanSummary(
            kind=self.summary.kind,
            total=remaining,
            total_is_upper=self.summary.total_is_upper,
            details=details,
        )

        def factory() -> Iterator[bytes]:
            return itertools.islice(self.iter_candidates(), count, None)

        return AttackPlan(factory, summary, list(self.warnings))


def _mask_combiner(
    base_iterator: Iterator[bytes],
    rules: Optional[RuleSet],
    append_mask: Optional[MaskPlan],
    prepend_mask: Optional[MaskPlan],
) -> Iterator[bytes]:
    for base in base_iterator:
        if rules is None:
            transformed_iter: Iterator[bytes] = iter((base,))
        else:
            transformed_iter = rules.apply(base)
        for transformed in transformed_iter:
            if append_mask is not None:
                for suffix in append_mask.iter_bytes():
                    yield transformed + suffix
            elif prepend_mask is not None:
                for prefix in prepend_mask.iter_bytes():
                    yield prefix + transformed
            else:
                yield transformed


def _deduplicator(iterator: Iterator[bytes], limit: int, warnings: list[str]) -> Iterator[bytes]:
    seen: set[bytes] = set()
    exhausted = False
    for candidate in iterator:
        if exhausted:
            yield candidate
            continue
        digest = hashlib.blake2b(candidate, digest_size=16).digest()
        if digest in seen:
            continue
        if len(seen) >= limit:
            exhausted = True
            warnings.append(
                f"deduplication stopped after {limit:,} unique candidates; "
                "later duplicates may be retried"
            )
            yield candidate
            continue
        seen.add(digest)
        yield candidate


def _finish(
    iterator: Iterator[bytes], options: PlanOptions, warnings: list[str]
) -> Iterator[bytes]:
    if options.dedupe:
        return _deduplicator(iterator, options.dedupe_limit, warnings)
    return iterator


def build_plan(options: PlanOptions) -> AttackPlan:
    if options.dedupe_limit < 1:
        raise UsageError("dedupe limit must be at least 1")
    if options.combinator_max < 1:
        raise UsageError("combinator limit must be at least 1")

    sources = sum(
        bool(value)
        for value in (
            options.wordlist,
            options.stdin,
            options.mask,
        )
    )
    if sources != 1:
        raise UsageError("select exactly one candidate source: --wordlist, --stdin, or --mask")
    if options.wordlist == "-" and options.stdin:
        raise UsageError("use either '-w -' or --stdin, not both")
    if options.wordlist == "-":
        options.wordlist = None
        options.stdin = True

    if options.rules is not None and options.mask is not None:
        raise UsageError(
            "rules are applied to wordlist candidates, not to mask-only attacks",
            hint="use --mask with --wordlist for a hybrid attack instead",
        )
    if options.mask_append is not None and options.mask_prepend is not None:
        raise UsageError("--mask-append and --mask-prepend are mutually exclusive")
    if (options.mask_append or options.mask_prepend) and not (options.wordlist or options.stdin):
        raise UsageError(
            "hybrid masks require --wordlist or --stdin",
            hint="use --mask for a mask-only attack",
        )
    if options.combinator is not None:
        if options.mask is not None:
            raise UsageError("--combinator cannot be combined with --mask")
        if options.mask_append or options.mask_prepend:
            raise UsageError("--combinator cannot be combined with a hybrid mask")
        if not (options.wordlist or options.stdin):
            raise UsageError("--combinator requires --wordlist")
        if options.combinator == "-":
            raise UsageError("the second combinator wordlist cannot be stdin")

    rules = options.rules
    rule_count = len(rules) if rules is not None else 1
    rules_upper = bool(rules and rules.has_rejection)
    warnings: list[str] = []

    # -- pure mask ---------------------------------------------------------
    if options.mask is not None:
        mask = options.mask
        if mask.keyspace <= 0:
            raise InputError("mask keyspace is empty")
        summary = PlanSummary(
            kind="mask",
            total=mask.keyspace,
            total_is_upper=False,
            details={
                "source": "mask",
                "mask": mask.description,
                "mask_keyspace": mask.keyspace,
                "variants": len(mask.variants),
                "encoding": options.encoding,
                "dedupe": False,
            },
        )

        def mask_factory() -> Iterator[bytes]:
            yield from mask.iter_bytes()

        return AttackPlan(mask_factory, summary, warnings)

    # -- combinator --------------------------------------------------------
    combinator_words: Optional[list[bytes]] = None
    combinator_count: Optional[int] = None
    if options.combinator is not None:
        raw_count = count_wordlist(options.combinator, skip_empty=options.skip_empty)
        if raw_count is not None and raw_count > options.combinator_max:
            raise UsageError(
                f"second combinator wordlist has {raw_count:,} words, above the "
                f"{options.combinator_max:,} word safety limit",
                hint="use a smaller second list or raise --combinator-max",
            )
        combinator_words = load_wordlist(options.combinator, skip_empty=options.skip_empty)
        combinator_count = len(combinator_words)
        if combinator_count == 0:
            raise InputError("second combinator wordlist is empty")

    # -- base wordlist / stdin --------------------------------------------
    base_count: Optional[int] = None
    if options.stdin:
        base_source = "stdin"
    else:
        assert options.wordlist is not None
        base_source = "wordlist"
        if options.count_lines:
            base_count = count_wordlist(options.wordlist, skip_empty=options.skip_empty)
            if base_count == 0:
                raise InputError("wordlist contains no candidates")

    mask_count = 1
    mask_description = None
    if options.mask_append is not None:
        mask_count = options.mask_append.keyspace
        mask_description = f"append {options.mask_append.description}"
    elif options.mask_prepend is not None:
        mask_count = options.mask_prepend.keyspace
        mask_description = f"prepend {options.mask_prepend.description}"
    if mask_count <= 0:
        raise InputError("hybrid mask keyspace is empty")

    if combinator_words is not None:
        assert combinator_count is not None
        rule_total = None if base_count is None else base_count * combinator_count * rule_count
        kind = "combinator"
    else:
        rule_total = None if base_count is None else base_count * rule_count * mask_count
        kind = "wordlist" if not options.stdin else "stdin"
        if mask_description:
            kind += "+mask"

    total: Optional[int] = rule_total if rule_total is not None else None
    total_is_upper = bool(total is not None and (rules_upper or options.dedupe))
    if options.dedupe:
        warnings.append("deduplication is enabled; the reported total is an upper bound")

    details = {
        "source": base_source,
        "wordlist": options.wordlist,
        "wordlist_count": base_count,
        "rules": len(rules) if rules is not None else 0,
        "rule_expansions": rule_count,
        "rules_upper_bound": rules_upper,
        "mask": mask_description,
        "mask_keyspace": mask_count if mask_description else None,
        "combinator": options.combinator,
        "combinator_count": combinator_count,
        "separator": options.separator.hex() if options.separator else None,
        "encoding": options.encoding,
        "skip_empty": options.skip_empty,
        "dedupe": options.dedupe,
    }
    summary = PlanSummary(
        kind=kind,
        total=total,
        total_is_upper=total_is_upper,
        details=details,
    )

    def wordlist_factory() -> Iterator[bytes]:
        path = "-" if options.stdin else options.wordlist
        assert path is not None
        with open_wordlist(path) as stream:
            for raw_line in stream:
                word = strip_line_ending(raw_line)
                if options.skip_empty and not word:
                    continue
                if combinator_words is not None:
                    for second in combinator_words:
                        combined = word + options.separator + second
                        yield from _mask_combiner(
                            iter((combined,)),
                            rules,
                            options.mask_append,
                            options.mask_prepend,
                        )
                else:
                    yield from _mask_combiner(
                        iter((word,)),
                        rules,
                        options.mask_append,
                        options.mask_prepend,
                    )

    return AttackPlan(
        lambda: _finish(wordlist_factory(), options, warnings),
        summary,
        warnings,
    )


def build_wordlist_plan(
    wordlist: str,
    *,
    rules: Optional[RuleSet] = None,
    encoding: str = "utf-8",
) -> AttackPlan:
    return build_plan(PlanOptions(wordlist=wordlist, rules=rules, encoding=encoding))
