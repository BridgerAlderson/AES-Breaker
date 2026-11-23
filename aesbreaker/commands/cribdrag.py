"""``aesbreaker cribdrag``: XOR two CTR/OFB ciphertexts and test a crib."""

from __future__ import annotations

import argparse
from pathlib import Path

from .. import __version__
from ..errors import UsageError
from ..util import (
    decode_data_arg,
    format_count,
    parse_hex_data,
    preview_bytes,
    write_json,
)
from . import common


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("first", help="first ciphertext (file, hex:..., or base64:...)")
    parser.add_argument("second", help="second ciphertext (file, hex:..., or base64:...)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--crib", metavar="TEXT", help="known plaintext fragment in the first ciphertext"
    )
    group.add_argument("--crib-hex", metavar="HEX", help="known plaintext fragment as hex")
    parser.add_argument("--offset", type=common.nonnegative_int, help="test only this offset")
    parser.add_argument("--top", type=common.positive_int, default=10, metavar="N")
    parser.add_argument(
        "--min-score",
        type=float,
        default=0.7,
        metavar="RATIO",
        help="minimum printable ratio to report (default: 0.7)",
    )
    parser.add_argument("--json", action="store_true", help="write the result as JSON")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON result to FILE")


def _printable_score(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for byte in data if 32 <= byte < 127 or byte in (9, 10, 13))
    return good / len(data)


def run(args: argparse.Namespace) -> int:
    input_paths = tuple(value for value in (args.first, args.second) if Path(value).is_file())
    common.validate_side_outputs(args, inputs=input_paths)
    first = decode_data_arg(args.first, what="first ciphertext")
    second = decode_data_arg(args.second, what="second ciphertext")
    if not first or not second:
        raise UsageError("both ciphertexts must be non-empty")
    crib = (
        args.crib.encode("utf-8")
        if args.crib is not None
        else parse_hex_data(args.crib_hex, what="crib")
    )
    if not crib:
        raise UsageError("the crib must be non-empty")
    original_lengths = (len(first), len(second))
    length = min(len(first), len(second))
    first = first[:length]
    second = second[:length]
    if len(crib) > length:
        raise UsageError("the crib is longer than the available ciphertext")
    xor = bytes(a ^ b for a, b in zip(first, second))
    positions = [args.offset] if args.offset is not None else range(length - len(crib) + 1)
    results = []
    for offset in positions:
        if not 0 <= offset <= length - len(crib):
            raise UsageError(f"offset {offset} is outside the valid range 0..{length - len(crib)}")
        recovered = bytes(a ^ b for a, b in zip(crib, xor[offset : offset + len(crib)]))
        score = _printable_score(recovered)
        if args.offset is not None or score >= args.min_score:
            results.append(
                {
                    "offset": offset,
                    "score": round(score, 6),
                    "recovered_hex": recovered.hex(),
                    "recovered_preview": preview_bytes(recovered),
                }
            )
    results.sort(key=lambda item: (-float(item["score"]), int(item["offset"])))
    if args.top:
        results = results[: args.top]

    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "cribdrag",
        "first_length": original_lengths[0],
        "second_length": original_lengths[1],
        "compared_bytes": length,
        "crib_hex": crib.hex(),
        "crib_preview": preview_bytes(crib),
        "results": results,
        "errors": [],
    }
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)
        return 0

    print("C1 xor C2 = P1 xor P2 when both ciphertexts use the same CTR/OFB key+nonce.")
    if original_lengths[0] != original_lengths[1]:
        print(
            f"Note: lengths differ ({format_count(original_lengths[0])} vs "
            f"{format_count(original_lengths[1])}); compared the first "
            f"{format_count(length)} bytes."
        )
    if not results:
        print(f"No offsets reached the printable threshold {args.min_score:.2f}.")
        return 1
    print(f"Results ({len(results)}):")
    for result in results:
        print(
            f"  offset {result['offset']:>8}  score {result['score']:.3f}  "
            f"{result['recovered_preview']}"
        )
        print(f"    hex: {result['recovered_hex']}")
    return 0
