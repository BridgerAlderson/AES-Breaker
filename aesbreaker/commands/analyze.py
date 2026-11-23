"""``aesbreaker analyze``: statistical checks for unknown AES data."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path

from .. import __version__
from ..errors import InputError
from ..formats.aescrypt import looks_like_aescrypt
from ..formats.openssl_enc import looks_like_openssl
from ..formats.zip_aes import looks_like_zip
from ..signatures import assess_plaintext, detect_magic, shannon_entropy
from ..util import (
    format_bytes,
    format_count,
    parse_size,
    read_prefix,
    sha256_file,
    write_json,
)
from . import common


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="file to analyze")
    parser.add_argument(
        "--block-size",
        type=common.positive_int,
        default=16,
        metavar="N",
        help="block size for ECB duplicate detection (default: 16)",
    )
    parser.add_argument(
        "--top",
        type=common.positive_int,
        default=10,
        metavar="N",
        help="number of most common byte values to show (default: 10)",
    )
    parser.add_argument(
        "--limit",
        type=parse_size,
        default=parse_size("16M"),
        metavar="SIZE",
        help="bytes sampled from the start (default: 16M; 0 = whole file)",
    )
    parser.add_argument("--no-hash", action="store_true", help="skip SHA-256")
    parser.add_argument("--json", action="store_true", help="write the report as JSON")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON report to FILE")


def _duplicate_blocks(data: bytes, block_size: int, max_groups: int = 20) -> dict:
    full = len(data) // block_size
    trailing = len(data) % block_size
    seen: dict[bytes, int] = {}
    duplicates: list[dict] = []
    duplicate_blocks = 0
    for index in range(full):
        block = data[index * block_size : (index + 1) * block_size]
        first = seen.get(block)
        if first is None:
            seen[block] = index * block_size
            continue
        duplicate_blocks += 1
        if len(duplicates) < max_groups:
            duplicates.append(
                {
                    "first_offset": first,
                    "repeat_offset": index * block_size,
                    "block_hex": block.hex(),
                }
            )
    total_bytes = len(seen) * block_size
    return {
        "block_size": block_size,
        "full_blocks": full,
        "trailing_bytes": trailing,
        "unique_blocks": len(seen),
        "duplicate_blocks": duplicate_blocks,
        "duplicate_bytes": duplicate_blocks * block_size,
        "unique_bytes": total_bytes,
        "duplicate_groups_shown": duplicates,
        "duplicates_truncated": duplicate_blocks > len(duplicates),
    }


def run(args: argparse.Namespace) -> int:
    common.validate_side_outputs(args, inputs=(args.input,))
    try:
        size = Path(args.input).stat().st_size
    except OSError as exc:
        raise InputError(f"cannot read {args.input}: {exc}") from None
    data = read_prefix(args.input, args.limit)
    sampled = bool(args.limit and size > args.limit)

    histogram = Counter(data)
    entropy = shannon_entropy(data)
    magic = detect_magic(data)
    plausibility = assess_plaintext(data)
    block_report = _duplicate_blocks(data, args.block_size)
    head = data[:16]

    hints = []
    container = False
    if looks_like_aescrypt(data):
        container = True
        hints.append("starts with an AES Crypt v1/v2/v3 header; use 'aesbreaker inspect'")
    if looks_like_openssl(data):
        container = True
        hints.append(
            "starts with an OpenSSL Salted__ header; use 'aesbreaker inspect --openssl-cipher ...'"
        )
    if head.startswith(b"PK\x03\x04") or looks_like_zip(args.input):
        container = True
        hints.append("looks like a ZIP archive; use 'aesbreaker inspect'")
    ecb_suspected = block_report["duplicate_blocks"] > 0 and not container

    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "analyze",
        "input": args.input,
        "size": size,
        "sha256": None if args.no_hash else sha256_file(args.input),
        "sampled": sampled,
        "analyzed_bytes": len(data),
        "entropy_bits_per_byte": round(entropy, 6),
        "magic": None if magic is None else {"name": magic.name, "description": magic.description},
        "text_plausibility": {
            "kind": plausibility.kind,
            "score": round(plausibility.score, 4),
            "detail": plausibility.detail,
        },
        "blocks": block_report,
        "ecb_suspected": ecb_suspected,
        "is_container": container,
        "top_bytes": [
            {"value": f"0x{byte:02x}", "count": count}
            for byte, count in histogram.most_common(args.top)
        ],
        "hints": hints,
    }
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)
        return 0

    print(f"File: {args.input}")
    print(f"Size: {format_bytes(size)} ({format_count(size)} bytes)")
    if payload["sha256"]:
        print(f"SHA-256: {payload['sha256']}")
    if sampled:
        print(
            f"Analyzed: {format_bytes(len(data))} sample "
            f"({format_count(len(data))} of {format_count(size)} bytes)"
        )
    else:
        print(f"Analyzed: {format_bytes(len(data))} (whole file)")
    print(f"Entropy: {entropy:.4f} bits/byte")
    if magic:
        print(f"Signature: {magic.description}")
    else:
        print("Signature: none recognized")
    print(f"Text heuristic: {plausibility.detail}")
    print(
        f"Blocks ({args.block_size} bytes): "
        f"{format_count(block_report['full_blocks'])} full, "
        f"{format_count(block_report['trailing_bytes'])} trailing bytes"
    )
    print(
        f"Duplicate blocks: {format_count(block_report['duplicate_blocks'])} "
        f"({format_bytes(block_report['duplicate_bytes'])})"
    )
    if block_report["duplicate_blocks"]:
        if container:
            print(
                "ECB indicator: repeated blocks are container metadata, so ECB "
                "inference does not apply."
            )
        else:
            print(
                "ECB indicator: repeated blocks are present; if this is raw "
                "ciphertext, ECB is likely."
            )
            for group in block_report["duplicate_groups_shown"][:10]:
                print(
                    f"  offset {group['first_offset']} == {group['repeat_offset']} "
                    f"({group['block_hex']})"
                )
    else:
        print("ECB indicator: no repeated blocks in the analyzed range.")
    print("Most common byte values:")
    for byte, count in histogram.most_common(args.top):
        percent = 100.0 * count / len(data) if data else 0.0
        print(f"  0x{byte:02x}  {format_count(count):>12}  {percent:6.2f}%")
    for hint in hints:
        print(f"Hint: {hint}")
    if entropy > 7.9 and not magic:
        print("Note: entropy this high is consistent with encryption or compression.")
    return 0
