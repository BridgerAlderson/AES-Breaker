"""``aesbreaker recover-iv``: known-plaintext IV/keystream recovery."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Literal

from .. import __version__
from ..crypto import (
    AES_BLOCK_SIZE,
    aes_ecb_decrypt_block,
    aes_ecb_encrypt_block,
    xor_bytes,
)
from ..errors import UsageError
from ..util import decode_data_arg, format_hex, parse_hex_data, read_file, write_json
from . import common


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="ciphertext (file, hex:..., or base64:...)")
    parser.add_argument("--key", metavar="HEX", help="AES key as hex")
    parser.add_argument("--key-file", metavar="FILE", help="raw AES key bytes")
    parser.add_argument("--mode", choices=("cbc", "ctr", "ofb", "cfb"), required=True)
    parser.add_argument(
        "--plaintext-block",
        metavar="HEX",
        required=True,
        help="known 16-byte plaintext block",
    )
    parser.add_argument(
        "--block-index",
        type=common.nonnegative_int,
        default=0,
        metavar="N",
        help="zero-based block index of the known plaintext (default: 0)",
    )
    parser.add_argument("--iv", metavar="HEX", help="initial IV/counter, when known")
    parser.add_argument("--ctr-little-endian", action="store_true")
    parser.add_argument("--json", action="store_true", help="write the result as JSON")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON result to FILE")


def _key(args) -> bytes:
    if (args.key is None) == (args.key_file is None):
        raise UsageError("supply exactly one of --key or --key-file")
    return (
        parse_hex_data(args.key, what="key") if args.key is not None else read_file(args.key_file)
    )


def run(args: argparse.Namespace) -> int:
    key = _key(args)
    if len(key) not in (16, 24, 32):
        raise UsageError("AES key must be 16, 24, or 32 bytes")
    inputs = [args.key_file]
    if args.input != "-":
        inputs.append(args.input if Path(args.input).is_file() else None)
    common.validate_side_outputs(args, inputs=tuple(inputs))
    ciphertext = decode_data_arg(args.input, what="ciphertext")
    known = parse_hex_data(args.plaintext_block, what="plaintext block")
    if len(known) != AES_BLOCK_SIZE:
        raise UsageError("--plaintext-block must be exactly 16 bytes")
    offset = args.block_index * AES_BLOCK_SIZE
    block = ciphertext[offset : offset + AES_BLOCK_SIZE]
    if len(block) != AES_BLOCK_SIZE:
        raise UsageError("ciphertext does not contain the requested block index")
    iv = parse_hex_data(args.iv, what="IV") if args.iv is not None else b""

    recovered = b""
    expected = None
    key_confirmed = None
    value_name = "recovered value"
    note = None

    if args.mode == "cbc":
        intermediate = aes_ecb_decrypt_block(key, block)
        recovered = xor_bytes(intermediate, known)
        value_name = "IV" if args.block_index == 0 else "effective IV (previous ciphertext block)"
        if args.block_index > 0:
            expected = ciphertext[offset - AES_BLOCK_SIZE : offset]
            key_confirmed = recovered == expected
            note = "For block N>0 this value is C[N-1]; matching it confirms the key."
        else:
            if iv:
                if len(iv) != AES_BLOCK_SIZE:
                    raise UsageError("CBC --iv must be 16 bytes")
                expected = iv
                key_confirmed = recovered == expected
            note = "IV = P0 xor D(C0) for the first CBC block."
    elif args.mode == "ctr":
        recovered = xor_bytes(block, known)
        value_name = "keystream block"
        if iv:
            if len(iv) != AES_BLOCK_SIZE:
                raise UsageError("CTR --iv must be 16 bytes")
            order: Literal["little", "big"] = "little" if args.ctr_little_endian else "big"
            counter = (int.from_bytes(iv, order) + args.block_index) % (1 << 128)
            expected = aes_ecb_encrypt_block(key, counter.to_bytes(16, order))
            key_confirmed = recovered == expected
            note = "CTR keystream = AES(key, initial_counter + block_index)."
        else:
            note = "Without the initial counter only this keystream block is recoverable."
    elif args.mode == "ofb":
        recovered = xor_bytes(block, known)
        value_name = "keystream block"
        if iv:
            if len(iv) != AES_BLOCK_SIZE:
                raise UsageError("OFB --iv must be 16 bytes")
            if args.block_index > 1_000_000:
                raise UsageError("OFB block index above 1,000,000 is not supported")
            state = iv
            for _ in range(args.block_index + 1):
                state = aes_ecb_encrypt_block(key, state)
            expected = state
            key_confirmed = recovered == expected
            note = "OFB keystream block N is E^N+1(IV)."
        else:
            note = "Without the IV only this keystream block is recoverable."
    else:  # cfb
        recovered = xor_bytes(block, known)
        value_name = "keystream block"
        if args.block_index == 0:
            if iv:
                if len(iv) != AES_BLOCK_SIZE:
                    raise UsageError("CFB --iv must be 16 bytes")
                expected = aes_ecb_encrypt_block(key, iv)
                key_confirmed = recovered == expected
            note = "CFB keystream block 0 is E(IV)."
        else:
            expected = aes_ecb_encrypt_block(key, ciphertext[offset - AES_BLOCK_SIZE : offset])
            key_confirmed = recovered == expected
            note = "CFB keystream block N is E(C[N-1])."

    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "recover-iv",
        "mode": args.mode,
        "block_index": args.block_index,
        "recovered_name": value_name,
        "recovered": recovered.hex(),
        "expected": expected.hex() if expected is not None else None,
        "key_confirmed": key_confirmed,
        "note": note,
        "errors": [],
    }
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)
        return 0
    print(f"Mode: {args.mode.upper()}")
    print(f"Block index: {args.block_index}")
    label = "IV" if value_name == "IV" else value_name.capitalize()
    print(f"{label}: {format_hex(recovered)}")
    if expected is not None:
        print(f"Expected: {format_hex(expected)}")
        print(f"Key confirmed: {'yes' if key_confirmed else 'no'}")
    if note:
        print(f"Note: {note}")
    return 0
