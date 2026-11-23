"""``aesbreaker derive``: reproduce container KDFs and derive raw key material."""

from __future__ import annotations

import argparse
import base64
import sys

from .. import __version__
from ..errors import UsageError
from ..kdf import (
    SUPPORTED_DIGESTS,
    evp_bytes_to_key,
    hkdf,
    normalize_digest,
    pbkdf2,
)
from ..util import format_hex, parse_hex_data, read_file, write_json
from . import common


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--kdf", choices=("evp", "pbkdf2", "hkdf"), required=True)
    common.add_password_arguments(parser)
    parser.add_argument("--salt", metavar="HEX", help="salt as hex")
    parser.add_argument("--salt-file", metavar="FILE", help="raw salt bytes from a file")
    parser.add_argument("--digest", choices=SUPPORTED_DIGESTS, default="sha256")
    parser.add_argument(
        "--key-length",
        type=common.positive_int,
        default=None,
        metavar="N",
        help="EVP key length (default: 32)",
    )
    parser.add_argument(
        "--iv-length",
        type=common.nonnegative_int,
        default=None,
        metavar="N",
        help="EVP IV length (default: 16; PBKDF2/HKDF: split this many bytes off as IV)",
    )
    parser.add_argument(
        "--length",
        type=common.positive_int,
        default=None,
        metavar="N",
        help="total PBKDF2/HKDF output length (default: key length + IV length)",
    )
    parser.add_argument("--iterations", type=common.positive_int, default=10000)
    parser.add_argument("--info", metavar="HEX", help="HKDF info string as hex")
    parser.add_argument("--base64", action="store_true", help="print base64 instead of hex")
    parser.add_argument("--out", metavar="FILE", help="write raw key||iv bytes to FILE")
    parser.add_argument("--json", action="store_true", help="write the result as JSON")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON result to FILE")


def _salt(args) -> bytes:
    if args.salt is not None and args.salt_file is not None:
        raise UsageError("use --salt or --salt-file, not both")
    if args.salt_file is not None:
        return read_file(args.salt_file)
    if args.salt is not None:
        return parse_hex_data(args.salt, what="salt")
    return b""


def run(args: argparse.Namespace) -> int:
    if args.kdf != "pbkdf2" and args.iterations != 10000:
        raise UsageError("--iterations only applies to PBKDF2")
    if args.kdf == "evp" and args.length is not None:
        raise UsageError("--length is not used by EVP; use --key-length/--iv-length")
    if args.kdf != "hkdf" and args.info is not None:
        raise UsageError("--info only applies to HKDF")
    password = common.resolve_password(args)
    salt = _salt(args)
    digest = normalize_digest(args.digest)
    common.validate_side_outputs(
        args,
        inputs=(args.password_file, args.salt_file),
        primary=args.out,
    )
    key_length = args.key_length or 32
    iv_length = args.iv_length
    if iv_length is None:
        iv_length = 16 if args.kdf == "evp" else 0

    key = b""
    iv = b""
    if args.kdf == "evp":
        key, iv = evp_bytes_to_key(password, salt, key_length, iv_length, digest=digest)
    elif args.kdf == "pbkdf2":
        total = args.length or (key_length + iv_length)
        material = pbkdf2(
            password,
            salt,
            args.iterations,
            total,
            digest=digest,
        )
        if iv_length:
            if iv_length >= total:
                raise UsageError("--iv-length must be smaller than the total length")
            key = material[: total - iv_length]
            iv = material[total - iv_length :]
        else:
            key = material
    else:
        info = parse_hex_data(args.info, what="HKDF info") if args.info else b""
        total = args.length or (key_length + iv_length)
        material = hkdf(password, salt, info, total, digest=digest)
        if iv_length:
            if iv_length >= total:
                raise UsageError("--iv-length must be smaller than the total length")
            key = material[: total - iv_length]
            iv = material[total - iv_length :]
        else:
            key = material

    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "derive",
        "kdf": args.kdf,
        "digest": digest,
        "iterations": args.iterations if args.kdf == "pbkdf2" else None,
        "salt": salt.hex(),
        "key": key.hex(),
        "iv": iv.hex() if iv else None,
        "key_bits": len(key) * 8,
        "errors": [],
    }
    if args.out:
        with common.output_sink(args.out, overwrite=True) as handle:
            handle.write(key + iv)
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)
        return 0

    def render(value: bytes) -> str:
        if args.base64:
            return base64.b64encode(value).decode("ascii")
        return format_hex(value)

    stream = sys.stderr if args.out == "-" else sys.stdout
    print(
        f"KDF: {args.kdf} ({digest}"
        f"{'' if args.kdf != 'pbkdf2' else f', {args.iterations} iterations'})",
        file=stream,
    )
    if salt:
        print(f"Salt: {salt.hex()}", file=stream)
    print(f"Key ({len(key) * 8} bits): {render(key)}", file=stream)
    if iv:
        print(f"IV ({len(iv) * 8} bits): {render(iv)}", file=stream)
    if args.out:
        print(f"Raw output: {args.out}", file=stream)
    return 0
