"""``aesbreaker decrypt``: decrypt with a known password or an exact raw spec."""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

from .. import __version__
from ..crypto import parse_cipher
from ..errors import InputError, UsageError
from ..formats import detect_and_open, normalize_format
from ..formats.base import Artifact
from ..formats.raw import RawSpec, decrypt_stream
from ..util import (
    check_output_path,
    decode_encoded_bytes,
    escape_control,
    format_bytes,
    parse_hex_data,
    parse_size,
    read_encoded_data,
    read_file,
    write_json,
)
from . import common

RAW_ENCODINGS = ("auto", "raw", "hex", "base64")


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="encrypted input file ('-' reads stdin in raw mode)")
    common.add_password_arguments(parser)
    common.add_format_arguments(parser, include_format=False)
    common.add_policy_arguments(parser)
    parser.add_argument(
        "--format",
        default=None,
        metavar="FORMAT",
        help="auto, aescrypt, openssl-enc, zip-aes, custom, or raw",
    )

    group = parser.add_argument_group("raw AES parameters (--format raw)")
    group.add_argument(
        "--cipher", metavar="CIPHER", help="e.g. aes-256-cbc, aes-256-ctr, aes-256-gcm"
    )
    group.add_argument("--key", metavar="HEX", help="raw key as hex")
    group.add_argument("--key-text", metavar="TEXT", help="raw key as UTF-8 text")
    group.add_argument("--key-file", metavar="FILE", help="raw key bytes from a file")
    group.add_argument("--iv", metavar="HEX", help="IV (CBC/CFB/OFB) or initial counter (CTR)")
    group.add_argument("--iv-file", metavar="FILE", help="raw IV bytes from a file")
    group.add_argument("--nonce", metavar="HEX", help="GCM nonce")
    group.add_argument("--tag", metavar="HEX", help="GCM authentication tag")
    group.add_argument("--aad", metavar="HEX", help="GCM additional authenticated data")
    group.add_argument(
        "--padding",
        choices=("pkcs7", "none"),
        default=None,
        help="block padding (default: pkcs7 for CBC/ECB, none for stream modes)",
    )
    group.add_argument(
        "--ctr-little-endian",
        action="store_true",
        help="use a little-endian CTR counter (WinZip style)",
    )
    group.add_argument(
        "--in-encoding",
        choices=RAW_ENCODINGS,
        default="auto",
        help="raw ciphertext encoding (default: auto)",
    )

    common.add_output_arguments(parser)
    parser.add_argument(
        "--max-extract-size",
        type=parse_size,
        default=parse_size("8G"),
        metavar="SIZE",
        help="ZIP extraction output limit (default: 8G; 0 = unlimited)",
    )
    parser.add_argument("--json", action="store_true", help="write the result as JSON")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON result to FILE")


def _raw_key(args) -> bytes:
    sources = [
        args.key is not None,
        args.key_text is not None,
        args.key_file is not None,
    ]
    if sum(sources) != 1:
        raise UsageError("supply exactly one of --key, --key-text, or --key-file")
    if args.key is not None:
        return parse_hex_data(args.key, what="key")
    if args.key_text is not None:
        return args.key_text.encode("utf-8")
    assert args.key_file is not None
    if args.key_file == "-":
        raise UsageError("--key-file cannot be stdin")
    return read_file(args.key_file)


def _raw_iv(args) -> bytes:
    sources = [args.iv is not None, args.iv_file is not None]
    if sum(sources) > 1:
        raise UsageError("use --iv or --iv-file, not both")
    if args.iv is not None:
        return parse_hex_data(args.iv, what="IV")
    if args.iv_file is not None:
        return read_file(args.iv_file)
    return b""


def _raw_input(args) -> bytes:
    if args.input == "-":
        return decode_encoded_bytes(sys.stdin.buffer.read(), args.in_encoding, what="ciphertext")
    return read_encoded_data(args.input, args.in_encoding, what="ciphertext")


def _raw_decrypt(args) -> int:
    if not args.cipher:
        raise UsageError("raw decryption requires --cipher")
    cipher = parse_cipher(args.cipher)
    key = _raw_key(args)
    iv = _raw_iv(args)
    nonce = parse_hex_data(args.nonce, what="nonce") if args.nonce else b""
    tag = parse_hex_data(args.tag, what="tag") if args.tag else b""
    aad = parse_hex_data(args.aad, what="AAD") if args.aad else b""
    if args.padding is None:
        padding = "pkcs7" if cipher.mode in ("cbc", "ecb") else "none"
    else:
        padding = args.padding
    spec = RawSpec(
        cipher=cipher,
        key=key,
        iv=iv,
        nonce=nonce,
        tag=tag,
        aad=aad,
        padding=padding,
        ctr_little_endian=args.ctr_little_endian,
    ).validate()

    data = _raw_input(args)
    output = args.out
    if output is None:
        if args.input == "-":
            raise UsageError("reading stdin requires --out (or --out -)")
        output = args.input + ".dec"
    if output != "-":
        common.ensure_output_is_not_input(output, _RawInput(args.input))
        check_output_path(output, overwrite=args.overwrite)
    common.validate_side_outputs(
        args,
        inputs=(
            args.input if args.input != "-" else None,
            args.key_file,
            args.iv_file,
        ),
        primary=output,
    )

    with common.output_sink(output, overwrite=args.overwrite) as handle:
        written = decrypt_stream(io.BytesIO(data), handle, spec)

    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "decrypt",
        "mode": "raw",
        "input": args.input,
        "cipher": cipher.name,
        "key_bits": cipher.key_len * 8,
        "padding": padding,
        "authenticated": cipher.mode == "gcm",
        "tag_verified": cipher.mode == "gcm",
        "output": output,
        "bytes_written": written,
        "errors": [],
    }
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)
        return 0
    stream = sys.stderr if output == "-" else sys.stdout
    print(f"Cipher: {cipher.describe()}", file=stream)
    print(f"Output: {output}", file=stream)
    print(f"Bytes: {format_bytes(written)}", file=stream)
    if cipher.mode == "gcm":
        print("Authentication: GCM tag verified", file=stream)
    else:
        print("Authentication: none available for this raw mode", file=stream)
        print(
            "Note: without a tag or MAC a wrong key may produce plausible output; "
            "use GCM or verify the plaintext independently.",
            file=stream,
        )
    return 0


class _RawInput:
    """Minimal artifact-like adapter for the path safety helper."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)


def _container_decrypt(args) -> int:
    policy = common.policy_from_args(args)
    format_hint = normalize_format(args.format or "auto")
    if format_hint not in (
        "auto",
        "aescrypt",
        "openssl-enc",
        "zip-aes",
        "custom",
    ):
        raise UsageError(f"unknown format: {args.format}")
    artifact: Artifact
    if format_hint == "custom":
        if not args.spec:
            raise UsageError("--format custom requires --spec FILE")
        if args.known_prefix is not None or args.known_prefix_hex is not None:
            raise UsageError(
                "--known-prefix is not used with a custom spec",
                hint='put the oracle in the spec\'s "oracle" object',
            )
        if args.policy != "auto":
            raise UsageError("--policy is not used with a custom spec")
        if (
            args.iv is not None
            or args.iv_file is not None
            or args.aad is not None
            or args.padding is not None
            or args.ctr_little_endian
            or args.in_encoding != "auto"
        ):
            raise UsageError(
                "raw AES options are not used with --format custom",
                hint="put IV/AAD/encoding details in the JSON spec",
            )
        from ..formats.custom import CustomArtifact

        artifact = CustomArtifact(args.input, args.spec)
    else:
        if args.spec:
            raise UsageError("--spec requires --format custom")
        artifact = detect_and_open(
            args.input,
            format_hint,
            common.format_options_from_args(args),
            policy=policy,
        )
    common.attach_input_origin(args, artifact)
    common.validate_format_options(artifact, args)
    if artifact.format_name == "openssl":
        require_cipher = getattr(artifact, "require_cipher", None)
        if require_cipher is not None:
            require_cipher()

    password = common.resolve_password(args)
    output = common.output_path_from_args(args, artifact)
    common.ensure_output_is_not_input(output, artifact)
    common.validate_side_outputs(
        args,
        inputs=(
            str(artifact.path),
            args.password_file,
            args.spec,
            getattr(args, "_input_original", None),
        ),
        primary=output,
    )
    if artifact.output_kind == "directory":
        if output == "-":
            raise UsageError("ZIP extraction requires a directory output, not '-'")
        if Path(output).exists() and not Path(output).is_dir():
            raise InputError(f"output path is not a directory: {output}")
        max_bytes = None if args.max_extract_size == 0 else args.max_extract_size
        report = artifact.extract(
            password,
            output,
            overwrite=args.overwrite,
            max_output_bytes=max_bytes,
        )
        details = dict(report.details)
        errors = list(details.get("errors") or [])
        payload = {
            "tool": "aesbreaker",
            "version": __version__,
            "command": "decrypt",
            "input": common.input_display(args, artifact),
            "format": artifact.format_name,
            "format_display": artifact.display_name,
            "output": output,
            "bytes_written": report.bytes_written,
            "verification": report.verification,
            "authenticated": True,
            "extraction": details,
            "errors": errors,
        }
        if args.json_out:
            write_json(args.json_out, payload)
        if args.json:
            write_json(None, payload)
        else:
            print(f"Format: {artifact.display_name}")
            print(f"Output directory: {output}")
            print(f"Extracted: {details.get('extracted_count', 0)}")
            print(f"Verification: {report.verification}")
            for entry in details.get("entries", []):
                if entry.get("status") not in ("extracted", "directory"):
                    name = escape_control(str(entry.get("name", "")))
                    print(f"  {name}: {entry.get('status')}")
            for error in errors:
                print(f"  error: {escape_control(error)}", file=sys.stderr)
        if errors:
            return 3
        return 0 if details.get("extracted_count", 0) > 0 else 3

    if output != "-":
        check_output_path(output, overwrite=args.overwrite)
    with common.output_sink(output, overwrite=args.overwrite) as handle:
        report = artifact.decrypt(password, handle)

    authenticated = artifact.format_name in ("aescrypt", "zip-aes")
    if artifact.format_name == "custom":
        authenticated = bool(report.details.get("authenticated", False))
    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "decrypt",
        "input": common.input_display(args, artifact),
        "format": artifact.format_name,
        "format_display": artifact.display_name,
        "output": output,
        "bytes_written": report.bytes_written,
        "verification": report.verification,
        "authenticated": authenticated,
        "details": report.details,
        "errors": [],
    }
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)
        return 0
    stream = sys.stderr if output == "-" else sys.stdout
    print(f"Format: {artifact.display_name}", file=stream)
    print(f"Output: {output}", file=stream)
    print(f"Bytes: {format_bytes(report.bytes_written)}", file=stream)
    print(f"Verification: {report.verification}", file=stream)
    if artifact.format_name == "openssl":
        print(
            "Note: openssl enc provides no authentication; a correct-looking "
            "plaintext can still come from a wrong key.",
            file=stream,
        )
    elif artifact.format_name == "custom" and not authenticated:
        if getattr(getattr(artifact, "config", None), "oracle_type", None):
            print(
                "Note: the spec oracle confirmed the password, but this spec "
                "has no ciphertext MAC/tag; the plaintext is not independently "
                "authenticated.",
                file=stream,
            )
        else:
            print(
                "Note: this spec has no verification oracle; the plaintext is unverified.",
                file=stream,
            )
    return 0


def run(args: argparse.Namespace) -> int:
    requested = normalize_format(args.format or "auto")
    if requested in ("raw", "custom"):
        return _run(args)
    with common.decoded_input(args):
        return _run(args)


def _run(args: argparse.Namespace) -> int:
    requested = normalize_format(args.format or "auto")
    if args.spec and requested != "custom":
        raise UsageError("--spec requires --format custom")
    if requested == "raw":
        if args.password is not None or args.password_hex is not None or args.password_file:
            raise UsageError(
                "raw mode takes --key material, not --password",
                hint="derive a key with 'aesbreaker derive' first",
            )
        openssl_specific = any(
            (
                args.openssl_cipher,
                args.openssl_digest,
                args.openssl_iterations,
                args.openssl_pbkdf2,
                args.openssl_nosalt,
                args.openssl_nopad,
                args.entry,
                args.openssl_encoding != "auto",
            )
        )
        if openssl_specific:
            raise UsageError("--openssl-* options cannot be used with --format raw")
        return _raw_decrypt(args)
    if args.cipher or args.key or args.key_text or args.key_file or args.nonce or args.tag:
        raise UsageError(
            "raw AES options require --format raw",
            hint="use --format raw --cipher aes-256-cbc --key <hex> ...",
        )
    if args.padding is not None or args.ctr_little_endian or args.in_encoding != "auto":
        raise UsageError("--padding/--ctr-little-endian/--in-encoding require --format raw")
    if args.input == "-":
        raise UsageError("container formats require a file input, not stdin")
    return _container_decrypt(args)
