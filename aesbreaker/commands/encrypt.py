"""``aesbreaker encrypt``: produce compatible containers for labs and testing."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import __version__
from ..errors import InputError, UsageError
from ..formats.aescrypt import encrypt_stream as encrypt_aescrypt
from ..formats.custom import encrypt_spec_file as encrypt_custom_spec
from ..formats.openssl_enc import encrypt_stream as encrypt_openssl
from ..formats.zip_aes import build_zip_aes
from ..kdf import SUPPORTED_DIGESTS
from ..util import check_output_path, format_bytes, write_json
from . import common

ZIP_STRENGTHS = {"128": 1, "192": 2, "256": 3}


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="plaintext file to encrypt")
    common.add_password_arguments(parser, encrypt=True)
    parser.add_argument(
        "--format",
        choices=("aescrypt", "openssl-enc", "zip-aes", "custom"),
        default="aescrypt",
        help="output container format (default: aescrypt)",
    )
    parser.add_argument(
        "--spec",
        metavar="FILE",
        help="JSON spec for --format custom",
    )
    common.add_output_arguments(parser)
    group = parser.add_argument_group("AES Crypt output options")
    group.add_argument(
        "--aescrypt-version",
        choices=("2", "3"),
        default="2",
        help="AES Crypt wire version (default: 2; v3 uses PBKDF2-HMAC-SHA512)",
    )
    group.add_argument(
        "--aescrypt-iterations",
        type=common.positive_int,
        default=600_000,
        help="AES Crypt v3 PBKDF2 iterations (default: 600000)",
    )
    group = parser.add_argument_group("OpenSSL enc output options")
    group.add_argument("--openssl-cipher", default="aes-256-cbc", metavar="CIPHER")
    group.add_argument("--openssl-digest", choices=SUPPORTED_DIGESTS, default="sha256")
    group.add_argument("--openssl-pbkdf2", action="store_true")
    group.add_argument("--openssl-iterations", type=common.positive_int, default=10000)
    group.add_argument("--openssl-nosalt", action="store_true")
    group.add_argument(
        "--openssl-nopad",
        action="store_true",
        help="do not add PKCS#7 padding (input length must be a multiple of 16)",
    )
    group = parser.add_argument_group("WinZip AES output options")
    group.add_argument("--zip-strength", choices=("128", "192", "256"), default="256")
    group.add_argument("--zip-compression", choices=("deflate", "store"), default="deflate")
    group.add_argument("--entry-name", metavar="NAME", help="name stored inside the ZIP")
    parser.add_argument("--json", action="store_true", help="write the result as JSON")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON result to FILE")


def _default_output(input_path: Path, format_name: str) -> str:
    suffix = {
        "aescrypt": ".aes",
        "openssl-enc": ".enc",
        "zip-aes": ".zip",
        "custom": ".custom",
    }[format_name]
    return str(input_path) + suffix


def run(args: argparse.Namespace) -> int:
    source = Path(args.input)
    if not source.is_file():
        raise InputError(f"input file not found: {source}")
    openssl_specific = any(
        (
            args.openssl_cipher != "aes-256-cbc",
            args.openssl_digest != "sha256",
            args.openssl_pbkdf2,
            args.openssl_iterations != 10000,
            args.openssl_nosalt,
            args.openssl_nopad,
        )
    )
    aescrypt_version = int(args.aescrypt_version)
    aescrypt_specific = aescrypt_version != 2 or args.aescrypt_iterations != 600_000
    if args.format != "aescrypt":
        if aescrypt_specific:
            raise UsageError(f"AES Crypt options do not apply to --format {args.format}")
    elif aescrypt_version == 2 and args.aescrypt_iterations != 600_000:
        raise UsageError("--aescrypt-iterations only applies to AES Crypt v3")
    zip_specific = any(
        (
            args.zip_strength != "256",
            args.zip_compression != "deflate",
            args.entry_name is not None,
        )
    )
    if args.format != "openssl-enc" and openssl_specific:
        raise UsageError(f"OpenSSL options do not apply to --format {args.format}")
    if args.format != "zip-aes" and zip_specific:
        raise UsageError(f"ZIP options do not apply to --format {args.format}")
    if args.format != "custom":
        if args.spec:
            raise UsageError("--spec requires --format custom")
        if args.format != "aescrypt" and aescrypt_specific:
            raise UsageError(f"AES Crypt options do not apply to --format {args.format}")
    elif not args.spec:
        raise UsageError("--format custom requires --spec FILE")
    elif aescrypt_specific:
        raise UsageError("AES Crypt options do not apply to --format custom")

    password = common.resolve_password(args, confirm=True)
    output = args.out or _default_output(source, args.format)
    if output != "-":
        if Path(output).resolve() == source.resolve():
            raise UsageError("refusing to overwrite the plaintext input")
        check_output_path(output, overwrite=args.overwrite)
    common.validate_side_outputs(
        args,
        inputs=(str(source), args.password_file, args.spec),
        primary=output,
    )

    bytes_written = 0
    details: dict = {}
    if args.format == "custom":
        plaintext = source.read_bytes()
        payload = encrypt_custom_spec(args.spec, plaintext, password)
        with common.output_sink(output, overwrite=args.overwrite) as handle:
            handle.write(payload)
        bytes_written = len(payload)
        details = {
            "format_display": "Custom AES (JSON spec)",
            "spec": args.spec,
            "cipher": "spec-defined",
            "kdf": "spec-defined",
            "authentication": "spec-defined oracle on decryption",
        }
    elif args.format == "aescrypt":
        with source.open("rb") as src, common.output_sink(output, overwrite=args.overwrite) as dst:
            encrypt_aescrypt(
                src,
                dst,
                password,
                version=aescrypt_version,
                iterations=args.aescrypt_iterations,
                created_by=f"AES-Breaker {__version__}",
            )
        bytes_written = Path(output).stat().st_size if output != "-" else 0
        details = {
            "format_display": f"AES Crypt v{aescrypt_version}",
            "kdf": (
                f"PBKDF2-HMAC-SHA512 ({args.aescrypt_iterations} iterations, UTF-8 password)"
                if aescrypt_version == 3
                else "ACKDF-SHA-256 (8192 rounds, UTF-16LE password)"
            ),
            "cipher": "AES-256-CBC",
            "authentication": "HMAC-SHA256",
        }
    elif args.format == "openssl-enc":
        with source.open("rb") as src, common.output_sink(output, overwrite=args.overwrite) as dst:
            encrypt_openssl(
                src,
                dst,
                password,
                cipher_name=args.openssl_cipher,
                digest=args.openssl_digest,
                use_pbkdf2=args.openssl_pbkdf2,
                iterations=args.openssl_iterations,
                salted=not args.openssl_nosalt,
                nopad=args.openssl_nopad,
            )
        bytes_written = Path(output).stat().st_size if output != "-" else 0
        details = {
            "format_display": "OpenSSL enc",
            "cipher": args.openssl_cipher,
            "kdf": (
                f"PBKDF2-HMAC-{args.openssl_digest.upper()} ({args.openssl_iterations})"
                if args.openssl_pbkdf2
                else f"EVP_BytesToKey-{args.openssl_digest.upper()}"
            ),
            "salted": not args.openssl_nosalt,
            "authentication": "none",
        }
    else:
        data = source.read_bytes()
        entry_name = args.entry_name or source.name
        payload = build_zip_aes(
            entry_name,
            data,
            password,
            strength=ZIP_STRENGTHS[args.zip_strength],
            compression=args.zip_compression,
        )
        archive_bytes = payload
        with common.output_sink(output, overwrite=args.overwrite) as handle:
            handle.write(archive_bytes)
        bytes_written = len(archive_bytes)
        details = {
            "format_display": f"WinZip AES (AE-2, AES-{args.zip_strength})",
            "entry": entry_name,
            "compression": args.zip_compression,
            "kdf": "PBKDF2-HMAC-SHA1 (1000 iterations)",
            "authentication": "HMAC-SHA1 auth code",
        }

    result_payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "encrypt",
        "input": str(source),
        "format": args.format,
        "output": output,
        "bytes_written": bytes_written,
        "details": details,
        "errors": [],
    }
    if args.json_out:
        write_json(args.json_out, result_payload)
    if args.json:
        write_json(None, result_payload)
        return 0
    stream = sys.stderr if output == "-" else sys.stdout
    print(f"Encrypted: {output}", file=stream)
    if output != "-":
        print(f"Bytes: {format_bytes(bytes_written)}", file=stream)
    print(f"Format: {details['format_display']}", file=stream)
    print(f"KDF: {details['kdf']}", file=stream)
    if details.get("authentication") == "none":
        print("Note: openssl enc does not authenticate the ciphertext.", file=stream)
    return 0
