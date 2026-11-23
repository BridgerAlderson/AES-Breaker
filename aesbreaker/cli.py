"""Command-line entry point."""

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

from . import __version__
from .commands import (
    analyze,
    crack,
    cribdrag,
    decrypt,
    derive,
    encrypt,
    infer,
    inspect,
    recover_iv,
    selftest,
)
from .errors import AesBreakerError

COMMANDS = (
    (crack, "crack", "recover a password with wordlists, rules, masks, or hybrids"),
    (decrypt, "decrypt", "decrypt with a known password or an exact raw AES spec"),
    (inspect, "inspect", "describe a container without decrypting it"),
    (analyze, "analyze", "statistical checks for unknown data (entropy, ECB blocks)"),
    (derive, "derive", "reproduce EVP/PBKDF2/HKDF key derivation"),
    (cribdrag, "cribdrag", "test a known plaintext crib against two CTR/OFB ciphertexts"),
    (recover_iv, "recover-iv", "recover a CBC IV or stream keystream from known plaintext"),
    (infer, "infer", "rank raw AES mode/IV interpretations with explicit confidence"),
    (encrypt, "encrypt", "create a compatible AES Crypt, OpenSSL, or WinZip AES file"),
    (selftest, "selftest", "run known-answer and interoperability checks"),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aesbreaker",
        description=(
            "AES decryption and password recovery for AES Crypt v1/v2/v3, "
            "OpenSSL enc, WinZip AES, and explicit custom specs."
        ),
        epilog=(
            "Authenticated containers (AES Crypt, WinZip AES) confirm passwords with "
            "their MAC. OpenSSL enc has no MAC, so its results are labelled confirmed "
            "only with a known plaintext prefix."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"aesbreaker {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for module, name, help_text in COMMANDS:
        subparser = subparsers.add_parser(
            name,
            help=help_text,
            description=help_text,
        )
        module.configure(subparser)
        subparser.set_defaults(func=module.run)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args)) or 0
    except AesBreakerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except BrokenPipeError:
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - final boundary
        if os.environ.get("AESBREAKER_DEBUG"):
            raise
        print(
            f"internal error: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        print(
            "set AESBREAKER_DEBUG=1 to see a traceback",
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
