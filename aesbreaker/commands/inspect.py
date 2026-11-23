"""``aesbreaker inspect``: describe a container without attempting decryption."""

from __future__ import annotations

import argparse
from pathlib import Path

from .. import __version__
from ..util import escape_control, format_bytes, sha256_file, write_json
from . import common


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="container file to inspect")
    common.add_format_arguments(parser)
    parser.add_argument("--no-hash", action="store_true", help="skip SHA-256 calculation")
    parser.add_argument("--json", action="store_true", help="write the report as JSON")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON report to FILE")


_ACRONYMS = {
    "aes": "AES",
    "kdf": "KDF",
    "iv": "IV",
    "hmac": "HMAC",
    "crc32": "CRC-32",
    "fs16": "fs16",
    "utf8": "UTF-8",
    "zip64": "ZIP64",
    "sha256": "SHA-256",
    "aad": "AAD",
    "ctr": "CTR",
}


def _label(key: str) -> str:
    words = key.split("_")
    rendered = []
    for index, word in enumerate(words):
        if word in _ACRONYMS:
            rendered.append(_ACRONYMS[word])
        elif index == 0:
            rendered.append(word[:1].upper() + word[1:])
        else:
            rendered.append(word)
    return " ".join(rendered)


def _format_scalar(value) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, str):
        return escape_control(value)
    return str(value)


def _print_value(label: str, value, indent: int) -> None:
    pad = " " * indent
    if isinstance(value, dict):
        print(f"{pad}{label}:")
        for key, child in value.items():
            _print_value(_label(key), child, indent + 2)
    elif isinstance(value, list):
        if not value:
            print(f"{pad}{label}: []")
            return
        if all(not isinstance(item, (dict, list)) for item in value):
            print(f"{pad}{label}:")
            for item in value:
                print(f"{pad}  - {_format_scalar(item)}")
            return
        print(f"{pad}{label}:")
        for index, item in enumerate(value):
            if isinstance(item, dict):
                name = item.get("name") or item.get("index")
                rendered_name = "" if name is None else escape_control(str(name))
                print(f"{pad}  [{index}] {rendered_name}:")
                for key, child in item.items():
                    if key in ("name", "index"):
                        continue
                    _print_value(_label(key), child, indent + 4)
            else:
                print(f"{pad}  - {_format_scalar(item)}")
    else:
        print(f"{pad}{label}: {_format_scalar(value)}")


def run(args: argparse.Namespace) -> int:
    if common.normalize_format(args.format or "auto") == "custom":
        return _run(args)
    with common.decoded_input(args):
        return _run(args)


def _run(args: argparse.Namespace) -> int:
    artifact = common.open_artifact_from_args(args)
    common.attach_input_origin(args, artifact)
    common.validate_format_options(artifact, args)
    source = Path(common.input_display(args, artifact))
    common.validate_side_outputs(
        args,
        inputs=(
            str(artifact.path),
            str(source),
            getattr(args, "spec", None),
        ),
    )
    details = artifact.inspect()
    digest = None if args.no_hash else sha256_file(source)
    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "inspect",
        "input": str(source),
        "size": source.stat().st_size,
        "sha256": digest,
        "format": artifact.format_name,
        "format_display": artifact.display_name,
        "details": details,
    }
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)
        return 0

    print(f"File: {source}")
    print(f"Size: {format_bytes(source.stat().st_size)} ({source.stat().st_size:,} bytes)")
    if digest:
        print(f"SHA-256: {digest}")
    print(f"Format: {artifact.display_name}")
    print("-" * 60)
    for key, value in details.items():
        _print_value(_label(key), value, 0)
    return 0
