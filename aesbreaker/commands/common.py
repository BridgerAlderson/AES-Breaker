"""Shared CLI argument handling and reporting helpers."""

from __future__ import annotations

import argparse
import getpass
import shutil
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Protocol

from ..candidates import PlanOptions, PlanSummary
from ..errors import InputError, OutputError, UsageError
from ..formats import detect_and_open, normalize_format
from ..formats.base import Artifact, FormatOptions, ValidationPolicy
from ..kdf import SUPPORTED_DIGESTS
from ..masks import (
    build_charset_plan,
    parse_custom_definitions,
    parse_mask,
)
from ..rules import Rule, RuleSet, load_preset, load_rule_file, parse_rule
from ..signatures import looks_like_base64
from ..util import (
    atomic_writer,
    b64_decode,
    format_count,
    parse_hex_data,
    read_file,
    read_password_file,
    safe_password_text,
)

FORMAT_CHOICES = ("auto", "aescrypt", "openssl-enc", "zip-aes", "custom")
POLICY_CHOICES = ("auto", "strict", "text", "magic", "any")
ENCODING_CHOICES = ("auto", "raw", "base64")


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a number") from None
    if not parsed > 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer") from None
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def add_format_arguments(parser: argparse.ArgumentParser, *, include_format: bool = True) -> None:
    if include_format:
        parser.add_argument(
            "--format",
            default="auto",
            metavar="FORMAT",
            help="auto, aescrypt, openssl-enc, zip-aes, or custom (default: auto)",
        )
    group = parser.add_argument_group("OpenSSL enc options")
    group.add_argument(
        "--openssl-cipher",
        metavar="CIPHER",
        help="cipher used by openssl enc (required for OpenSSL files), e.g. aes-256-cbc",
    )
    group.add_argument(
        "--openssl-digest",
        choices=SUPPORTED_DIGESTS,
        default=None,
        help="KDF digest (default: sha256, matching OpenSSL 3; use md5 for old files)",
    )
    group.add_argument(
        "--openssl-pbkdf2",
        action="store_true",
        help="use PBKDF2 instead of EVP_BytesToKey",
    )
    group.add_argument(
        "--openssl-iterations",
        type=positive_int,
        default=None,
        metavar="N",
        help="PBKDF2 iteration count (default: 10000)",
    )
    group.add_argument(
        "--openssl-nosalt",
        action="store_true",
        help="the file was created with 'openssl enc -nosalt'",
    )
    group.add_argument(
        "--openssl-nopad",
        action="store_true",
        help="the file was created with 'openssl enc -nopad' (block modes only)",
    )
    group.add_argument(
        "--openssl-encoding",
        choices=ENCODING_CHOICES,
        default="auto",
        help="OpenSSL input encoding (default: auto)",
    )
    parser.add_argument(
        "--entry",
        metavar="NAME|INDEX",
        help="ZIP entry to verify against (default: first WinZip AES entry)",
    )
    parser.add_argument(
        "--spec",
        metavar="FILE",
        help="JSON scheme/spec for --format custom",
    )


def add_policy_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("unauthenticated format verification")
    group.add_argument(
        "--policy",
        choices=POLICY_CHOICES,
        default="auto",
        help=(
            "how to accept candidates for openssl enc, which has no MAC: "
            "auto (text/magic), strict (prefix only), text, magic, or any "
            "(padding only, unconfirmed)"
        ),
    )
    group.add_argument(
        "--known-prefix",
        metavar="TEXT",
        help="exact known plaintext prefix (UTF-8) used to confirm candidates",
    )
    group.add_argument(
        "--known-prefix-hex",
        metavar="HEX",
        help="exact known plaintext prefix as hex",
    )


def add_password_arguments(parser: argparse.ArgumentParser, *, encrypt: bool = False) -> None:
    group = parser.add_argument_group("password (avoid command-line secrets on shared hosts)")
    group.add_argument(
        "-p",
        "--password",
        help=(
            "password as UTF-8 text; visible in the process list and shell "
            "history (omit to prompt, or use --password-file)"
        ),
    )
    group.add_argument(
        "--password-hex",
        help=("password as hex bytes; visible in argv (prefer --password-file or the prompt)"),
    )
    group.add_argument(
        "--password-file",
        metavar="FILE",
        help="read the password from FILE (recommended for scripts)",
    )


def add_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-o",
        "--out",
        metavar="PATH",
        help="output file or directory ('-' writes plaintext to stdout for file formats)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="replace existing output files",
    )


def format_options_from_args(args: argparse.Namespace) -> FormatOptions:
    return FormatOptions(
        cipher=getattr(args, "openssl_cipher", None),
        digest=getattr(args, "openssl_digest", None) or "sha256",
        pbkdf2=bool(getattr(args, "openssl_pbkdf2", False)),
        iterations=getattr(args, "openssl_iterations", None) or 10000,
        nosalt=bool(getattr(args, "openssl_nosalt", False)),
        nopad=bool(getattr(args, "openssl_nopad", False)),
        in_encoding=getattr(args, "openssl_encoding", "auto") or "auto",
        entry=getattr(args, "entry", None),
        zip_strength=getattr(args, "zip_strength", 3),
        zip_compression=getattr(args, "zip_compression", "deflate"),
    )


def policy_from_args(args: argparse.Namespace) -> ValidationPolicy:
    text_prefix = getattr(args, "known_prefix", None)
    hex_prefix = getattr(args, "known_prefix_hex", None)
    if text_prefix is not None and hex_prefix is not None:
        raise UsageError("use --known-prefix or --known-prefix-hex, not both")
    prefix = b""
    if text_prefix is not None:
        prefix = text_prefix.encode("utf-8")
    elif hex_prefix is not None:
        prefix = parse_hex_data(hex_prefix, what="known prefix")
    return ValidationPolicy(
        mode=getattr(args, "policy", "auto"),
        known_prefix=prefix,
    )


def open_artifact_from_args(
    args: argparse.Namespace,
    policy: Optional[ValidationPolicy] = None,
) -> Artifact:
    format_hint = normalize_format(getattr(args, "format", "auto"))
    if format_hint not in (
        "auto",
        "aescrypt",
        "openssl-enc",
        "zip-aes",
        "custom",
    ):
        raise UsageError(
            f"unknown format: {getattr(args, 'format', 'auto')}",
            hint="choose auto, aescrypt, openssl-enc, zip-aes, or custom",
        )
    spec_path = getattr(args, "spec", None)
    if format_hint == "custom":
        if not spec_path:
            raise UsageError(
                "--format custom requires --spec FILE",
                hint="write a JSON spec describing the cipher, KDF, IV, and oracle",
            )
        if getattr(args, "known_prefix", None) or getattr(args, "known_prefix_hex", None):
            raise UsageError(
                "--known-prefix is not used with a custom spec",
                hint='put the oracle in the spec\'s "oracle" object',
            )
        if getattr(args, "policy", "auto") != "auto":
            raise UsageError("--policy is not used with a custom spec")
        from ..formats.custom import CustomArtifact

        return CustomArtifact(getattr(args, "input"), spec_path)
    if spec_path:
        raise UsageError("--spec requires --format custom")
    return detect_and_open(
        getattr(args, "input"),
        format_hint,
        format_options_from_args(args),
        policy=policy,
    )


def validate_format_options(artifact: Artifact, args: argparse.Namespace) -> None:
    openssl_specific = any(
        (
            getattr(args, "openssl_cipher", None),
            getattr(args, "openssl_digest", None),
            getattr(args, "openssl_iterations", None),
            getattr(args, "openssl_pbkdf2", False),
            getattr(args, "openssl_nosalt", False),
            getattr(args, "openssl_nopad", False),
            getattr(args, "openssl_encoding", "auto") != "auto",
        )
    )
    if artifact.format_name != "openssl" and openssl_specific:
        raise UsageError(f"--openssl-* options do not apply to {artifact.format_name} artifacts")
    if artifact.format_name != "zip-aes" and getattr(args, "entry", None):
        raise UsageError("--entry only applies to WinZip AES ZIP archives")
    if artifact.format_name == "zip-aes" and openssl_specific:
        raise UsageError("OpenSSL options cannot be used with a ZIP archive")


def resolve_password(
    args: argparse.Namespace,
    *,
    confirm: bool = False,
    required: bool = True,
) -> bytes:
    provided = [
        getattr(args, "password", None) is not None,
        getattr(args, "password_hex", None) is not None,
        getattr(args, "password_file", None) is not None,
    ]
    if sum(provided) > 1:
        raise UsageError("use only one of --password, --password-hex, or --password-file")
    if getattr(args, "password", None) is not None:
        return args.password.encode("utf-8")
    if getattr(args, "password_hex", None) is not None:
        password = parse_hex_data(args.password_hex, what="password")
        return password
    if getattr(args, "password_file", None) is not None:
        return read_password_file(args.password_file)
    if not required:
        return b""
    if not sys.stdin.isatty():
        raise UsageError(
            "a password is required",
            hint="use -p, --password-hex, or --password-file (stdin is not a terminal)",
        )
    try:
        first = getpass.getpass("Password: ")
        if confirm:
            second = getpass.getpass("Repeat password: ")
            if first != second:
                raise UsageError("passwords do not match")
    except (EOFError, KeyboardInterrupt):
        raise UsageError("password prompt cancelled") from None
    return first.encode("utf-8")


def password_json(password: Optional[bytes]) -> Optional[dict]:
    if password is None:
        return None
    text, display = safe_password_text(password)
    return {
        "hex": password.hex(),
        "text": text,
        "display": display,
        "valid_utf8": text is not None,
    }


def print_password(password: bytes) -> None:
    text, display = safe_password_text(password)
    print(f"Password: {display}")
    print(f"Password hex: {password.hex()}")
    if text is None:
        print("Note: the password is not valid UTF-8; the hex form is authoritative.")


def write_password_output(args: argparse.Namespace, password: bytes) -> None:
    path = getattr(args, "password_out", None)
    if not path:
        return
    if path == "-":
        if getattr(args, "json", False):
            raise UsageError("--password-out - cannot be combined with --json")
        sys.stdout.buffer.write(password)
        sys.stdout.buffer.flush()
        return
    with atomic_writer(path, overwrite=True) as handle:
        handle.write(password)


@contextmanager
def output_sink(path: str, *, overwrite: bool):
    """Write a binary output atomically, or spool stdout until success.

    Spooling to a temporary file means a late authentication or padding
    failure cannot leave partial plaintext on stdout.
    """
    if path == "-":
        with tempfile.TemporaryFile("w+b") as buffer:
            yield buffer
            buffer.flush()
            buffer.seek(0)
            shutil.copyfileobj(buffer, sys.stdout.buffer, length=64 * 1024)
            sys.stdout.buffer.flush()
        return
    with atomic_writer(path, overwrite=overwrite) as handle:
        yield handle


def _resolved_path(value: Optional[str]) -> Optional[Path]:
    if not value or value == "-":
        return None
    try:
        return Path(value).expanduser().resolve()
    except OSError:
        return Path(value).expanduser()


def validate_side_outputs(
    args: argparse.Namespace,
    *,
    inputs: tuple[Optional[str], ...] = (),
    primary: Optional[str] = None,
) -> None:
    """Prevent --json-out/--password-out from clobbering inputs or stdout.

    Side outputs may replace an existing side file, but never an input file
    (encrypted container, wordlist, key file) or the primary plaintext output.
    Multiple destinations on stdout are rejected.
    """
    if getattr(args, "json_out", None) == "-":
        raise UsageError(
            "--json-out requires a file path",
            hint="use --json to write JSON to stdout",
        )
    targets: list[str] = []
    if getattr(args, "json", False):
        targets.append("--json")
    if getattr(args, "password_out", None) == "-":
        targets.append("--password-out -")
    if primary == "-":
        targets.append("--out -")
    if len(targets) > 1:
        raise UsageError(
            "multiple outputs would write to stdout: " + ", ".join(targets),
            hint="write one of them to a file",
        )

    input_paths = []
    for value in inputs:
        resolved = _resolved_path(value)
        if resolved is not None:
            input_paths.append((value, resolved))
    primary_path = _resolved_path(primary)
    if primary_path is not None:
        for input_value, input_path in input_paths:
            if primary_path == input_path:
                raise UsageError(
                    f"primary output would overwrite input {input_value}",
                    hint="choose a different output path",
                )

    side: list[tuple[str, Path]] = []
    json_path = _resolved_path(getattr(args, "json_out", None))
    if json_path is not None:
        side.append(("--json-out", json_path))
    password_path = _resolved_path(getattr(args, "password_out", None))
    if password_path is not None:
        side.append(("--password-out", password_path))

    for label, path in side:
        for input_value, input_path in input_paths:
            if path == input_path:
                raise UsageError(
                    f"{label} would overwrite input {input_value}",
                    hint="choose a different output path",
                )
        if primary_path is not None and path == primary_path:
            raise UsageError(
                f"{label} would overwrite the primary output",
                hint="choose a different output path",
            )
    if len(side) == 2 and side[0][1] == side[1][1]:
        raise UsageError("--json-out and --password-out point to the same file")


@contextmanager
def decoded_input(args: argparse.Namespace):
    """Auto-decode a base64 AES/ZIP/OpenSSL blob into a temporary file.

    The original path is kept for display, default output naming, and
    checkpoint identity. Custom specs are excluded because they already define
    their own input encoding.
    """
    original = getattr(args, "input", None)
    if not original or original == "-":
        yield
        return
    data = read_file(original)
    if not looks_like_base64(data):
        yield
        return
    try:
        decoded = b64_decode(data, what="input")
    except InputError:
        yield
        return
    if not decoded.startswith((b"AES", b"PK\x03\x04", b"Salted__")):
        yield
        return
    with tempfile.TemporaryDirectory(prefix="aesbreaker-b64-") as raw_dir:
        path = Path(raw_dir) / "decoded"
        path.write_bytes(decoded)
        args._input_original = str(original)
        args.input = str(path)
        try:
            yield
        finally:
            args.input = original
            del args._input_original


def attach_input_origin(args: argparse.Namespace, artifact: Artifact) -> None:
    original = getattr(args, "_input_original", None)
    if original:
        setattr(artifact, "input_origin", Path(original))


def input_display(args: argparse.Namespace, artifact: Artifact) -> str:
    original = getattr(args, "_input_original", None)
    return str(original) if original else str(artifact.path)


def output_path_from_args(args: argparse.Namespace, artifact: Artifact) -> str:
    explicit = getattr(args, "out", None)
    if explicit:
        return explicit
    original = getattr(args, "_input_original", None)
    source = Path(original) if original else artifact.path
    name = source.name
    for suffix in (".b64", ".base64"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    if artifact.output_kind == "directory":
        if name.lower().endswith(".zip"):
            name = name[:-4]
        return str(source.parent / (name + ".extracted"))
    for suffix in (".aes", ".enc", ".zip"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
    return str(source.parent / (name + ".dec"))


class _HasPath(Protocol):
    path: Path


def ensure_output_is_not_input(output: str, artifact: _HasPath) -> None:
    if output == "-":
        return
    try:
        output_path = Path(output).resolve()
        input_paths = [artifact.path.resolve()]
        origin = getattr(artifact, "input_origin", None)
        if origin is not None:
            input_paths.append(Path(origin).resolve())
    except OSError:
        return
    if any(output_path == input_path for input_path in input_paths):
        raise OutputError(
            "refusing to overwrite the encrypted input with its plaintext",
            hint="choose a different --out path",
        )


def load_rules_from_args(args: argparse.Namespace) -> Optional[RuleSet]:
    presets = getattr(args, "rules_preset", None) or []
    files = getattr(args, "rules", None) or []
    inline = getattr(args, "rule", None) or []
    if not presets and not files and not inline:
        return None
    collected: list[Rule] = []
    for name in presets:
        collected.extend(load_preset(name).rules)
    for path in files:
        collected.extend(load_rule_file(path).rules)
    for value in inline:
        collected.append(parse_rule(value))
    seen = set()
    unique = []
    for rule_obj in collected:
        if rule_obj.text not in seen:
            seen.add(rule_obj.text)
            unique.append(rule_obj)
    if not unique:
        raise InputError("no usable rules were supplied")
    return RuleSet(unique)


def _custom_charsets(args: argparse.Namespace) -> dict[str, str]:
    values = {}
    for key in ("cs1", "cs2", "cs3", "cs4"):
        value = getattr(args, key, None)
        if value is not None:
            values[key[-1]] = value
    return parse_custom_definitions(values)


def build_plan_options_from_args(args: argparse.Namespace) -> PlanOptions:
    """Build a PlanOptions from crack arguments, including masks and rules."""
    custom = _custom_charsets(args)
    encoding = getattr(args, "encoding", "utf-8")
    mask = None
    charset_mask = None
    mask_append = None
    mask_prepend = None

    if getattr(args, "mask", None) is not None and getattr(args, "charset", None) is not None:
        raise UsageError("--mask and --charset are mutually exclusive")

    increment_requested = bool(
        getattr(args, "increment", False)
        or getattr(args, "increment_min", None) is not None
        or getattr(args, "increment_max", None) is not None
    )
    has_mask = getattr(args, "mask", None) is not None
    if increment_requested and not has_mask:
        raise UsageError("--increment requires --mask")
    if has_mask and (getattr(args, "min_length", 1) != 1 or getattr(args, "max_length", 8) != 8):
        raise UsageError(
            "use --increment-min/--increment-max with --mask, not --min-length/--max-length"
        )
    if (
        getattr(args, "mask_append", None) or getattr(args, "mask_prepend", None)
    ) and increment_requested:
        raise UsageError("increment mode is only supported for a standalone --mask")
    if (getattr(args, "mask_append", None) or getattr(args, "mask_prepend", None)) and (
        getattr(args, "min_length", 1) != 1 or getattr(args, "max_length", 8) != 8
    ):
        raise UsageError("--min-length/--max-length only apply to --charset")
    if getattr(args, "mask", None) is not None:
        mask = parse_mask(
            args.mask,
            custom,
            encoding=encoding,
            increment=increment_requested,
            min_length=getattr(args, "increment_min", None),
            max_length=getattr(args, "increment_max", None),
        )
    elif getattr(args, "charset", None) is not None:
        if increment_requested:
            raise UsageError("--charset uses --min-length/--max-length, not --increment")
        charset_mask = build_charset_plan(
            args.charset,
            min_length=getattr(args, "min_length", 1),
            max_length=getattr(args, "max_length", 8),
            encoding=encoding,
            custom=custom,
        )

    if getattr(args, "mask_append", None) is not None:
        mask_append = parse_mask(args.mask_append, custom, encoding=encoding)
    if getattr(args, "mask_prepend", None) is not None:
        mask_prepend = parse_mask(args.mask_prepend, custom, encoding=encoding)
    if mask_append is not None and mask_prepend is not None:
        raise UsageError("--mask-append and --mask-prepend are mutually exclusive")
    if mask is None and charset_mask is not None:
        mask = charset_mask
    if mask is not None and (mask_append is not None or mask_prepend is not None):
        raise UsageError("a mask-only attack cannot also use a hybrid mask")
    if mask is not None and (getattr(args, "wordlist", None) or getattr(args, "stdin", False)):
        raise UsageError(
            "--mask/--charset are standalone attacks",
            hint="use --mask-append or --mask-prepend together with --wordlist for a hybrid attack",
        )

    rules = load_rules_from_args(args)
    if rules is not None and mask is not None:
        raise UsageError(
            "rules cannot be applied to a mask-only attack; use --wordlist with --mask"
        )

    return PlanOptions(
        wordlist=getattr(args, "wordlist", None),
        stdin=bool(getattr(args, "stdin", False)),
        rules=rules,
        mask=mask,
        mask_append=mask_append,
        mask_prepend=mask_prepend,
        combinator=getattr(args, "combinator", None),
        separator=(getattr(args, "separator", "") or "").encode(encoding),
        encoding=encoding,
        skip_empty=not bool(getattr(args, "include_empty", False)),
        dedupe=bool(getattr(args, "dedupe", False)),
        dedupe_limit=getattr(args, "dedupe_limit", 5_000_000),
        count_lines=not bool(getattr(args, "no_count", False)),
        combinator_max=getattr(args, "combinator_max", 5_000_000),
    )


def mask_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("mask / hybrid options")
    group.add_argument("--mask", metavar="MASK", help="mask attack, e.g. '?u?l?l?l?d?d'")
    group.add_argument(
        "--charset",
        metavar="CHARS",
        help="brute-force character set (placeholders allowed), with --min-length/--max-length",
    )
    group.add_argument("--min-length", type=positive_int, default=1, metavar="N")
    group.add_argument("--max-length", type=positive_int, default=8, metavar="N")
    group.add_argument(
        "--increment",
        action="store_true",
        help="test shorter prefixes before the full mask",
    )
    group.add_argument("--increment-min", type=positive_int, metavar="N")
    group.add_argument("--increment-max", type=positive_int, metavar="N")
    group.add_argument("--mask-append", metavar="MASK", help="append this mask to each word")
    group.add_argument("--mask-prepend", metavar="MASK", help="prepend this mask to each word")
    group.add_argument("-1", dest="cs1", metavar="CHARS", help="custom charset ?1")
    group.add_argument("-2", dest="cs2", metavar="CHARS", help="custom charset ?2")
    group.add_argument("-3", dest="cs3", metavar="CHARS", help="custom charset ?3")
    group.add_argument("-4", dest="cs4", metavar="CHARS", help="custom charset ?4")
    group.add_argument(
        "--encoding",
        default="utf-8",
        help="encoding for mask literals and custom charsets (default: utf-8)",
    )


def rules_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("word mutation rules")
    group.add_argument("--rules", action="append", metavar="FILE", help="load a rule file")
    group.add_argument("--rule", action="append", metavar="RULE", help="inline rule")
    group.add_argument(
        "--rules-preset",
        action="append",
        choices=("common", "leet", "digits", "years"),
        help="use a bundled rule preset",
    )


def describe_plan(summary: PlanSummary) -> str:
    lines = [f"Attack: {summary.kind}"]
    details = summary.details
    if details.get("wordlist"):
        count = details.get("wordlist_count")
        count_text = f"{format_count(count)} words" if count is not None else "count unknown"
        lines.append(f"Wordlist: {details['wordlist']} ({count_text})")
    if details.get("combinator"):
        lines.append(
            f"Combinator: {details['combinator']} ({format_count(details.get('combinator_count') or 0)} words)"
        )
    if details.get("rules"):
        suffix = " (some rejected at runtime)" if details.get("rules_upper_bound") else ""
        lines.append(f"Rules: {format_count(details['rules'])}{suffix}")
    if details.get("mask"):
        lines.append(f"Mask: {details['mask']}")
    if summary.total is not None:
        prefix = "at most " if summary.total_is_upper else ""
        lines.append(f"Total: {prefix}{format_count(summary.total)} candidates")
    else:
        lines.append("Total: unknown (streaming source)")
    return "\n".join(lines)
