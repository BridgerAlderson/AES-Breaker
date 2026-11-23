"""Small, dependency-free helpers shared by the CLI and format readers."""

from __future__ import annotations

import base64
import binascii
import bz2
import contextlib
import gzip
import hashlib
import json
import lzma
import math
import os
import re
import secrets
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Optional

from .errors import InputError, OutputError

_MIB = 1024 * 1024


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_count(value: int) -> str:
    return f"{value:,}"


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None or not math.isfinite(seconds) or seconds < 0:
        return "--:--:--"
    total = int(seconds)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def format_bytes(value: int) -> str:
    if value < 1024:
        return f"{value} B"
    size = float(value)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        size /= 1024.0
        if size < 1024.0 or unit == "TiB":
            return f"{size:.2f} {unit}"
    return f"{size:.2f} TiB"


def format_rate(value: float) -> str:
    if not math.isfinite(value) or value < 0:
        return "0/s"
    if value >= 1_000_000:
        return f"{value / 1_000_000:.2f} M/s"
    if value >= 1_000:
        return f"{value / 1_000:.2f} k/s"
    return f"{value:.0f}/s"


def format_percent(part: int, total: Optional[int]) -> str:
    if not total:
        return "?"
    return f"{100.0 * part / total:.2f}%"


def format_hex(data: bytes, *, upper: bool = False) -> str:
    return data.hex().upper() if upper else data.hex()


# ---------------------------------------------------------------------------
# Parsing user supplied byte strings
# ---------------------------------------------------------------------------

_HEX_SEPARATORS = re.compile(r"[\s:\-_]")


def parse_hex_data(text: str, *, what: str = "hex data") -> bytes:
    """Decode hex with optional ``0x`` prefix and common separators."""
    cleaned = _HEX_SEPARATORS.sub("", text.strip())
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2:
        raise InputError(f"{what} must contain an even number of hex digits")
    if not cleaned:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise InputError(f"{what} is not valid hex: {exc}") from None


def b64_decode(text: str | bytes, *, what: str = "base64 data") -> bytes:
    if isinstance(text, str):
        raw = text.encode("ascii", "strict")
    else:
        raw = text
    compact = re.sub(rb"\s+", b"", raw)
    if not compact:
        return b""
    if b"=" not in compact:
        compact += b"=" * ((-len(compact)) % 4)
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        if not re.fullmatch(rb"[A-Za-z0-9_-]+={0,2}", compact):
            raise InputError(f"{what} is not valid base64") from None
        translated = compact.replace(b"-", b"+").replace(b"_", b"/")
        try:
            return base64.b64decode(translated, validate=True)
        except (binascii.Error, ValueError):
            raise InputError(f"{what} is not valid base64") from None


def decode_data_arg(value: str, *, what: str = "input") -> bytes:
    """Decode ``hex:``/``base64:`` inline data or read a file path.

    A bare value is treated as a file when one exists; otherwise it is
    accepted as hex when it consists solely of hex digits and separators.
    This keeps the cryptanalysis commands pleasant to use without making
    container commands guess at their input type.
    """
    lowered = value.lower()
    if lowered.startswith("hex:"):
        return parse_hex_data(value[4:], what=what)
    if lowered.startswith("base64:"):
        return b64_decode(value[7:], what=what)
    if lowered.startswith("b64:"):
        return b64_decode(value[4:], what=what)
    path = Path(value)
    if path.is_file():
        return read_file(path)
    if path.exists():
        raise InputError(f"{what} path is not a regular file: {value}")
    if re.fullmatch(r"[0-9a-fA-F\s:\-_]+", value) and len(_HEX_SEPARATORS.sub("", value)) % 2 == 0:
        return parse_hex_data(value, what=what)
    raise InputError(
        f"{what} is neither an existing file nor an inline hex/base64 value",
        hint="use a file path, 'hex:<bytes>', or 'base64:<bytes>'",
    )


# ---------------------------------------------------------------------------
# Files and streams
# ---------------------------------------------------------------------------


def read_file(path: str | Path) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from None


def read_prefix(path: str | Path, limit: int) -> bytes:
    """Read at most *limit* bytes (0 means the whole file)."""
    try:
        with open(path, "rb") as handle:
            return handle.read(limit) if limit else handle.read()
    except OSError as exc:
        raise InputError(f"cannot read {path}: {exc.strerror or exc}") from None


def read_password_file(path: str | Path) -> bytes:
    data = read_file(path)
    if data.endswith(b"\n"):
        data = data[:-1]
    if data.endswith(b"\r"):
        data = data[:-1]
    return data


def strip_line_ending(line: bytes) -> bytes:
    """Remove exactly one line terminator; never strip spaces."""
    if line.endswith(b"\n"):
        line = line[:-1]
    if line.endswith(b"\r"):
        line = line[:-1]
    return line


def iter_wordlist_lines(stream: BinaryIO, *, skip_empty: bool = True) -> Iterator[bytes]:
    for line in stream:
        candidate = strip_line_ending(line)
        if skip_empty and not candidate:
            continue
        yield candidate


def count_wordlist_lines(stream: BinaryIO, *, skip_empty: bool = True) -> int:
    """Count candidates exactly, matching :func:`iter_wordlist_lines`."""
    count = 0
    for line in stream:
        if skip_empty:
            if strip_line_ending(line):
                count += 1
        else:
            count += 1
    return count


def _compression_type(path: Path) -> Optional[str]:
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return "gzip"
    if suffix == ".bz2":
        return "bzip2"
    if suffix in (".xz", ".lzma"):
        return "xz"
    try:
        with path.open("rb") as handle:
            magic = handle.read(6)
    except OSError:
        return None
    if magic.startswith(b"\x1f\x8b"):
        return "gzip"
    if magic.startswith(b"BZh"):
        return "bzip2"
    if magic.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    return None


@contextmanager
def open_wordlist(path: str) -> Iterator[BinaryIO]:
    """Open a plain or compressed wordlist in binary mode.

    ``-`` means stdin.  Compressed streams are detected by suffix and then by
    magic bytes, so a gzip file named ``rockyou.txt`` still works.
    """
    if path == "-":
        yield sys.stdin.buffer
        return
    source = Path(path)
    if not source.exists():
        raise InputError(f"wordlist not found: {path}")
    if source.is_dir():
        raise InputError(f"wordlist path is a directory: {path}")
    # Compression sniffing reads ahead; only do that for seekable regular
    # files.  A FIFO (for example /dev/fd/63) is consumed exactly once.
    kind = _compression_type(source) if source.is_file() else None
    handle: Any
    try:
        if kind == "gzip":
            handle = gzip.open(source, "rb")
        elif kind == "bzip2":
            handle = bz2.open(source, "rb")
        elif kind == "xz":
            handle = lzma.open(source, "rb")
        else:
            handle = source.open("rb")
    except OSError as exc:
        raise InputError(f"cannot open wordlist {path}: {exc}") from None
    try:
        yield handle
    finally:
        handle.close()


def count_wordlist(path: str, *, skip_empty: bool = True) -> Optional[int]:
    if path == "-":
        return None
    source = Path(path)
    if source.is_dir():
        raise InputError(f"wordlist path is a directory: {path}")
    if not source.is_file():
        # A FIFO or device cannot be counted without consuming it.
        if source.exists():
            return None
        raise InputError(f"wordlist not found: {path}")
    with open_wordlist(path) as stream:
        return count_wordlist_lines(stream, skip_empty=skip_empty)


def load_wordlist(path: str, *, skip_empty: bool = True) -> list[bytes]:
    with open_wordlist(path) as stream:
        return list(iter_wordlist_lines(stream, skip_empty=skip_empty))


def check_output_path(path: str | Path, *, overwrite: bool) -> None:
    target = Path(path)
    if target.exists():
        if target.is_dir():
            raise OutputError(f"output path is a directory: {target}")
        if not overwrite:
            raise OutputError(
                f"output already exists: {target}",
                hint="pass --overwrite to replace it",
            )
    parent = target.parent
    if parent.exists() and not parent.is_dir():
        raise OutputError(f"output parent is not a directory: {parent}")


@contextmanager
def atomic_writer(path: str | Path, *, overwrite: bool = False) -> Iterator[BinaryIO]:
    """Write a file atomically, removing a partial file on any failure."""
    target = Path(path)
    check_output_path(target, overwrite=overwrite)
    parent = target.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OutputError(f"cannot create output directory {parent}: {exc}") from None
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".part", dir=str(parent))
    handle = os.fdopen(fd, "wb")
    try:
        yield handle
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        if target.exists() and not overwrite:
            raise OutputError(
                f"output appeared while writing: {target}",
                hint="pass --overwrite to replace it",
            )
        os.replace(temp_name, target)
    except BaseException:
        with contextlib.suppress(Exception):
            handle.close()
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


@contextmanager
def output_stream(path: str) -> Iterator[BinaryIO]:
    """Open ``-`` as stdout, otherwise use an atomic file writer."""
    if path == "-":
        stream = sys.stdout.buffer
        try:
            yield stream
            stream.flush()
        finally:
            pass
        return
    with atomic_writer(path, overwrite=True) as handle:
        yield handle


# ---------------------------------------------------------------------------
# Safe archive extraction
# ---------------------------------------------------------------------------

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def safe_zip_target(base: Path, name: str) -> Path:
    """Resolve a ZIP member name below *base*, rejecting traversal tricks.

    Backslashes are treated as separators because archives produced on
    Windows frequently use them.  Existing symlinks in the destination path
    are refused rather than followed.
    """
    if "\x00" in name:
        raise OutputError("archive member name contains a NUL byte")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or _WINDOWS_DRIVE.match(normalized):
        raise OutputError(f"archive member uses an absolute path: {name!r}")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if not parts:
        raise OutputError(f"archive member has an empty name: {name!r}")
    if any(part == ".." for part in parts):
        raise OutputError(f"archive member escapes the output directory: {name!r}")
    if any(part.split(".")[0].upper() in _WINDOWS_RESERVED for part in parts):
        raise OutputError(f"archive member uses a reserved name: {name!r}")

    current = base
    for part in parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise OutputError(f"refusing to follow symlink during extraction: {current}")
        if current.exists() and not current.is_dir():
            raise OutputError(f"archive path collides with a file: {current}")
    target = base.joinpath(*parts)
    if target.is_symlink():
        raise OutputError(f"refusing to overwrite a symlink: {target}")
    return target


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------


def hexdump(data: bytes, *, width: int = 16, limit: Optional[int] = 512) -> str:
    if limit is not None and len(data) > limit:
        shown = data[:limit]
    else:
        shown = data
    lines = []
    for offset in range(0, len(shown), width):
        chunk = shown[offset : offset + width]
        hex_part = " ".join(f"{byte:02x}" for byte in chunk)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
    if limit is not None and len(data) > limit:
        lines.append(f"... {len(data) - limit} more bytes")
    return "\n".join(lines)


def escape_control(text: str) -> str:
    """Escape control characters in untrusted metadata before terminal output."""
    return "".join(ch if ch.isprintable() or ch == "\t" else f"\\x{ord(ch):02x}" for ch in text)


def preview_bytes(data: bytes, *, limit: int = 64) -> str:
    sample = data[:limit]
    try:
        text = sample.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            compact = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
            if len(compact) > 120:
                compact = compact[:117] + "..."
            return repr(compact)
    except UnicodeDecodeError:
        pass
    return sample.hex() + ("..." if len(data) > limit else "")


def safe_password_text(password: bytes) -> tuple[Optional[str], str]:
    """Return (utf8-or-None, escaped display form) for a recovered password."""
    try:
        text = password.decode("utf-8")
    except UnicodeDecodeError:
        return None, password.hex()
    return text, text.encode("unicode_escape").decode("ascii")


def write_json(path: Optional[str], payload: dict) -> None:
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if path is None or path == "-":
        sys.stdout.write(rendered)
        sys.stdout.flush()
        return
    with atomic_writer(path, overwrite=True) as handle:
        handle.write(rendered.encode("utf-8"))


def random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def is_tty(stream: object = sys.stderr) -> bool:
    return bool(getattr(stream, "isatty", lambda: False)())


def clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def sha256_file(path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise InputError(f"cannot hash {path}: {exc}") from None
    return digest.hexdigest()


def looks_like_hex_text(data: bytes) -> bool:
    sample = data.strip()
    if not sample or len(sample) % 2:
        return False
    try:
        sample.decode("ascii")
    except UnicodeDecodeError:
        return False
    return bool(re.fullmatch(rb"[0-9a-fA-F\s:\-_]+", sample))


def decode_encoded_bytes(data: bytes, encoding: str, *, what: str = "input") -> bytes:
    """Decode raw/hex/base64 bytes, with a conservative ``auto`` mode."""
    if encoding == "raw":
        return data
    if encoding == "hex":
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError:
            raise InputError(f"{what} is not ASCII hex") from None
        return parse_hex_data(text, what=what)
    if encoding == "base64":
        return b64_decode(data, what=what)
    if encoding != "auto":
        raise InputError(
            f"unknown input encoding: {encoding}",
            hint="use auto, raw, hex, or base64",
        )
    if looks_like_hex_text(data):
        try:
            return parse_hex_data(data.decode("ascii"), what=what)
        except InputError:
            pass
    compact = re.sub(rb"\s+", b"", data)
    if (
        len(compact) >= 4
        and len(compact) % 4 == 0
        and re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", compact)
    ):
        try:
            decoded = b64_decode(data, what=what)
        except InputError:
            pass
        else:
            if decoded:
                return decoded
    return data


def read_encoded_data(path: str | Path, encoding: str, *, what: str = "input") -> bytes:
    """Read a file and decode it as raw, hex, base64, or auto."""
    return decode_encoded_bytes(read_file(path), encoding, what=what)


_SIZE_RE = re.compile(r"^\s*(\d+)\s*([kmgt]?i?b?)?\s*$", re.IGNORECASE)


def parse_size(text: str) -> int:
    """Parse 512, 64K, 8M, 2G, 1T (binary suffixes, 0 = unlimited)."""
    match = _SIZE_RE.match(text)
    if not match:
        raise ValueError(f"invalid size: {text!r}")
    value = int(match.group(1))
    suffix = (match.group(2) or "").lower()
    multipliers = {
        "": 1,
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gib": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
        "tib": 1024**4,
    }
    if suffix not in multipliers:
        raise ValueError(f"invalid size suffix: {text!r}")
    return value * multipliers[suffix]
