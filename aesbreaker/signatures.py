"""File-signature and plaintext-plausibility checks.

These checks are used for reporting and for the *unauthenticated* OpenSSL
policy.  They are never a substitute for a MAC or tag, so the calling code
labels heuristic matches as probable rather than confirmed.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Optional

TEXT_MIN_LENGTH = 16
TEXT_MIN_RATIO = 0.98


@dataclass(frozen=True)
class Magic:
    name: str
    offset: int
    signature: bytes
    description: str
    strength: str = "strong"

    @property
    def label(self) -> str:
        return self.name


# Signatures are intentionally conservative.  MZ (PE) is only two bytes and
# is therefore reported by analysis but not used to auto-accept a plaintext.
MAGIC_SIGNATURES: tuple[Magic, ...] = (
    Magic("PNG image", 0, b"\x89PNG\r\n\x1a\n", "PNG image"),
    Magic("JPEG image", 0, b"\xff\xd8\xff", "JPEG image"),
    Magic("GIF87a image", 0, b"GIF87a", "GIF image"),
    Magic("GIF89a image", 0, b"GIF89a", "GIF image"),
    Magic("PDF document", 0, b"%PDF-", "PDF document"),
    Magic("AES Crypt v1 container", 0, b"AES\x01", "AES Crypt v1 encrypted container"),
    Magic("AES Crypt v2 container", 0, b"AES\x02", "AES Crypt v2 encrypted container"),
    Magic("AES Crypt v3 container", 0, b"AES\x03", "AES Crypt v3 encrypted container"),
    Magic("OpenSSL enc container", 0, b"Salted__", "OpenSSL salted container"),
    Magic("ZIP archive", 0, b"PK\x03\x04", "ZIP local file header"),
    Magic("ZIP archive (empty)", 0, b"PK\x05\x06", "ZIP end of central directory"),
    Magic("ZIP archive (spanned)", 0, b"PK\x07\x08", "ZIP data descriptor"),
    Magic("gzip stream", 0, b"\x1f\x8b", "gzip compressed data"),
    Magic("bzip2 stream", 0, b"BZh", "bzip2 compressed data"),
    Magic("xz stream", 0, b"\xfd7zXZ\x00", "xz compressed data"),
    Magic("7-Zip archive", 0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    Magic("RAR archive", 0, b"Rar!\x1a\x07", "RAR archive"),
    Magic("ELF binary", 0, b"\x7fELF", "ELF executable"),
    Magic("SQLite database", 0, b"SQLite format 3\x00", "SQLite 3 database"),
    Magic("OLE2 document", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 compound document"),
    Magic("RIFF/WAVE audio", 0, b"RIFF", "RIFF container"),
    Magic("PEM private key", 0, b"-----BEGIN ", "PEM encoded data"),
    Magic("UTF-8 BOM", 0, b"\xef\xbb\xbf", "UTF-8 text with BOM"),
    Magic("UTF-16 LE BOM", 0, b"\xff\xfe", "UTF-16LE text with BOM"),
    Magic("UTF-16 BE BOM", 0, b"\xfe\xff", "UTF-16BE text with BOM"),
    Magic("PE executable", 0, b"MZ", "DOS/PE executable", strength="medium"),
)

_BASE64_RE = re.compile(rb"^[A-Za-z0-9+/=\s]+$")


@dataclass(frozen=True)
class Plausibility:
    kind: str  # "magic", "text", or "none"
    score: float
    detail: str
    magic: Optional[str] = None

    @property
    def is_magic(self) -> bool:
        return self.kind == "magic"

    @property
    def is_text(self) -> bool:
        return self.kind == "text"

    @property
    def is_none(self) -> bool:
        return self.kind == "none"


def detect_magic(data: bytes, *, include_medium: bool = True) -> Optional[Magic]:
    for magic in MAGIC_SIGNATURES:
        if magic.strength == "medium" and not include_medium:
            continue
        if len(data) >= magic.offset + len(magic.signature):
            if data[magic.offset : magic.offset + len(magic.signature)] == magic.signature:
                if magic.name == "RIFF/WAVE audio":
                    # RIFF alone is four bytes; require a known subtype.
                    subtype = data[8:12]
                    if subtype not in (b"WAVE", b"AVI ", b"WEBP"):
                        continue
                    return Magic(
                        "RIFF media",
                        0,
                        data[:12],
                        f"RIFF container ({subtype.decode('ascii', 'replace')})",
                    )
                return magic
    # TAR has a magic at a fixed offset rather than the start.
    if len(data) >= 262 and data[257:262] == b"ustar":
        return Magic("TAR archive", 257, b"ustar", "POSIX tar archive")
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return Magic("ISO media", 4, b"ftyp", "ISO base media (MP4/MOV)")
    return None


def looks_like_base64(data: bytes) -> bool:
    sample = data[:4096]
    if not sample or not _BASE64_RE.match(sample):
        return False
    non_whitespace = re.sub(rb"\s+", b"", sample)
    return len(non_whitespace) >= 16


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def byte_histogram(data: bytes, limit: int = 16) -> list[tuple[int, int]]:
    return Counter(data).most_common(limit)


def assess_plaintext(data: bytes) -> Plausibility:
    """Classify decrypted bytes as strong magic, text, or unknown.

    Text requires at least 16 bytes and a 98% printable ratio.  Random bytes
    have a vanishingly small chance of passing both this and a valid padding
    check, but the result is still labelled heuristic by callers.
    """
    if not data:
        return Plausibility("none", 0.0, "empty output")
    magic = detect_magic(data, include_medium=False)
    if magic is not None:
        return Plausibility("magic", 1.0, f"{magic.description} magic", magic.label)

    sample = data[:4096]
    if b"\x00" in sample:
        return Plausibility("none", 0.0, "contains NUL bytes")
    if len(data) < TEXT_MIN_LENGTH:
        return Plausibility("none", 0.0, f"shorter than {TEXT_MIN_LENGTH} bytes; no text heuristic")

    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        text = None

    if text is not None:
        allowed = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        ratio = allowed / len(text)
        if ratio >= TEXT_MIN_RATIO:
            return Plausibility(
                "text",
                ratio,
                f"valid UTF-8, {ratio * 100:.1f}% printable",
            )

    printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
    ratio = printable / len(sample)
    if ratio >= 0.95:
        return Plausibility("text", ratio * 0.9, f"printable ASCII, {ratio * 100:.1f}% printable")
    return Plausibility("none", 0.0, "high-entropy or binary data")


def describe_head(data: bytes, limit: int = 32) -> str:
    head = data[:limit]
    try:
        text = head.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in text):
            return repr(text)
    except UnicodeDecodeError:
        pass
    return head.hex()
