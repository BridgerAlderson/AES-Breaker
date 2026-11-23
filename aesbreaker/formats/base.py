"""Common interfaces for containers, verifiers, and decryption results."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, ClassVar

from ..errors import UnsupportedError, UsageError

POLICY_MODES = ("auto", "strict", "text", "magic", "any")

# A known-plaintext prefix shorter than this is not sufficient for a
# "confirmed" verdict: a 1-byte prefix is matched by 1/256 of random wrong
# keys, and even 4 bytes are only 2^-32 evidence.
MIN_CONFIRM_PREFIX = 8


class Outcome(IntEnum):
    """Result of testing one password candidate.

    ``WEAK`` is evidence that a key produced valid padding but nothing more;
    it is never treated as a hit.  ``PROBABLE`` is a heuristic match (text or
    file magic) and is reported as such.  ``CONFIRMED`` means a MAC, tag, or
    exact known plaintext matched.
    """

    REJECT = 0
    WEAK = 1
    PROBABLE = 2
    CONFIRMED = 3


@dataclass(frozen=True)
class ValidationPolicy:
    mode: str = "auto"
    known_prefix: bytes = b""

    def __post_init__(self) -> None:
        if self.mode not in POLICY_MODES:
            raise UsageError(
                f"unknown verification policy: {self.mode}",
                hint="choose auto, strict, text, magic, or any",
            )
        if not isinstance(self.known_prefix, bytes):
            raise UsageError("known prefix must be raw bytes")
        if self.mode == "strict" and not self.known_prefix:
            # Strict is only meaningful with an exact oracle.  Formats that
            # authenticate ignore the policy entirely.
            pass

    @property
    def has_prefix(self) -> bool:
        return bool(self.known_prefix)

    def describe(self) -> str:
        base = {
            "auto": "padding plus text/magic heuristic",
            "strict": "known prefix or magic only",
            "text": "padding plus printable-text heuristic",
            "magic": "padding plus strong file magic",
            "any": "first valid PKCS#7 padding (unconfirmed)",
        }[self.mode]
        if self.has_prefix:
            return f"exact known prefix ({len(self.known_prefix)} bytes)"
        return base


@dataclass
class FormatOptions:
    """Format-specific knobs supplied by the CLI."""

    cipher: str | None = None
    digest: str = "sha256"
    pbkdf2: bool = False
    iterations: int = 10000
    nosalt: bool = False
    nopad: bool = False
    in_encoding: str = "auto"
    entry: str | None = None
    zip_strength: int = 3
    zip_compression: str = "deflate"


@dataclass
class DecryptReport:
    format_name: str
    output: str | None
    bytes_written: int
    verification: str
    details: dict = field(default_factory=dict)


class Verifier(ABC):
    """A picklable, read-only candidate tester used by the attack engine."""

    format_name: ClassVar[str] = "unknown"

    @abstractmethod
    def describe(self) -> dict:
        """Return JSON-friendly parameters for the final report."""

    @abstractmethod
    def verify(self, password: bytes) -> Outcome:
        """Test a raw candidate password.  Must be safe to call repeatedly."""

    def verification_label(self) -> str:
        return "authenticated"


class Artifact(ABC):
    """A parsed encrypted container."""

    format_name: ClassVar[str] = "unknown"
    display_name: ClassVar[str] = "unknown format"
    output_kind: ClassVar[str] = "file"  # "file" or "directory"

    def __init__(self, path: Path, size: int) -> None:
        self.path = path
        self.size = size

    @abstractmethod
    def inspect(self) -> dict:
        """Return format details safe to display without a password."""

    @abstractmethod
    def verifier(self, policy: ValidationPolicy) -> Verifier:
        """Build a candidate tester for cracking."""

    @abstractmethod
    def decrypt(self, password: bytes, handle: BinaryIO) -> DecryptReport:
        """Decrypt into *handle* after verifying the password.

        Implementations must not leave unauthenticated plaintext behind: the
        CLI supplies an atomic writer, so raising on a bad MAC discards the
        partial file.
        """

    def extract(
        self,
        password: bytes,
        directory: str,
        *,
        overwrite: bool = False,
        max_output_bytes: int | None = None,
    ) -> DecryptReport:
        """Extract an archive container (only archive formats implement this)."""
        raise UnsupportedError(f"{self.format_name} outputs a single file, not an archive")

    def default_decrypted_name(self) -> str:
        return self.path.name
