"""Container detection and construction."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..errors import FormatError
from ..signatures import looks_like_base64
from ..util import b64_decode
from .aescrypt import AesCryptArtifact
from .base import Artifact, FormatOptions, ValidationPolicy
from .openssl_enc import (
    OpenSSLArtifact,
    looks_like_openssl,
)
from .zip_aes import ZipAesArtifact, looks_like_zip

FORMATS = {
    "aescrypt": "AES Crypt v1/v2/v3",
    "openssl-enc": "OpenSSL enc (Salted__)",
    "zip-aes": "WinZip AES ZIP (AE-1/AE-2)",
}

FORMAT_ALIASES = {
    "aes": "aescrypt",
    "aes-crypt": "aescrypt",
    "pyaescrypt": "aescrypt",
    "openssl": "openssl-enc",
    "openssl-enc": "openssl-enc",
    "zip": "zip-aes",
    "zip-aes": "zip-aes",
    "wz-aes": "zip-aes",
    "custom": "custom",
    "spec": "custom",
    "raw-spec": "custom",
}


def normalize_format(name: str) -> str:
    normalized = name.strip().lower()
    if normalized == "auto":
        return "auto"
    return FORMAT_ALIASES.get(normalized, normalized)


def _peek_base64_openssl(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            head = handle.read(8192)
    except OSError:
        return False
    if not looks_like_base64(head):
        return False
    try:
        decoded = b64_decode(head, what="base64 input")
    except Exception:
        return False
    return decoded.startswith(b"Salted__")


def detect_and_open(
    path: str | Path,
    format_hint: str = "auto",
    options: Optional[FormatOptions] = None,
    policy: Optional[ValidationPolicy] = None,
) -> Artifact:
    path = Path(path)
    if not path.exists():
        raise FormatError(f"input file not found: {path}")
    if not path.is_file():
        raise FormatError(f"input is not a regular file: {path}")
    options = options or FormatOptions()
    normalized = normalize_format(format_hint)
    if normalized in FORMATS:
        return _open_known(path, normalized, options, policy)
    if normalized != "auto":
        raise FormatError(
            f"unknown format: {format_hint}",
            hint="choose auto, aescrypt, openssl-enc, or zip-aes",
        )

    try:
        with path.open("rb") as handle:
            head = handle.read(16)
    except OSError as exc:
        raise FormatError(f"cannot read {path}: {exc}") from None

    if looks_like_zip(path):
        return ZipAesArtifact(path, options)
    if head[:3] == b"AES":
        # Constructing the artifact produces a precise version/corruption
        # error instead of a generic "unknown format".
        return AesCryptArtifact(path)
    if looks_like_openssl(head):
        return OpenSSLArtifact(path, options, policy=policy)
    if _peek_base64_openssl(path):
        return OpenSSLArtifact(path, options, policy=policy)

    raise FormatError(
        f"unrecognized container format: {path}",
        hint=(
            "supported containers are AES Crypt v1/v2/v3, OpenSSL enc "
            "(Salted__), and WinZip AES ZIP; use 'aesbreaker inspect' or "
            "'aesbreaker analyze' for raw data"
        ),
    )


def _open_known(
    path: Path,
    format_name: str,
    options: FormatOptions,
    policy: Optional[ValidationPolicy],
) -> Artifact:
    if format_name == "aescrypt":
        return AesCryptArtifact(path)
    if format_name == "openssl-enc":
        # The cipher may be omitted for inspection; cracking and decryption
        # call require_cipher() and produce an actionable error.
        return OpenSSLArtifact(path, options, policy=policy)
    if format_name == "zip-aes":
        return ZipAesArtifact(path, options)
    raise FormatError(f"unknown format: {format_name}")
