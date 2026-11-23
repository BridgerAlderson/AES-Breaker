from __future__ import annotations

import base64
from pathlib import Path

import pytest

from aesbreaker.errors import FormatError, UsageError
from aesbreaker.formats import detect_and_open, normalize_format
from aesbreaker.formats.base import FormatOptions, ValidationPolicy

from .helpers import make_aescrypt, make_openssl, make_zip


def test_normalize_format_aliases():
    assert normalize_format("AES") == "aescrypt"
    assert normalize_format("pyaescrypt") == "aescrypt"
    assert normalize_format("openssl") == "openssl-enc"
    assert normalize_format("zip") == "zip-aes"
    assert normalize_format("auto") == "auto"
    assert normalize_format("unknown") == "unknown"


def test_auto_detection(tmp_path: Path):
    aescrypt = make_aescrypt(tmp_path / "a.aes")
    assert detect_and_open(aescrypt).format_name == "aescrypt"

    archive = make_zip(tmp_path / "a.zip")
    assert detect_and_open(archive).format_name == "zip-aes"

    openssl = make_openssl(tmp_path / "a.enc")
    artifact = detect_and_open(
        openssl,
        options=FormatOptions(cipher="aes-256-cbc", digest="sha256"),
    )
    assert artifact.format_name == "openssl"


def test_base64_openssl_detection(tmp_path: Path):
    path = make_openssl(tmp_path / "a.enc")
    encoded = tmp_path / "a.b64"
    encoded.write_text(base64.encodebytes(path.read_bytes()).decode("ascii"))
    artifact = detect_and_open(
        encoded,
        options=FormatOptions(cipher="aes-256-cbc", digest="sha256"),
    )
    assert artifact.format_name == "openssl"


def test_self_extracting_zip_detection(tmp_path: Path):
    path = make_zip(tmp_path / "inner.zip")
    sfx = tmp_path / "sfx.bin"
    sfx.write_bytes(b"stub" * 60 + path.read_bytes())
    artifact = detect_and_open(sfx)
    assert artifact.format_name == "zip-aes"


def test_unknown_format(tmp_path: Path):
    path = tmp_path / "random.bin"
    path.write_bytes(b"\x00\x01\x02" * 100)
    with pytest.raises(FormatError):
        detect_and_open(path)


def test_explicit_format_mismatch(tmp_path: Path):
    path = make_aescrypt(tmp_path / "a.aes")
    with pytest.raises(FormatError):
        detect_and_open(path, "zip-aes")


def test_openssl_requires_explicit_cipher_for_cracking(tmp_path: Path):
    path = make_openssl(tmp_path / "a.enc")
    artifact = detect_and_open(path)
    assert artifact.format_name == "openssl"
    with pytest.raises(UsageError):
        artifact.verifier(ValidationPolicy())


def test_missing_input(tmp_path: Path):
    with pytest.raises(FormatError):
        detect_and_open(tmp_path / "missing")


def test_unknown_explicit_format(tmp_path: Path):
    path = make_aescrypt(tmp_path / "a.aes")
    with pytest.raises(FormatError):
        detect_and_open(path, "not-a-format")
