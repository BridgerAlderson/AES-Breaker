from __future__ import annotations

import os

from aesbreaker.signatures import (
    MAGIC_SIGNATURES,
    assess_plaintext,
    detect_magic,
    looks_like_base64,
    shannon_entropy,
)


def test_magic_signatures():
    assert detect_magic(b"\x89PNG\r\n\x1a\nrest").name == "PNG image"
    assert detect_magic(b"PK\x03\x04rest").name == "ZIP archive"
    assert detect_magic(b"%PDF-1.7").name == "PDF document"
    assert detect_magic(b"\x7fELF" + b"\x00" * 20).name == "ELF binary"
    assert detect_magic(b"MZ" + b"\x00" * 20).name == "PE executable"
    assert detect_magic(b"RIFF\x00\x00\x00\x00WAVEfmt ") is not None
    assert detect_magic(b"\x00" * 257 + b"ustar") is not None
    assert detect_magic(b"\x00\x00\x00\x00ftypisom") is not None


def test_assess_magic_and_text():
    magic = assess_plaintext(b"\x89PNG\r\n\x1a\n" + b"x" * 100)
    assert magic.kind == "magic"
    assert magic.magic == "PNG image"

    text = assess_plaintext(b"The quick brown fox jumps over the lazy dog.")
    assert text.kind == "text"
    assert text.score > 0.9

    short = assess_plaintext(b"hello")
    assert short.kind == "none"

    binary = assess_plaintext(bytes(range(64)))
    assert binary.kind == "none"

    with_nul = assess_plaintext(b"text\x00with\x00nul" * 4)
    assert with_nul.kind == "none"


def test_utf8_text_with_non_ascii():
    text = assess_plaintext("Türkçe bir metin, yeterince uzun ve okunabilir.".encode("utf-8"))
    assert text.kind == "text"


def test_pe_magic_is_not_used_for_automatic_text_acceptance():
    # MZ is only two bytes and must not turn arbitrary binary into a match.
    result = assess_plaintext(b"MZ" + bytes(range(1, 64)))
    assert result.kind == "none"


def test_shannon_entropy():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"A" * 100) == 0.0
    assert 0.99 < shannon_entropy(bytes(range(256))) < 8.01
    assert shannon_entropy(os.urandom(4096)) > 7.0


def test_looks_like_base64():
    assert looks_like_base64(b"U2FsdGVkX18" + b"A" * 20)
    assert not looks_like_base64(b"not base64 !!!")
    assert not looks_like_base64(b"short")


def test_signature_table_is_unique():
    names = [magic.name for magic in MAGIC_SIGNATURES]
    assert len(names) == len(set(names))
