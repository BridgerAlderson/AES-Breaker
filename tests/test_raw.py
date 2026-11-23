from __future__ import annotations

import io

import pytest

from aesbreaker.crypto import (
    aes_cbc_encrypt,
    aes_ctr_crypt,
    aes_gcm_encrypt,
    parse_cipher,
    pkcs7_pad,
)
from aesbreaker.errors import DecryptionError, UsageError
from aesbreaker.formats.raw import RawSpec, decrypt_stream


def _run(source: bytes, spec: RawSpec) -> bytes:
    output = io.BytesIO()
    decrypt_stream(io.BytesIO(source), output, spec)
    return output.getvalue()


def test_cbc_pkcs7_and_none():
    key = bytes(range(16))
    iv = bytes(range(16))
    plaintext = b"hello raw cbc" * 5
    ciphertext = aes_cbc_encrypt(key, iv, pkcs7_pad(plaintext))
    spec = RawSpec(cipher=parse_cipher("aes-128-cbc"), key=key, iv=iv)
    assert _run(ciphertext, spec) == plaintext

    raw = aes_cbc_encrypt(key, iv, b"A" * 32)
    spec_none = RawSpec(
        cipher=parse_cipher("aes-128-cbc"),
        key=key,
        iv=iv,
        padding="none",
    )
    assert _run(raw, spec_none) == b"A" * 32


def test_ctr_and_streaming():
    key = bytes(range(32))
    iv = bytes(range(16))
    plaintext = bytes(range(256)) * 1000
    ciphertext = aes_ctr_crypt(key, iv, plaintext)
    spec = RawSpec(cipher=parse_cipher("aes-256-ctr"), key=key, iv=iv, padding="none")
    assert _run(ciphertext, spec) == plaintext


def test_ctr_little_endian():
    key = bytes(range(16))
    initial = b"\x01" + b"\x00" * 15
    plaintext = b"\x00" * 16
    ciphertext = aes_ctr_crypt(key, initial, plaintext, little_endian=True)
    spec = RawSpec(
        cipher=parse_cipher("aes-128-ctr"),
        key=key,
        iv=initial,
        ctr_little_endian=True,
        padding="none",
    )
    assert _run(ciphertext, spec) == plaintext


def test_gcm_decrypt_and_bad_tag():
    key = bytes(range(16))
    nonce = bytes(range(12))
    plaintext = b"authenticated payload" * 3
    ciphertext, tag = aes_gcm_encrypt(key, nonce, plaintext, aad=b"header")
    spec = RawSpec(
        cipher=parse_cipher("aes-128-gcm"),
        key=key,
        nonce=nonce,
        tag=tag,
        aad=b"header",
        padding="none",
    )
    assert _run(ciphertext, spec) == plaintext
    bad = RawSpec(
        cipher=parse_cipher("aes-128-gcm"),
        key=key,
        nonce=nonce,
        tag=b"\x00" * 16,
        aad=b"header",
        padding="none",
    )
    output = io.BytesIO()
    with pytest.raises(DecryptionError):
        decrypt_stream(io.BytesIO(ciphertext), output, bad)
    assert output.getvalue() == b""


def test_invalid_padding():
    key = bytes(range(16))
    iv = bytes(range(16))
    ciphertext = aes_cbc_encrypt(key, iv, b"\x00" * 16)
    spec = RawSpec(cipher=parse_cipher("aes-128-cbc"), key=key, iv=iv)
    with pytest.raises(DecryptionError):
        _run(ciphertext, spec)


def test_unaligned_ciphertext():
    key = bytes(range(16))
    iv = bytes(range(16))
    spec = RawSpec(cipher=parse_cipher("aes-128-cbc"), key=key, iv=iv, padding="none")
    with pytest.raises(DecryptionError):
        _run(b"A" * 15, spec)


def test_spec_validation():
    key = bytes(range(16))
    with pytest.raises(UsageError):
        RawSpec(cipher=parse_cipher("aes-128-cbc"), key=b"short", iv=bytes(16)).validate()
    with pytest.raises(UsageError):
        RawSpec(cipher=parse_cipher("aes-128-cbc"), key=key).validate()
    with pytest.raises(UsageError):
        RawSpec(cipher=parse_cipher("aes-128-ctr"), key=key, iv=bytes(16)).validate()
    with pytest.raises(UsageError):
        RawSpec(cipher=parse_cipher("aes-128-gcm"), key=key, nonce=bytes(12)).validate()
    with pytest.raises(UsageError):
        RawSpec(
            cipher=parse_cipher("aes-128-gcm"),
            key=key,
            nonce=bytes(12),
            tag=bytes(16),
            padding="pkcs7",
        ).validate()
    with pytest.raises(UsageError):
        RawSpec(cipher=parse_cipher("aes-128-ecb"), key=key, iv=bytes(16)).validate()
    with pytest.raises(UsageError):
        RawSpec(
            cipher=parse_cipher("aes-128-cbc"),
            key=key,
            iv=bytes(16),
            tag=b"t" * 16,
        ).validate()
    with pytest.raises(UsageError):
        RawSpec(
            cipher=parse_cipher("aes-128-cbc"),
            key=key,
            iv=bytes(16),
            ctr_little_endian=True,
        ).validate()


def test_empty_ciphertext_with_pkcs7_fails():
    spec = RawSpec(
        cipher=parse_cipher("aes-128-cbc"),
        key=bytes(16),
        iv=bytes(16),
    )
    with pytest.raises(DecryptionError):
        _run(b"", spec)


def test_cfb_ofb():
    key = bytes(range(16))
    iv = bytes(range(16))
    plaintext = b"stream text" * 7
    for mode in ("cfb", "ofb"):
        from aesbreaker.crypto import aes_cfb_cipher, aes_ofb_cipher

        cipher = aes_cfb_cipher(key, iv) if mode == "cfb" else aes_ofb_cipher(key, iv)
        ciphertext = cipher.encrypt(plaintext)
        spec = RawSpec(
            cipher=parse_cipher(f"aes-128-{mode}"),
            key=key,
            iv=iv,
            padding="none",
        )
        assert _run(ciphertext, spec) == plaintext
