from __future__ import annotations

import pytest

from aesbreaker.errors import UsageError
from aesbreaker.kdf import (
    aescrypt_password_bytes,
    aescrypt_stretch,
    evp_bytes_to_key,
    hkdf,
    normalize_digest,
    pbkdf2,
)


def test_evp_bytes_to_key_known_vector():
    key, iv = evp_bytes_to_key(b"password", bytes.fromhex("3132333435363738"), 32, 16, "md5")
    assert key.hex() == ("bbb0ddff1b944b3cc68eaaeb7ac20099e5155bae6ed28f668b60cbc4157de1bd")
    assert iv.hex() == "fa1dd9ab5d62d787256eb8aec82de442"


def test_evp_bytes_to_key_without_salt():
    key, iv = evp_bytes_to_key(b"secret", b"", 16, 16, "sha256")
    assert len(key) == 16
    assert len(iv) == 16
    key2, iv2 = evp_bytes_to_key(b"secret", b"", 16, 16, "sha256")
    assert (key, iv) == (key2, iv2)


def test_pbkdf2_rfc6070():
    assert (
        pbkdf2(b"password", b"salt", 1, 20, "sha1").hex()
        == "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    )
    assert (
        pbkdf2(b"password", b"salt", 4096, 20, "sha1").hex()
        == "4b007901b765489abead49d926f721d065a429c1"
    )


def test_hkdf_rfc5869_case_1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = hkdf(ikm, salt, info, 42, "sha256")
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_aescrypt_stretch_known_vector():
    key = aescrypt_stretch(
        "hunter2".encode("utf-16-le"),
        bytes.fromhex("86f1de059e0c34a94c70068a73bd3b47"),
    )
    assert key.hex() == ("f905adb1f9461db5c156a6ab98905936db8ba86e0de549f96fcf11739548495e")


def test_aescrypt_password_conversion():
    assert aescrypt_password_bytes(b"hunter2") == "hunter2".encode("utf-16-le")
    assert aescrypt_password_bytes(b"\xff\xfe") is None
    assert aescrypt_password_bytes(b"x" * 1024) is not None
    assert aescrypt_password_bytes(b"x" * 1025) is None


def test_digest_validation():
    assert normalize_digest("SHA-256") == "sha256"
    with pytest.raises(UsageError):
        normalize_digest("blake2b")
    with pytest.raises(UsageError):
        pbkdf2(b"p", b"s", 0, 16)
    with pytest.raises(UsageError):
        pbkdf2(b"p", b"s", 1, 0)
    with pytest.raises(UsageError):
        hkdf(b"p", b"s", b"i", 0 - 1)
