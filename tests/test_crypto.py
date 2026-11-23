from __future__ import annotations

import pytest

from aesbreaker.crypto import (
    AES_BLOCK_SIZE,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_cfb_crypt,
    aes_ctr_crypt,
    aes_ecb_decrypt_block,
    aes_ecb_encrypt_block,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    aes_ofb_crypt,
    parse_cipher,
    pkcs7_pad,
    pkcs7_unpad,
    pkcs7_valid_last_block,
)
from aesbreaker.errors import DecryptionError, UsageError

ECB_VECTORS = [
    (
        "000102030405060708090a0b0c0d0e0f",
        "69c4e0d86a7b0430d8cdb78070b4c55a",
    ),
    (
        "000102030405060708090a0b0c0d0e0f1011121314151617",
        "dda97ca4864cdfe06eaf70a0ec0d7191",
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8ea2b7ca516745bfeafc49904b496089",
    ),
]


@pytest.mark.parametrize("key_hex,expected", ECB_VECTORS)
def test_aes_ecb_nist(key_hex, expected):
    key = bytes.fromhex(key_hex)
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    ciphertext = aes_ecb_encrypt_block(key, plaintext)
    assert ciphertext.hex() == expected
    assert aes_ecb_decrypt_block(key, ciphertext) == plaintext


def test_aes_cbc_nist():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ciphertext = aes_cbc_encrypt(key, iv, plaintext)
    assert ciphertext.hex() == "7649abac8119b246cee98e9b12e9197d"
    assert aes_cbc_decrypt(key, iv, ciphertext) == plaintext


def test_aes_ctr_nist():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    counter = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    assert aes_ctr_crypt(key, counter, plaintext).hex() == "874d6191b620e3261bef6864990db6ce"


def test_aes_ctr_little_endian_counter():
    key = bytes(range(16))
    initial = b"\x01" + b"\x00" * 15
    keystream = aes_ctr_crypt(key, initial, b"\x00" * 16, little_endian=True)
    assert keystream == aes_ecb_encrypt_block(key, initial)


def test_aes_cfb_ofb_roundtrip():
    from Crypto.Cipher import AES

    key = bytes(range(32))
    iv = bytes(range(16))
    plaintext = b"A" * 100
    cfb_ciphertext = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).encrypt(plaintext)
    assert aes_cfb_crypt(key, iv, cfb_ciphertext) == plaintext
    assert aes_ofb_crypt(key, iv, aes_ofb_crypt(key, iv, plaintext)) == plaintext


def test_gcm_known_answers():
    ciphertext, tag = aes_gcm_encrypt(bytes(16), bytes(12), b"")
    assert ciphertext == b""
    assert tag.hex() == "58e2fccefa7e3061367f1d57a4e7455a"

    ciphertext, tag = aes_gcm_encrypt(bytes(16), bytes(12), bytes(16))
    assert ciphertext.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"
    assert aes_gcm_decrypt(bytes(16), bytes(12), ciphertext, tag) == bytes(16)


def test_gcm_aad_and_tag_rejection():
    key = bytes(range(16))
    nonce = bytes(range(12))
    ciphertext, tag = aes_gcm_encrypt(key, nonce, b"payload", aad=b"header")
    assert aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b"header") == b"payload"
    with pytest.raises(DecryptionError):
        aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=b"wrong")
    with pytest.raises(DecryptionError):
        aes_gcm_decrypt(key, nonce, ciphertext, b"\x00" * 16, aad=b"header")


def test_pkcs7_roundtrip_and_validation():
    for size in (0, 1, 15, 16, 17, 1000):
        data = b"x" * size
        padded = pkcs7_pad(data)
        assert len(padded) % AES_BLOCK_SIZE == 0
        assert len(padded) > len(data)
        assert pkcs7_unpad(padded) == data
        assert pkcs7_valid_last_block(padded[-16:])

    for invalid in (
        b"\x00" * 16,
        b"A" * 15 + b"\x11",
        b"A" * 14 + b"\x03\x02",
    ):
        assert not pkcs7_valid_last_block(invalid)
        with pytest.raises(DecryptionError):
            pkcs7_unpad(invalid)


def test_invalid_key_and_iv_lengths():
    with pytest.raises(UsageError):
        aes_ecb_encrypt_block(b"x" * 20, b"\x00" * 16)
    with pytest.raises(UsageError):
        aes_cbc_encrypt(b"x" * 16, b"short", b"\x00" * 16)
    with pytest.raises((UsageError, ValueError)):
        aes_cbc_encrypt(b"x" * 16, b"\x00" * 16, b"not a block")


def test_parse_cipher():
    spec = parse_cipher("AES-256-CBC")
    assert spec.key_len == 32
    assert spec.mode == "cbc"
    assert spec.iv_len == 16
    assert parse_cipher("aes_128_ctr").key_len == 16
    with pytest.raises(UsageError):
        parse_cipher("aes-512-cbc")
    with pytest.raises(UsageError):
        parse_cipher("chacha20-poly1305")
