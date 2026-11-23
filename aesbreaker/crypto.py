"""Thin, explicit wrappers around the AES primitives.

Correctness rules enforced here:

* key lengths are exactly 16, 24, or 32 bytes -- never silently padded or
  truncated;
* PKCS#7 removal validates every padding byte and raises on failure;
* CTR uses a full 128-bit counter.  OpenSSL starts it at the IV interpreted
  big-endian; WinZip AES starts it at 1 interpreted little-endian;
* GCM tags are always verified before plaintext is returned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError as exc:  # pragma: no cover - exercised only without the dep
    raise RuntimeError(
        "pycryptodome is required for AES operations: pip install pycryptodome"
    ) from exc

from .errors import DecryptionError, UsageError

AES_BLOCK_SIZE = 16
_VALID_KEY_LENGTHS = (16, 24, 32)
_CIPHER_RE = re.compile(r"^aes-(128|192|256)-(cbc|ecb|cfb1|cfb8|cfb|ofb|ctr|gcm)$")
_MODES = ("cbc", "ecb", "cfb1", "cfb8", "cfb", "ofb", "ctr", "gcm")


@dataclass(frozen=True)
class CipherSpec:
    name: str
    key_len: int
    mode: str

    @property
    def iv_len(self) -> int:
        if self.mode == "ecb":
            return 0
        if self.mode == "gcm":
            return 12
        return AES_BLOCK_SIZE

    @property
    def needs_padding(self) -> bool:
        return self.mode in ("cbc", "ecb")

    @property
    def is_authenticated(self) -> bool:
        return self.mode == "gcm"

    def describe(self) -> str:
        return f"{self.name.upper()} ({self.key_len * 8}-bit key, {self.mode.upper()} mode)"


def parse_cipher(name: str) -> CipherSpec:
    normalized = name.strip().lower().replace("_", "-")
    match = _CIPHER_RE.match(normalized)
    if not match:
        raise UsageError(
            f"unsupported cipher: {name}",
            hint="use aes-128|192|256 with cbc, ecb, cfb1, cfb8, cfb, ofb, ctr, or gcm",
        )
    bits = int(match.group(1))
    mode = match.group(2)
    return CipherSpec(name=normalized, key_len=bits // 8, mode=mode)


def check_key(key: bytes) -> bytes:
    if len(key) not in _VALID_KEY_LENGTHS:
        raise UsageError(
            f"AES key must be 16, 24, or 32 bytes (got {len(key)})",
            hint="derive a key with 'aesbreaker derive' instead of padding it",
        )
    return key


def check_iv(iv: bytes, *, mode: str = "cbc") -> bytes:
    if mode == "ecb":
        return b""
    if mode == "gcm":
        if not 1 <= len(iv) <= 64:
            raise UsageError("GCM nonce must be between 1 and 64 bytes")
        return iv
    if len(iv) != AES_BLOCK_SIZE:
        raise UsageError(
            f"{mode.upper()} IV must be exactly {AES_BLOCK_SIZE} bytes (got {len(iv)})"
        )
    return iv


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------


def pkcs7_pad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    if not 1 <= block_size <= 255:
        raise ValueError("invalid block size")
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding]) * padding


def pkcs7_valid_last_block(block: bytes) -> bool:
    """Check a single decrypted final block for valid PKCS#7 padding."""
    if len(block) != AES_BLOCK_SIZE:
        return False
    padding = block[-1]
    if not 1 <= padding <= AES_BLOCK_SIZE:
        return False
    return block[-padding:] == bytes([padding]) * padding


def pkcs7_unpad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    if not data:
        raise DecryptionError("cannot remove PKCS#7 padding from empty data")
    if len(data) % block_size:
        raise DecryptionError("ciphertext is not a multiple of the AES block size")
    padding = data[-1]
    if not 1 <= padding <= block_size:
        raise DecryptionError(
            "invalid PKCS#7 padding (wrong password, wrong cipher, or corrupt data)"
        )
    if data[-padding:] != bytes([padding]) * padding:
        raise DecryptionError(
            "invalid PKCS#7 padding (wrong password, wrong cipher, or corrupt data)"
        )
    return data[:-padding]


# ---------------------------------------------------------------------------
# Block modes
# ---------------------------------------------------------------------------


def aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    check_key(key)
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError("ECB block must be exactly 16 bytes")
    return AES.new(key, AES.MODE_ECB).encrypt(block)


def aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
    check_key(key)
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError("ECB block must be exactly 16 bytes")
    return AES.new(key, AES.MODE_ECB).decrypt(block)


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    check_key(key)
    check_iv(iv, mode="cbc")
    if len(data) % AES_BLOCK_SIZE:
        raise ValueError("CBC data must be a multiple of 16 bytes")
    return AES.new(key, AES.MODE_CBC, iv=iv).encrypt(data)


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    check_key(key)
    check_iv(iv, mode="cbc")
    if len(data) % AES_BLOCK_SIZE:
        raise ValueError("CBC data must be a multiple of 16 bytes")
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)


def aes_cbc_decrypt_last_block(key: bytes, previous: bytes, last: bytes) -> bytes:
    """Decrypt just the final CBC block: D(C_n) xor C_{n-1}."""
    if len(previous) != AES_BLOCK_SIZE or len(last) != AES_BLOCK_SIZE:
        raise ValueError("CBC blocks must be exactly 16 bytes")
    return xor_bytes(aes_ecb_decrypt_block(key, last), previous)


def aes_ecb_decrypt_last_block(key: bytes, last: bytes) -> bytes:
    return aes_ecb_decrypt_block(key, last)


def aes_ctr_cipher(
    key: bytes,
    initial_counter: bytes,
    *,
    little_endian: bool = False,
):
    """Return a stateful CTR cipher with a full-width 128-bit counter.

    pycryptodome's implicit CTR counter is block-aligned; constructing an
    explicit ``Counter`` makes OpenSSL's IV-as-counter semantics and WinZip's
    little-endian counter starting at 1 exact.
    """
    check_key(key)
    check_iv(initial_counter, mode="ctr")
    order: Literal["little", "big"] = "little" if little_endian else "big"
    initial = int.from_bytes(initial_counter, order)
    counter = Counter.new(
        128,
        initial_value=initial,
        little_endian=little_endian,
        allow_wraparound=True,
    )
    return AES.new(key, AES.MODE_CTR, counter=counter)


def aes_ctr_crypt(
    key: bytes,
    initial_counter: bytes,
    data: bytes,
    *,
    little_endian: bool = False,
) -> bytes:
    return aes_ctr_cipher(key, initial_counter, little_endian=little_endian).decrypt(data)


class _Cfb1Cipher:
    """Bit-oriented CFB1 compatible with OpenSSL's ``-cfb1`` mode.

    pycryptodome only supports CFB segment sizes that are multiples of 8, so
    this stateful implementation feeds one ciphertext bit back into the shift
    register per bit. It is intentionally only used for CFB1 files; CFB8 and
    CFB128 use pycryptodome's optimized implementation.
    """

    def __init__(self, key: bytes, iv: bytes) -> None:
        check_key(key)
        check_iv(iv, mode="cfb")
        self._cipher = AES.new(key, AES.MODE_ECB)
        self._register = bytearray(iv)

    def _crypt(self, data: bytes, *, encrypting: bool) -> bytes:
        output = bytearray(len(data))
        for index, value in enumerate(data):
            result = 0
            for bit in range(7, -1, -1):
                input_bit = (value >> bit) & 1
                keystream = self._cipher.encrypt(bytes(self._register))[0] >> 7
                output_bit = input_bit ^ keystream
                result |= output_bit << bit
                # Encryption feeds the ciphertext bit back; decryption feeds
                # the incoming ciphertext bit back.
                carry = output_bit if encrypting else input_bit
                for position in range(15, -1, -1):
                    next_carry = (self._register[position] >> 7) & 1
                    self._register[position] = ((self._register[position] << 1) & 0xFF) | carry
                    carry = next_carry
            output[index] = result
        return bytes(output)

    def encrypt(self, data: bytes) -> bytes:
        return self._crypt(data, encrypting=True)

    def decrypt(self, data: bytes) -> bytes:
        return self._crypt(data, encrypting=False)


def aes_cfb1_cipher(key: bytes, iv: bytes) -> _Cfb1Cipher:
    return _Cfb1Cipher(key, iv)


def aes_cfb_cipher(key: bytes, iv: bytes, *, segment_size: int = 128):
    check_key(key)
    check_iv(iv, mode="cfb")
    return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=segment_size)


def aes_cfb_crypt(key: bytes, iv: bytes, data: bytes, *, segment_size: int = 128) -> bytes:
    return aes_cfb_cipher(key, iv, segment_size=segment_size).decrypt(data)


def aes_ofb_cipher(key: bytes, iv: bytes):
    check_key(key)
    check_iv(iv, mode="ofb")
    return AES.new(key, AES.MODE_OFB, iv=iv)


def aes_ofb_crypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    return aes_ofb_cipher(key, iv).decrypt(data)


# ---------------------------------------------------------------------------
# GCM
# ---------------------------------------------------------------------------


def aes_gcm_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    *,
    aad: bytes = b"",
) -> tuple[bytes, bytes]:
    check_key(key)
    check_iv(nonce, mode="gcm")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.encrypt_and_digest(plaintext)


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    *,
    aad: bytes = b"",
) -> bytes:
    check_key(key)
    check_iv(nonce, mode="gcm")
    if not 4 <= len(tag) <= 16:
        raise UsageError("GCM tag must be between 4 and 16 bytes")
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=len(tag))
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise DecryptionError(
            "GCM authentication failed (wrong key, nonce, tag, AAD, or corrupt data)"
        ) from None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def xor_bytes(left: bytes, right: bytes) -> bytes:
    length = min(len(left), len(right))
    return bytes(a ^ b for a, b in zip(left[:length], right[:length]))


def require_block_multiple(data: bytes, *, what: str = "ciphertext") -> None:
    if len(data) % AES_BLOCK_SIZE:
        raise DecryptionError(
            f"{what} is not a multiple of the AES block size "
            f"({len(data)} bytes, remainder {len(data) % AES_BLOCK_SIZE})"
        )
