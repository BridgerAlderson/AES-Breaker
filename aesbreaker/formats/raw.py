"""Exact raw AES decryption with explicitly supplied parameters.

Unlike the legacy text mode this module never pads, truncates, or guesses a
key.  Every parameter must be supplied, GCM tags are verified, and PKCS#7 is
checked strictly.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from typing import Any, BinaryIO

from Crypto.Cipher import AES

from ..crypto import (
    AES_BLOCK_SIZE,
    CipherSpec,
    aes_cfb1_cipher,
    aes_cfb_cipher,
    aes_ctr_cipher,
    aes_ofb_cipher,
    pkcs7_unpad,
)
from ..errors import DecryptionError, UsageError

CHUNK_SIZE = 64 * 1024


@dataclass(frozen=True)
class RawSpec:
    cipher: CipherSpec
    key: bytes
    iv: bytes = b""
    nonce: bytes = b""
    tag: bytes = b""
    aad: bytes = b""
    padding: str = "pkcs7"
    ctr_little_endian: bool = False

    def validate(self) -> "RawSpec":
        if len(self.key) != self.cipher.key_len:
            raise UsageError(
                f"{self.cipher.name} requires a {self.cipher.key_len}-byte key "
                f"(got {len(self.key)})"
            )
        if self.cipher.mode == "gcm":
            if not 1 <= len(self.nonce) <= 64:
                raise UsageError("GCM requires --nonce (1..64 bytes)")
            if not 4 <= len(self.tag) <= 16:
                raise UsageError("GCM requires --tag (4..16 bytes)")
            if self.padding != "none":
                raise UsageError("GCM does not use PKCS#7 padding")
            if self.iv:
                raise UsageError("GCM uses --nonce, not --iv")
            if self.ctr_little_endian:
                raise UsageError("--ctr-little-endian is CTR-only")
        elif self.cipher.mode == "ecb":
            if self.iv:
                raise UsageError("ECB does not use an IV")
            if self.padding not in ("pkcs7", "none"):
                raise UsageError("padding must be pkcs7 or none")
        elif self.cipher.mode in ("cbc",):
            if len(self.iv) != AES_BLOCK_SIZE:
                raise UsageError("CBC requires a 16-byte --iv")
            if self.padding not in ("pkcs7", "none"):
                raise UsageError("padding must be pkcs7 or none")
        else:  # ctr, cfb, ofb
            if len(self.iv) != AES_BLOCK_SIZE:
                raise UsageError(
                    f"{self.cipher.mode.upper()} requires a 16-byte --iv "
                    "(the initial counter for CTR)"
                )
            if self.padding != "none":
                raise UsageError(f"{self.cipher.mode.upper()} is a stream mode and has no padding")
            if self.ctr_little_endian and self.cipher.mode != "ctr":
                raise UsageError("--ctr-little-endian is CTR-only")
        if self.cipher.mode != "gcm":
            if self.nonce:
                raise UsageError("--nonce only applies to GCM")
            if self.tag:
                raise UsageError("--tag only applies to GCM")
            if self.aad:
                raise UsageError("--aad only applies to GCM")
        if self.cipher.mode != "ctr" and self.ctr_little_endian:
            raise UsageError("--ctr-little-endian is CTR-only")
        return self


def decrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    spec: RawSpec,
) -> int:
    spec = spec.validate()
    cipher = spec.cipher

    decryptor: Any
    if cipher.mode in ("cbc", "ecb"):
        decryptor = (
            AES.new(spec.key, AES.MODE_ECB)
            if cipher.mode == "ecb"
            else AES.new(spec.key, AES.MODE_CBC, iv=spec.iv)
        )
        written = 0
        pending = b""
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            pending += chunk
            # Keep at least one full block for padding removal; never emit
            # ciphertext bytes that are not block aligned.
            while len(pending) > AES_BLOCK_SIZE:
                take = len(pending) - AES_BLOCK_SIZE
                take -= take % AES_BLOCK_SIZE
                if take <= 0:
                    break
                block = pending[:take]
                pending = pending[take:]
                plain = decryptor.decrypt(block)
                destination.write(plain)
                written += len(plain)
        if not pending:
            if spec.padding == "pkcs7":
                raise DecryptionError("ciphertext is empty; no PKCS#7 padding present")
            return written
        if len(pending) % AES_BLOCK_SIZE:
            raise DecryptionError(f"ciphertext length is not a multiple of {AES_BLOCK_SIZE} bytes")
        final_plain = decryptor.decrypt(pending)
        if spec.padding == "pkcs7":
            final_plain = pkcs7_unpad(final_plain)
        destination.write(final_plain)
        return written + len(final_plain)

    if cipher.mode == "ctr":
        decryptor = aes_ctr_cipher(spec.key, spec.iv, little_endian=spec.ctr_little_endian)
    elif cipher.mode == "cfb1":
        decryptor = aes_cfb1_cipher(spec.key, spec.iv)
    elif cipher.mode in ("cfb", "cfb8"):
        segment = 128 if cipher.mode == "cfb" else 8
        decryptor = aes_cfb_cipher(spec.key, spec.iv, segment_size=segment)
    elif cipher.mode == "ofb":
        decryptor = aes_ofb_cipher(spec.key, spec.iv)
    elif cipher.mode == "gcm":
        decryptor = AES.new(spec.key, AES.MODE_GCM, nonce=spec.nonce, mac_len=len(spec.tag))
        if spec.aad:
            decryptor.update(spec.aad)
    else:
        raise UsageError(f"unsupported raw mode: {cipher.mode}")

    if cipher.mode == "gcm":
        # Never expose plaintext before the tag is verified.  Spooling keeps
        # memory bounded for large inputs while still making stdout safe.
        written = 0
        with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b") as buffer:
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                plain = decryptor.decrypt(chunk)
                buffer.write(plain)
                written += len(plain)
            try:
                decryptor.verify(spec.tag)
            except ValueError:
                raise DecryptionError(
                    "GCM authentication failed: wrong key, nonce, tag, AAD, or corrupt ciphertext"
                ) from None
            buffer.seek(0)
            shutil.copyfileobj(buffer, destination, length=CHUNK_SIZE)
        return written

    written = 0
    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            break
        plain = decryptor.decrypt(chunk)
        destination.write(plain)
        written += len(plain)
    return written
