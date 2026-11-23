"""AES Crypt v1/v2/v3 container support.

v2 (written by pyAesCrypt >= 6 and AES-Breaker) is the legacy ACKDF format::

    "AES" | version=0x02 | reserved=0x00
    extensions: [uint16be length | bytes] ... | uint16be 0
    iv1                16 bytes (external IV, public)
    c_iv_key           48 bytes AES-256-CBC(iv1, key) over iv0 || internal_key
    hmac1              32 bytes HMAC-SHA256(key, c_iv_key)
    ciphertext         N*16 bytes AES-256-CBC(iv0, internal_key)
    fs16               1 byte  (plaintext length modulo 16)
    hmac0              32 bytes HMAC-SHA256(internal_key, ciphertext)

v1 is the same payload/trailer layout without the v2 extension table.  v3
uses PBKDF2-HMAC-SHA512 over the UTF-8 password with a stored iteration count,
folds the version byte into the session HMAC, and uses authenticated PKCS#7
padding instead of the legacy ``fs16`` byte.

For v1/v2 the password is stretched with ACKDF -- 8192 rounds of SHA-256 over
``digest || utf16le(password)`` seeded by ``iv1 || 16*0x00`` -- not PBKDF2.
``hmac1`` authenticates the password with a 256-bit MAC, so candidate
verification is exact and cheap.

Note that the format does not cover ``fs16`` with either HMAC.  A modified
``fs16`` can change the recovered plaintext length by up to 15 bytes without
invalidating the ciphertext MAC.  This is a property of AES Crypt v1/v2
itself; ``fs16`` is unauthenticated, while v3 PKCS#7 is authenticated.
the decrypted report records whether the padding is internally consistent.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional

from ..crypto import AES_BLOCK_SIZE, aes_cbc_decrypt, aes_cbc_encrypt
from ..errors import DecryptionError, FormatError, UsageError
from ..kdf import (
    AESCRYPT_MAX_PASSWORD_CHARS,
    aescrypt_password_bytes,
    aescrypt_stretch,
    pbkdf2,
)
from ..util import random_bytes
from .base import Artifact, DecryptReport, Outcome, ValidationPolicy, Verifier

MAGIC = b"AES"
SUPPORTED_VERSIONS = (1, 2, 3)
SUPPORTED_VERSION = 2  # version written by encrypt_stream
HEADER_EXTENSION_LIMIT = 1024
HEADER_EXTENSION_BYTES_LIMIT = 1024 * 1024
DEFAULT_BUFFER = 64 * 1024


@dataclass(frozen=True)
class AesCryptHeader:
    version: int
    reserved: int
    extensions: tuple[bytes, ...]
    extension_offset: int
    iv1: bytes
    c_iv_key: bytes
    hmac1: bytes
    ciphertext_offset: int
    ciphertext_length: int
    fs16: Optional[int]
    hmac0: bytes
    iterations: Optional[int] = None

    @property
    def is_v3(self) -> bool:
        return self.version == 3

    @property
    def padding_length(self) -> int:
        if self.fs16 is None:
            return 0
        return (AES_BLOCK_SIZE - self.fs16) % AES_BLOCK_SIZE

    @property
    def plaintext_length(self) -> Optional[int]:
        if self.fs16 is None:
            return None
        return max(0, self.ciphertext_length - self.padding_length)

    @property
    def created_by(self) -> Optional[str]:
        for extension in self.extensions:
            if b"\x00" not in extension:
                continue
            name, _, value = extension.partition(b"\x00")
            if name.strip().upper() == b"CREATED_BY":
                try:
                    return value.rstrip(b"\x00").decode("utf-8", "replace")
                except Exception:
                    return None
        return None


def _read_exact(handle: BinaryIO, count: int, what: str) -> bytes:
    data = handle.read(count)
    if len(data) != count:
        raise FormatError(
            f"truncated AES Crypt header: expected {count} bytes of {what}, got {len(data)}"
        )
    return data


def parse_header(path: str | Path) -> AesCryptHeader:
    path = Path(path)
    try:
        size = path.stat().st_size
        handle = path.open("rb")
    except OSError as exc:
        raise FormatError(f"cannot open {path}: {exc}") from None

    with handle:
        prefix = handle.read(5)
        if len(prefix) < 5 or prefix[:3] != MAGIC:
            raise FormatError(
                f"not an AES Crypt file: {path}",
                hint="the file must start with the bytes b'AES'",
            )
        version = prefix[3]
        reserved = prefix[4]
        if version not in SUPPORTED_VERSIONS:
            raise FormatError(
                f"unsupported AES Crypt version {version}",
                hint="versions 1, 2, and 3 are supported",
            )
        if reserved != 0:
            raise FormatError("invalid AES Crypt header: reserved byte is not zero")

        extension_start = 5
        extensions: list[bytes] = []
        extension_bytes = 0
        if version >= 2:
            while True:
                raw_length = handle.read(2)
                if len(raw_length) != 2:
                    raise FormatError("truncated AES Crypt extension table")
                length = int.from_bytes(raw_length, "big")
                if length == 0:
                    break
                if len(extensions) >= HEADER_EXTENSION_LIMIT:
                    raise FormatError("too many AES Crypt header extensions")
                extension_bytes += length
                if extension_bytes > HEADER_EXTENSION_BYTES_LIMIT:
                    raise FormatError("AES Crypt header extensions exceed the safety limit")
                data = handle.read(length)
                if len(data) != length:
                    raise FormatError("truncated AES Crypt header extension")
                extensions.append(data)

        iterations: Optional[int] = None
        if version == 3:
            raw_iterations = _read_exact(handle, 4, "PBKDF2 iteration count")
            iterations = int.from_bytes(raw_iterations, "big")
            if not 1 <= iterations <= 5_000_000:
                raise FormatError(f"invalid AES Crypt v3 iteration count: {iterations}")

        iv1 = _read_exact(handle, 16, "external IV")
        c_iv_key = _read_exact(handle, 48, "encrypted IV/key")
        hmac1 = _read_exact(handle, 32, "header HMAC")
        ciphertext_offset = handle.tell()
        trailer_length = 33 if version in (1, 2) else 32
        ciphertext_length = size - ciphertext_offset - trailer_length
        if ciphertext_length < 0 or ciphertext_length % AES_BLOCK_SIZE:
            raise FormatError(
                f"invalid AES Crypt payload length ({ciphertext_length} bytes after the header)"
            )

        handle.seek(-trailer_length, os.SEEK_END)
        trailer = handle.read(trailer_length)
        if len(trailer) != trailer_length:
            raise FormatError("truncated AES Crypt trailer")
        if version in (1, 2):
            fs16: Optional[int] = trailer[0]
            hmac0 = trailer[1:]
            assert fs16 is not None
            if fs16 >= AES_BLOCK_SIZE:
                raise FormatError(f"invalid AES Crypt fs16 value: {fs16}")
            if ciphertext_length and ciphertext_length < ((AES_BLOCK_SIZE - fs16) % AES_BLOCK_SIZE):
                raise FormatError("AES Crypt payload is shorter than its padding")
        else:
            fs16 = None
            hmac0 = trailer

        return AesCryptHeader(
            version=version,
            reserved=reserved,
            extensions=tuple(extensions),
            extension_offset=extension_start,
            iv1=iv1,
            c_iv_key=c_iv_key,
            hmac1=hmac1,
            ciphertext_offset=ciphertext_offset,
            ciphertext_length=ciphertext_length,
            fs16=fs16,
            hmac0=hmac0,
            iterations=iterations,
        )


def looks_like_aescrypt(head: bytes) -> bool:
    return len(head) >= 4 and head[:3] == MAGIC and head[3] in SUPPORTED_VERSIONS


def _describe_extension(extension: bytes) -> dict:
    if len(extension) >= 128 and extension == b"\x00" * len(extension):
        return {
            "name": "CONTAINER",
            "value": f"{len(extension)} zero bytes",
            "length": len(extension),
        }
    if b"\x00" in extension:
        raw_name, _, raw_value = extension.partition(b"\x00")
        name = raw_name.decode("utf-8", "replace")
        value = raw_value.rstrip(b"\x00").decode("utf-8", "replace")
        return {"name": name, "value": value, "length": len(extension)}
    return {
        "name": "<unnamed>",
        "value": extension[:64].hex(),
        "length": len(extension),
    }


def _derive_key(
    password: bytes,
    version: int,
    iv1: bytes,
    iterations: Optional[int],
) -> bytes:
    if version == 3:
        try:
            text = password.decode("utf-8")
        except UnicodeDecodeError:
            raise DecryptionError("AES Crypt v3 passwords must be valid UTF-8") from None
        assert iterations is not None
        return pbkdf2(
            text.encode("utf-8"),
            iv1,
            iterations,
            32,
            digest="sha512",
        )
    password_utf16 = aescrypt_password_bytes(password)
    if password_utf16 is None:
        raise DecryptionError(
            "AES Crypt passwords must be valid UTF-8 and at most "
            f"{AESCRYPT_MAX_PASSWORD_CHARS} characters"
        )
    return aescrypt_stretch(password_utf16, iv1)


def _header_hmac(key: bytes, header: AesCryptHeader) -> bytes:
    data = header.c_iv_key
    if header.version == 3:
        data += bytes([header.version])
    return _hmac_sha256(key, data)


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


@dataclass(frozen=True)
class AesCryptVerifier(Verifier):
    format_name = "aescrypt"
    iv1: bytes
    c_iv_key: bytes
    hmac1: bytes
    version: int = 2
    iterations: Optional[int] = None
    created_by: Optional[str] = None

    def describe(self) -> dict:
        return {
            "format": "aescrypt",
            "display_name": f"AES Crypt v{self.version}",
            "cipher": "AES-256-CBC",
            "kdf": (
                f"PBKDF2-HMAC-SHA512 ({self.iterations} iterations, UTF-8 password)"
                if self.version == 3
                else "ACKDF-SHA-256 (8192 rounds, UTF-16LE password)"
            ),
            "authentication": "HMAC-SHA256",
            "password_check": (
                "HMAC-SHA256 of encrypted IV/key and version byte"
                if self.version == 3
                else "HMAC-SHA256 of the encrypted IV/key"
            ),
            "created_by": self.created_by,
        }

    def verification_label(self) -> str:
        return "HMAC-SHA256 (256-bit)"

    def verify(self, password: bytes) -> Outcome:
        try:
            key = _derive_key(password, self.version, self.iv1, self.iterations)
        except Exception:
            return Outcome.REJECT
        data = self.c_iv_key
        if self.version == 3:
            data += bytes([self.version])
        expected = hmac.new(key, data, hashlib.sha256).digest()
        return Outcome.CONFIRMED if hmac.compare_digest(expected, self.hmac1) else Outcome.REJECT


class AesCryptArtifact(Artifact):
    format_name = "aescrypt"
    display_name = "AES Crypt"

    def __init__(self, path: str | Path, header: Optional[AesCryptHeader] = None) -> None:
        path = Path(path)
        header = header or parse_header(path)
        super().__init__(path, path.stat().st_size)
        self.header = header

    def inspect(self) -> dict:
        header = self.header
        is_v3 = header.version == 3
        return {
            "format": "aescrypt",
            "display_name": f"AES Crypt v{header.version}",
            "version": header.version,
            "reserved": header.reserved,
            "extensions": [_describe_extension(ext) for ext in header.extensions],
            "created_by": header.created_by,
            "kdf": (
                f"PBKDF2-HMAC-SHA512 ({header.iterations} iterations, UTF-8 password)"
                if is_v3
                else "ACKDF-SHA-256 (8192 rounds, UTF-16LE password)"
            ),
            "cipher": "AES-256-CBC with a random internal key",
            "authentication": "HMAC-SHA256 (header key material and ciphertext)",
            "external_iv": header.iv1.hex(),
            "encrypted_key_material_bytes": len(header.c_iv_key),
            "header_hmac": header.hmac1.hex(),
            "ciphertext_offset": header.ciphertext_offset,
            "ciphertext_bytes": header.ciphertext_length,
            "ciphertext_blocks": header.ciphertext_length // AES_BLOCK_SIZE,
            "fs16": header.fs16,
            "iterations": header.iterations,
            "plaintext_bytes_estimate": header.plaintext_length,
            "fs16_authenticated": None if is_v3 else False,
            "structural_status": "valid",
            "notes": (
                [
                    "The password is verified by the header HMAC before decryption.",
                    "v3 uses PBKDF2-HMAC-SHA512 and authenticated PKCS#7 padding.",
                ]
                if is_v3
                else [
                    "The password is verified by the header HMAC before decryption.",
                    "AES Crypt v1/v2 does not authenticate fs16; plaintext length may have been altered by up to 15 bytes.",
                ]
            ),
        }

    def verifier(self, policy: ValidationPolicy) -> Verifier:
        # The container is authenticated, so the heuristic policy is unused.
        return AesCryptVerifier(
            iv1=self.header.iv1,
            c_iv_key=self.header.c_iv_key,
            hmac1=self.header.hmac1,
            version=self.header.version,
            iterations=self.header.iterations,
            created_by=self.header.created_by,
        )

    def _verify_ciphertext_mac(self, internal_key: bytes) -> None:
        expected = hmac.new(internal_key, digestmod=hashlib.sha256)
        with self.path.open("rb") as handle:
            handle.seek(self.header.ciphertext_offset)
            remaining = self.header.ciphertext_length
            while remaining:
                chunk = handle.read(min(DEFAULT_BUFFER, remaining))
                if not chunk:
                    raise DecryptionError("unexpected end of AES Crypt ciphertext")
                expected.update(chunk)
                remaining -= len(chunk)
        if not hmac.compare_digest(expected.digest(), self.header.hmac0):
            raise DecryptionError(
                "AES Crypt ciphertext HMAC does not match; the payload is corrupt "
                "or has been modified after encryption"
            )

    def decrypt(self, password: bytes, handle: BinaryIO) -> DecryptReport:
        header = self.header
        key = _derive_key(password, header.version, header.iv1, header.iterations)
        if not hmac.compare_digest(_header_hmac(key, header), header.hmac1):
            raise DecryptionError(
                "incorrect password for this AES Crypt file",
                hint="the password did not match the header HMAC",
            )

        iv_key = aes_cbc_decrypt(key, header.iv1, header.c_iv_key)
        iv0 = iv_key[:16]
        internal_key = iv_key[16:48]
        self._verify_ciphertext_mac(internal_key)
        if header.version == 3:
            return self._decrypt_v3(internal_key, iv0, handle)
        return self._decrypt_legacy(internal_key, iv0, handle)

    def _decrypt_legacy(self, internal_key: bytes, iv0: bytes, handle: BinaryIO) -> DecryptReport:
        header = self.header
        written = 0
        pad = header.padding_length
        plain_limit = header.plaintext_length
        assert plain_limit is not None
        final_plain_block = b""
        if not header.ciphertext_length:
            return DecryptReport(
                format_name=self.format_name,
                output=None,
                bytes_written=0,
                verification="HMAC-SHA256 verified (password and ciphertext)",
                details={
                    "created_by": header.created_by,
                    "ciphertext_bytes": 0,
                    "plaintext_bytes": 0,
                    "fs16": header.fs16,
                    "padding_consistent": True,
                    "fs16_authenticated": False,
                    "header_hmac_verified": True,
                    "ciphertext_hmac_verified": True,
                },
            )
        with self.path.open("rb") as source:
            source.seek(header.ciphertext_offset)
            remaining = header.ciphertext_length
            cipher = _CbcStream(internal_key, iv0)
            while remaining:
                chunk = source.read(min(DEFAULT_BUFFER, remaining))
                if not chunk:
                    raise DecryptionError("unexpected end of AES Crypt ciphertext")
                remaining -= len(chunk)
                plaintext = cipher.decrypt(chunk)
                if remaining == 0:
                    final_plain_block = plaintext[-AES_BLOCK_SIZE:]
                if written + len(plaintext) > plain_limit:
                    plaintext = plaintext[: plain_limit - written]
                if plaintext:
                    handle.write(plaintext)
                    written += len(plaintext)

        padding_consistent = True
        if pad:
            padding_consistent = (
                len(final_plain_block) == AES_BLOCK_SIZE
                and final_plain_block[-pad:] == bytes([pad]) * pad
            )

        details = {
            "created_by": header.created_by,
            "ciphertext_bytes": header.ciphertext_length,
            "plaintext_bytes": written,
            "fs16": header.fs16,
            "padding_consistent": padding_consistent,
            "fs16_authenticated": False,
            "header_hmac_verified": True,
            "ciphertext_hmac_verified": True,
        }
        return DecryptReport(
            format_name=self.format_name,
            output=None,
            bytes_written=written,
            verification="HMAC-SHA256 verified (password and ciphertext)",
            details=details,
        )

    def _decrypt_v3(self, internal_key: bytes, iv0: bytes, handle: BinaryIO) -> DecryptReport:
        header = self.header
        written = 0
        pending = b""
        with self.path.open("rb") as source:
            source.seek(header.ciphertext_offset)
            remaining = header.ciphertext_length
            cipher = _CbcStream(internal_key, iv0)
            while remaining:
                chunk = source.read(min(DEFAULT_BUFFER, remaining))
                if not chunk:
                    raise DecryptionError("unexpected end of AES Crypt ciphertext")
                remaining -= len(chunk)
                plaintext = cipher.decrypt(chunk)
                data = pending + plaintext
                if len(data) > AES_BLOCK_SIZE:
                    output = data[:-AES_BLOCK_SIZE]
                    handle.write(output)
                    written += len(output)
                    pending = data[-AES_BLOCK_SIZE:]
                else:
                    pending = data

        if len(pending) != AES_BLOCK_SIZE:
            raise DecryptionError("AES Crypt v3 payload has no final block")
        padding = pending[-1]
        if not 1 <= padding <= AES_BLOCK_SIZE or pending[-padding:] != (bytes([padding]) * padding):
            raise DecryptionError("AES Crypt v3 payload has invalid PKCS#7 padding")
        data = pending[:-padding]
        if data:
            handle.write(data)
            written += len(data)

        details = {
            "created_by": header.created_by,
            "ciphertext_bytes": header.ciphertext_length,
            "plaintext_bytes": written,
            "fs16": None,
            "iterations": header.iterations,
            "padding_consistent": True,
            "fs16_authenticated": None,
            "pkcs7_padding_authenticated": True,
            "header_hmac_verified": True,
            "ciphertext_hmac_verified": True,
        }
        return DecryptReport(
            format_name=self.format_name,
            output=None,
            bytes_written=written,
            verification="HMAC-SHA256 verified (password and ciphertext)",
            details=details,
        )

    def default_decrypted_name(self) -> str:
        name = self.path.name
        if name.lower().endswith(".aes"):
            return name[:-4]
        return name + ".dec"


class _CbcStream:
    """Stateful AES-CBC decryptor that accepts arbitrary chunk boundaries."""

    def __init__(self, key: bytes, iv: bytes) -> None:
        from Crypto.Cipher import AES

        self._cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        self._pending = b""

    def decrypt(self, data: bytes) -> bytes:
        data = self._pending + data
        usable = len(data) - (len(data) % AES_BLOCK_SIZE)
        self._pending = data[usable:]
        if not usable:
            return b""
        return self._cipher.decrypt(data[:usable])


def encrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    password: bytes,
    *,
    version: int = 2,
    iterations: int = 600_000,
    created_by: str = "AES-Breaker",
    buffer_size: int = DEFAULT_BUFFER,
) -> None:
    """Write an AES Crypt v2/v3 file. v2 is the default for pyAesCrypt 6.x."""
    if buffer_size % AES_BLOCK_SIZE:
        raise ValueError("buffer size must be a multiple of 16")
    if version == 3:
        _encrypt_v3(
            source,
            destination,
            password,
            iterations=iterations,
            created_by=created_by,
            buffer_size=buffer_size,
        )
        return
    if version != 2:
        raise UsageError("AES Crypt writer supports version 2 or 3")
    password_utf16 = aescrypt_password_bytes(password)
    if password_utf16 is None:
        raise UsageError(
            "AES Crypt passwords must be valid UTF-8 and at most "
            f"{AESCRYPT_MAX_PASSWORD_CHARS} characters"
        )

    iv1 = random_bytes(16)
    key = aescrypt_stretch(password_utf16, iv1)
    iv0 = random_bytes(16)
    internal_key = random_bytes(32)

    destination.write(MAGIC + bytes([SUPPORTED_VERSION, 0]))
    extension = b"CREATED_BY\x00" + created_by.encode("utf-8")
    if len(extension) > 0xFFFF:
        raise ValueError("created-by extension is too long")
    destination.write(struct.pack(">H", len(extension)))
    destination.write(extension)
    container_extension = b"\x00" * 128
    destination.write(struct.pack(">H", len(container_extension)))
    destination.write(container_extension)
    destination.write(b"\x00\x00")

    c_iv_key = aes_cbc_encrypt(key, iv1, iv0 + internal_key)
    destination.write(iv1)
    destination.write(c_iv_key)
    destination.write(_hmac_sha256(key, c_iv_key))

    cipher = _CbcEncryptor(internal_key, iv0)
    payload_mac = hmac.new(internal_key, digestmod=hashlib.sha256)
    fs16 = 0
    while True:
        chunk = _read_full(source, buffer_size)
        if len(chunk) < buffer_size:
            fs16 = len(chunk) % AES_BLOCK_SIZE
            padding = (AES_BLOCK_SIZE - fs16) % AES_BLOCK_SIZE
            if padding:
                chunk += bytes([padding]) * padding
            if chunk:
                ciphertext = cipher.encrypt(chunk)
                payload_mac.update(ciphertext)
                destination.write(ciphertext)
            break
        ciphertext = cipher.encrypt(chunk)
        payload_mac.update(ciphertext)
        destination.write(ciphertext)

    destination.write(bytes([fs16]))
    destination.write(payload_mac.digest())


class _CbcEncryptor:
    def __init__(self, key: bytes, iv: bytes) -> None:
        from Crypto.Cipher import AES

        self._cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    def encrypt(self, data: bytes) -> bytes:
        if len(data) % AES_BLOCK_SIZE:
            raise ValueError("CBC plaintext chunk must be block aligned")
        return self._cipher.encrypt(data)


def _read_full(source: BinaryIO, size: int) -> bytes:
    """Read up to *size* bytes, retrying short reads that are not EOF."""
    chunks = []
    remaining = size
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _encrypt_v3(
    source: BinaryIO,
    destination: BinaryIO,
    password: bytes,
    *,
    iterations: int,
    created_by: str,
    buffer_size: int,
) -> None:
    if not 1 <= iterations <= 5_000_000:
        raise UsageError("AES Crypt v3 iterations must be between 1 and 5000000")
    try:
        password_utf8 = password.decode("utf-8").encode("utf-8")
    except UnicodeDecodeError:
        raise UsageError("AES Crypt v3 passwords must be valid UTF-8") from None

    iv1 = random_bytes(16)
    key = pbkdf2(password_utf8, iv1, iterations, 32, digest="sha512")
    iv0 = random_bytes(16)
    internal_key = random_bytes(32)

    destination.write(MAGIC + bytes([3, 0]))
    extension = b"CREATED_BY\x00" + created_by.encode("utf-8")
    if len(extension) > 0xFFFF:
        raise ValueError("created-by extension is too long")
    destination.write(struct.pack(">H", len(extension)))
    destination.write(extension)
    destination.write(b"\x00\x00")
    destination.write(iterations.to_bytes(4, "big"))

    c_iv_key = aes_cbc_encrypt(key, iv1, iv0 + internal_key)
    destination.write(iv1)
    destination.write(c_iv_key)
    destination.write(_hmac_sha256(key, c_iv_key + b"\x03"))

    cipher = _CbcEncryptor(internal_key, iv0)
    payload_mac = hmac.new(internal_key, digestmod=hashlib.sha256)

    def encrypt_write(data: bytes) -> None:
        ciphertext = cipher.encrypt(data)
        payload_mac.update(ciphertext)
        destination.write(ciphertext)

    pending = b""
    while True:
        chunk = _read_full(source, buffer_size)
        if len(chunk) == buffer_size:
            if pending:
                encrypt_write(pending)
            pending = chunk
            continue
        data = pending + chunk
        padding = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
        data += bytes([padding]) * padding
        encrypt_write(data)
        break

    destination.write(payload_mac.digest())


def encrypt_bytes(
    plaintext: bytes,
    password: bytes,
    *,
    version: int = 2,
    iterations: int = 600_000,
    created_by: str = "AES-Breaker",
) -> bytes:
    source = io.BytesIO(plaintext)
    destination = io.BytesIO()
    encrypt_stream(
        source,
        destination,
        password,
        version=version,
        iterations=iterations,
        created_by=created_by,
    )
    return destination.getvalue()
