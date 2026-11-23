"""Key derivation functions used by the supported containers and tools.

The AES Crypt v1/v2 KDF is *not* PBKDF2. It is the file-format
password stretching defined by AES Crypt: 8192 SHA-256 rounds over
``digest || password_utf16le``, seeded with the external IV and 16 zero
bytes. AES Crypt v3 uses PBKDF2-HMAC-SHA512 instead.  Naming it accurately matters because a PBKDF2 implementation would
recover nothing.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from .errors import UsageError

SUPPORTED_DIGESTS = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
AESCRYPT_STRETCH_ROUNDS = 8192
AESCRYPT_MAX_PASSWORD_CHARS = 1024


def normalize_digest(name: str) -> str:
    normalized = name.strip().lower().replace("-", "")
    if normalized not in SUPPORTED_DIGESTS:
        raise UsageError(
            f"unsupported digest: {name}",
            hint="choose one of: " + ", ".join(SUPPORTED_DIGESTS),
        )
    return normalized


def evp_bytes_to_key(
    password: bytes,
    salt: bytes,
    key_len: int,
    iv_len: int,
    digest: str = "sha256",
) -> tuple[bytes, bytes]:
    """OpenSSL ``EVP_BytesToKey`` with a single iteration.

    This is the legacy KDF used by ``openssl enc`` without ``-pbkdf2``:
    ``D_i = H(D_{i-1} || password || salt)`` and the key/IV are the
    concatenation of consecutive digests.
    """
    digest = normalize_digest(digest)
    if key_len < 0 or iv_len < 0:
        raise ValueError("negative key or IV length")
    if not password:
        # OpenSSL permits an empty passphrase; do not reject it silently.
        password = b""
    material = b""
    previous = b""
    wanted = key_len + iv_len
    while len(material) < wanted:
        previous = hashlib.new(digest, previous + password + salt).digest()
        material += previous
    return material[:key_len], material[key_len:wanted]


def pbkdf2(
    password: bytes,
    salt: bytes,
    iterations: int,
    length: int,
    digest: str = "sha256",
) -> bytes:
    digest = normalize_digest(digest)
    if iterations < 1:
        raise UsageError("PBKDF2 iteration count must be at least 1")
    if length < 1:
        raise UsageError("derived key length must be at least 1 byte")
    if length > 1024 * 1024:
        raise UsageError("derived key length is unreasonably large")
    return hashlib.pbkdf2_hmac(digest, password, salt, iterations, dklen=length)


def aescrypt_password_bytes(password: bytes) -> Optional[bytes]:
    """Convert candidate bytes to the UTF-16LE form AES Crypt hashes.

    pyAesCrypt accepts a ``str`` password and encodes it as UTF-16LE, so a
    candidate that is not valid UTF-8 could never have produced an AES Crypt
    file.  Returning ``None`` lets the hot verify loop reject it cheaply.
    Passwords longer than the format's 1024-character limit are likewise
    impossible and are rejected.
    """
    try:
        text = password.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) > AESCRYPT_MAX_PASSWORD_CHARS:
        return None
    return text.encode("utf-16-le")


def aescrypt_stretch(password_utf16le: bytes, external_iv: bytes) -> bytes:
    """AES Crypt v1/v2 password stretching (SHA-256 x 8192)."""
    if len(external_iv) != 16:
        raise ValueError("AES Crypt external IV must be 16 bytes")
    digest = external_iv + b"\x00" * 16
    sha256 = hashlib.sha256
    password = password_utf16le
    for _ in range(AESCRYPT_STRETCH_ROUNDS):
        digest = sha256(digest + password).digest()
    return digest


def hkdf(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int,
    digest: str = "sha256",
) -> bytes:
    """RFC 5869 HKDF (extract-then-expand)."""
    digest = normalize_digest(digest)
    if length < 0:
        raise UsageError("HKDF output length cannot be negative")
    hash_len = hashlib.new(digest).digest_size
    if length > 255 * hash_len:
        raise UsageError("HKDF output length exceeds 255 hash blocks")
    effective_salt = salt if salt else b"\x00" * hash_len
    prk = hmac.new(effective_salt, ikm, digest).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), digest).digest()
        output += previous
        counter += 1
    return output[:length]
