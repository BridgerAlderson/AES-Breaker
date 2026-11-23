"""OpenSSL ``enc`` compatibility.

``openssl enc`` stores only a salt (``Salted__`` + 8 bytes).  The cipher,
digest, PBKDF2 choice, and iteration count are *not* recorded in the file, so
they must be supplied explicitly.  The format also has no MAC or AEAD tag:
a correct PKCS#7 padding is only ~1/256 evidence, never proof.

This module therefore:

* rejects ambiguous defaults instead of guessing;
* verifies padding on the final block cheaply, then optionally confirms an
  exact known-plaintext prefix;
* otherwise requires a validation policy (text, magic, or any) and reports
  matches as *probable*, not confirmed;
* refuses to pretend that CTR/CFB/OFB can be verified without a known prefix.
"""

from __future__ import annotations

import hmac
import io
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Optional

from Crypto.Cipher import AES

from ..crypto import (
    AES_BLOCK_SIZE,
    CipherSpec,
    aes_cfb1_cipher,
    aes_cfb_cipher,
    aes_ctr_cipher,
    aes_ecb_decrypt_block,
    aes_ofb_cipher,
    parse_cipher,
    pkcs7_pad,
    pkcs7_unpad,
    pkcs7_valid_last_block,
    xor_bytes,
)
from ..errors import (
    DecryptionError,
    FormatError,
    InputError,
    UnsupportedError,
    UsageError,
)
from ..kdf import evp_bytes_to_key, normalize_digest, pbkdf2
from ..signatures import assess_plaintext, looks_like_base64
from ..util import b64_decode, random_bytes
from .base import (
    MIN_CONFIRM_PREFIX,
    Artifact,
    DecryptReport,
    Outcome,
    ValidationPolicy,
    Verifier,
)

SALTED_MAGIC = b"Salted__"
SALT_LENGTH = 8
DEFAULT_BUFFER = 64 * 1024
PROBE_SIZE = 64
SUPPORTED_ENCODINGS = ("auto", "raw", "base64")


@dataclass(frozen=True)
class OpenSSLLayout:
    cipher: Optional[CipherSpec]
    digest: str
    pbkdf2: bool
    iterations: int
    salt: bytes
    ciphertext_offset: int
    ciphertext_length: int
    payload: Optional[bytes]
    source_encoding: str
    nopad: bool


def _read_at(path: Path, offset: int, length: int) -> bytes:
    with path.open("rb") as handle:
        handle.seek(offset)
        return handle.read(length)


def _load_layout(path: str | Path, options) -> OpenSSLLayout:
    path = Path(path)
    encoding = options.in_encoding
    if encoding not in SUPPORTED_ENCODINGS:
        raise UsageError(
            f"invalid OpenSSL input encoding: {encoding}",
            hint="choose auto, raw, or base64",
        )
    digest = normalize_digest(options.digest)
    if options.iterations < 1:
        raise UsageError("OpenSSL PBKDF2 iterations must be at least 1")
    try:
        size = path.stat().st_size
        head = _read_at(path, 0, 4096)
    except OSError as exc:
        raise FormatError(f"cannot read {path}: {exc}") from None

    payload: Optional[bytes] = None
    source_encoding = "raw"

    if head.startswith(SALTED_MAGIC):
        if options.nosalt:
            raise FormatError("the file has a Salted__ header but --openssl-nosalt was given")
        salt = head[SALT_LENGTH:16]
        ciphertext_offset = 16
        ciphertext_length = size - 16
    else:
        decoded: Optional[bytes] = None
        if encoding in ("auto", "base64") and looks_like_base64(head):
            try:
                candidate = b64_decode(_read_at(path, 0, size), what="OpenSSL base64 input")
            except InputError:
                candidate = None
            if candidate is not None:
                if candidate.startswith(SALTED_MAGIC):
                    decoded = candidate
                elif options.nosalt and encoding == "base64":
                    # Without a Salted__ marker, base64 is only assumed when
                    # the caller explicitly says so; auto would silently
                    # reinterpret a raw ASCII-looking ciphertext.
                    decoded = candidate
        if decoded is not None:
            payload = decoded
            source_encoding = "base64"
            if decoded.startswith(SALTED_MAGIC):
                if options.nosalt:
                    raise FormatError(
                        "decoded file has a Salted__ header but --openssl-nosalt was given"
                    )
                salt = decoded[SALT_LENGTH:16]
                ciphertext_offset = 16
                ciphertext_length = len(decoded) - 16
            else:
                salt = b""
                ciphertext_offset = 0
                ciphertext_length = len(decoded)
        elif options.nosalt:
            salt = b""
            ciphertext_offset = 0
            ciphertext_length = size
        else:
            raise FormatError(
                "not an OpenSSL salted container (no Salted__ header)",
                hint=(
                    "files created with 'openssl enc -nosalt' need --openssl-nosalt; "
                    "the cipher and digest must also be supplied"
                ),
            )

    cipher = parse_cipher(options.cipher) if options.cipher else None
    if cipher is not None:
        if cipher.mode == "gcm":
            raise UnsupportedError(
                "openssl enc does not produce AES-GCM files",
                hint="use 'aesbreaker decrypt --format raw' for an explicit GCM file",
            )
        if cipher.mode in ("cbc", "ecb"):
            if options.nopad:
                if ciphertext_length % AES_BLOCK_SIZE:
                    raise FormatError(
                        f"{cipher.name} ciphertext length is not a multiple of 16 "
                        f"({ciphertext_length} bytes) although --openssl-nopad was given"
                    )
            elif ciphertext_length <= 0 or ciphertext_length % AES_BLOCK_SIZE:
                raise FormatError(
                    f"{cipher.name} ciphertext length is invalid "
                    f"({ciphertext_length} bytes; must be a non-zero multiple of 16)"
                )
        if options.nopad and cipher.mode not in ("cbc", "ecb"):
            raise UsageError("--openssl-nopad only applies to CBC/ECB modes")
    if ciphertext_length < 0:
        raise FormatError("OpenSSL ciphertext length is negative")

    return OpenSSLLayout(
        cipher=cipher,
        digest=digest,
        pbkdf2=options.pbkdf2,
        iterations=options.iterations,
        salt=salt,
        ciphertext_offset=ciphertext_offset,
        ciphertext_length=ciphertext_length,
        payload=payload,
        source_encoding=source_encoding,
        nopad=bool(options.nopad),
    )


def looks_like_openssl(head: bytes) -> bool:
    return head.startswith(SALTED_MAGIC)


def _derive(
    password: bytes,
    salt: bytes,
    key_len: int,
    iv_len: int,
    digest: str,
    use_pbkdf2: bool,
    iterations: int,
) -> tuple[bytes, bytes]:
    if use_pbkdf2:
        material = pbkdf2(password, salt, iterations, key_len + iv_len, digest=digest)
        return material[:key_len], material[key_len:]
    return evp_bytes_to_key(password, salt, key_len, iv_len, digest=digest)


@dataclass(frozen=True)
class OpenSSLVerifier(Verifier):
    format_name = "openssl"
    cipher_name: str
    key_len: int
    mode: str
    digest: str
    use_pbkdf2: bool
    iterations: int
    salt: bytes
    first_ct: bytes
    ciphertext_length: int
    last_ct: bytes
    previous_ct: Optional[bytes]
    policy: ValidationPolicy
    nopad: bool = False

    @property
    def iv_len(self) -> int:
        if self.mode == "ecb":
            return 0
        return AES_BLOCK_SIZE

    def describe(self) -> dict:
        return {
            "format": "openssl-enc",
            "display_name": "OpenSSL enc",
            "cipher": self.cipher_name,
            "kdf": (
                f"PBKDF2-HMAC-{self.digest.upper()} ({self.iterations} iterations)"
                if self.use_pbkdf2
                else f"EVP_BytesToKey({self.digest.upper()}, 1 iteration)"
            ),
            "authentication": "none (openssl enc has no MAC/tag)",
            "padding": "none (openssl -nopad)" if self.nopad else "PKCS#7",
            "evidence": (
                "none without a known prefix (no padding, no MAC)"
                if self.nopad
                else "PKCS#7 padding plus optional text/magic/prefix"
            ),
            "verification_policy": self.policy.describe(),
            "known_prefix": self.policy.known_prefix.hex() if self.policy.has_prefix else None,
        }

    def verification_label(self) -> str:
        if self.policy.has_prefix:
            return "exact known-plaintext prefix (openssl enc is unauthenticated)"
        if self.nopad:
            return "heuristic only, no padding or MAC (openssl enc -nopad)"
        return "heuristic (openssl enc is unauthenticated)"

    def _derive(self, password: bytes) -> tuple[bytes, bytes]:
        return _derive(
            password,
            self.salt,
            self.key_len,
            self.iv_len,
            self.digest,
            self.use_pbkdf2,
            self.iterations,
        )

    def verify(self, password: bytes) -> Outcome:
        prefix = self.policy.known_prefix
        if prefix and len(prefix) < MIN_CONFIRM_PREFIX:
            # Guard direct construction as well as the artifact factory.
            return Outcome.REJECT
        key, iv = self._derive(password)

        if self.mode in ("ctr", "cfb", "cfb1", "cfb8", "ofb"):
            if not prefix:
                # Guarded at construction; keep the invariant explicit.
                return Outcome.REJECT
            plain = _stream_decrypt(self.mode, key, iv, self.first_ct, little_endian=False)
            if hmac.compare_digest(plain[: len(prefix)], prefix):
                return Outcome.CONFIRMED
            return Outcome.REJECT

        # Block modes: cheap padding check on the final block first.
        try:
            if self.mode == "ecb":
                last_plain = aes_ecb_decrypt_block(key, self.last_ct)
            elif self.previous_ct is None:
                last_plain = xor_bytes(aes_ecb_decrypt_block(key, self.last_ct), iv)
            else:
                last_plain = xor_bytes(aes_ecb_decrypt_block(key, self.last_ct), self.previous_ct)
        except Exception:
            return Outcome.REJECT

        if not self.nopad and not pkcs7_valid_last_block(last_plain):
            return Outcome.REJECT

        full_probe = self.ciphertext_length <= len(self.first_ct)
        probe = _block_decrypt(self.mode, key, iv, self.first_ct)
        if full_probe:
            if self.nopad:
                plaintext = probe
            else:
                try:
                    plaintext = pkcs7_unpad(probe)
                except DecryptionError:
                    return Outcome.REJECT
        else:
            plaintext = probe

        if prefix:
            if len(plaintext) < len(prefix):
                return Outcome.REJECT
            if not hmac.compare_digest(plaintext[: len(prefix)], prefix):
                return Outcome.REJECT
            return Outcome.CONFIRMED

        if self.policy.mode == "strict":
            return Outcome.REJECT
        if self.policy.mode == "any":
            return Outcome.WEAK if self.nopad else Outcome.PROBABLE

        plausibility = assess_plaintext(plaintext)
        if self.policy.mode == "magic":
            return Outcome.PROBABLE if plausibility.is_magic else Outcome.WEAK
        if self.policy.mode == "text":
            return Outcome.PROBABLE if plausibility.is_text else Outcome.WEAK
        if plausibility.is_magic or plausibility.is_text:
            return Outcome.PROBABLE
        return Outcome.WEAK


def _block_decrypt(mode: str, key: bytes, iv: bytes, data: bytes) -> bytes:
    if not data:
        return b""
    if mode == "ecb":
        return AES.new(key, AES.MODE_ECB).decrypt(data)
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(data)


def _stream_decrypt(
    mode: str,
    key: bytes,
    iv: bytes,
    data: bytes,
    *,
    little_endian: bool,
) -> bytes:
    if mode == "ctr":
        return aes_ctr_cipher(key, iv, little_endian=little_endian).decrypt(data)
    if mode == "cfb1":
        return aes_cfb1_cipher(key, iv).decrypt(data)
    if mode in ("cfb", "cfb8"):
        segment = {"cfb": 128, "cfb8": 8}[mode]
        return aes_cfb_cipher(key, iv, segment_size=segment).decrypt(data)
    if mode == "ofb":
        return aes_ofb_cipher(key, iv).decrypt(data)
    raise ValueError(f"not a stream mode: {mode}")


class OpenSSLArtifact(Artifact):
    format_name = "openssl"
    display_name = "OpenSSL enc"

    def __init__(
        self,
        path: str | Path,
        options,
        *,
        policy: Optional[ValidationPolicy] = None,
    ) -> None:
        path = Path(path)
        layout = _load_layout(path, options)
        super().__init__(path, path.stat().st_size)
        self.options = options
        self.layout = layout
        self.policy = policy or ValidationPolicy()
        self.cipher = layout.cipher
        self.salt = layout.salt
        self.ciphertext_offset = layout.ciphertext_offset
        self.ciphertext_length = layout.ciphertext_length
        self._payload = layout.payload
        self.source_encoding = layout.source_encoding
        self.first_ct: bytes = b""
        self.last_ct: bytes = b""
        self.previous_ct: Optional[bytes] = None

        if self.cipher is not None:
            probe_len = max(PROBE_SIZE, len(self.policy.known_prefix))
            probe_len = min(probe_len, self.ciphertext_length)
            if self.cipher.mode in ("cbc", "ecb"):
                if probe_len:
                    probe_len = (
                        (probe_len + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE
                    ) * AES_BLOCK_SIZE
                    probe_len = min(probe_len, self.ciphertext_length)
                if probe_len == 0 and self.ciphertext_length:
                    probe_len = AES_BLOCK_SIZE
            self.first_ct = self.read_ciphertext(0, probe_len)
            if self.cipher.mode in ("cbc", "ecb"):
                if self.ciphertext_length >= AES_BLOCK_SIZE:
                    self.last_ct = self.read_ciphertext(
                        self.ciphertext_length - AES_BLOCK_SIZE, AES_BLOCK_SIZE
                    )
                else:
                    self.last_ct = b""
                if self.ciphertext_length >= 2 * AES_BLOCK_SIZE:
                    self.previous_ct = self.read_ciphertext(
                        self.ciphertext_length - 2 * AES_BLOCK_SIZE, AES_BLOCK_SIZE
                    )
                else:
                    self.previous_ct = None
            else:
                self.last_ct = b""
                self.previous_ct = None
        else:
            self.first_ct = b""
            self.last_ct = b""
            self.previous_ct = None

    # -- ciphertext access -------------------------------------------------

    def read_ciphertext(self, offset: int, length: int) -> bytes:
        if length <= 0 or offset < 0:
            return b""
        if self._payload is not None:
            start = self.ciphertext_offset + offset
            return self._payload[start : start + length]
        return _read_at(self.path, self.ciphertext_offset + offset, length)

    def iter_ciphertext(self, chunk_size: int = DEFAULT_BUFFER) -> Iterator[bytes]:
        offset = 0
        while offset < self.ciphertext_length:
            chunk = self.read_ciphertext(offset, min(chunk_size, self.ciphertext_length - offset))
            if not chunk:
                raise DecryptionError("unexpected end of OpenSSL ciphertext")
            offset += len(chunk)
            yield chunk

    # -- inspection --------------------------------------------------------

    def inspect(self) -> dict:
        cipher = self.cipher
        mode = cipher.mode if cipher else None
        block_ok = self.ciphertext_length % AES_BLOCK_SIZE == 0 if mode in ("cbc", "ecb") else None
        result: dict[str, Any] = {
            "format": "openssl-enc",
            "display_name": "OpenSSL enc"
            + (" (base64)" if self.source_encoding == "base64" else ""),
            "salt": self.salt.hex() if self.salt else None,
            "salted": bool(self.salt),
            "ciphertext_offset": self.ciphertext_offset,
            "ciphertext_bytes": self.ciphertext_length,
            "ciphertext_blocks": self.ciphertext_length // AES_BLOCK_SIZE,
            "ciphertext_block_aligned": block_ok,
            "file_encoding": self.source_encoding,
            "cipher": cipher.name if cipher else None,
            "mode": mode,
            "digest": self.layout.digest,
            "kdf": (
                f"PBKDF2-HMAC-{self.layout.digest.upper()}, {self.layout.iterations} iterations"
                if self.layout.pbkdf2
                else f"EVP_BytesToKey({self.layout.digest.upper()}), 1 iteration"
            ),
            "authentication": "none",
            "padding": "none (--openssl-nopad)" if self.layout.nopad else "PKCS#7",
            "structural_status": "valid",
            "notes": [
                "OpenSSL enc does not store the cipher or digest; both were supplied on the command line.",
                "OpenSSL enc is not authenticated. PKCS#7 padding is weak evidence and CTR/CFB/OFB have no verification at all without a known prefix.",
            ],
        }
        if cipher is None:
            result["notes"].insert(
                0, "No --openssl-cipher was supplied, so block structure was not validated."
            )
        return result

    # -- cracking ----------------------------------------------------------

    def verifier(self, policy: ValidationPolicy) -> Verifier:
        cipher = self.require_cipher()
        if policy.has_prefix and len(policy.known_prefix) < MIN_CONFIRM_PREFIX:
            raise UsageError(
                f"known prefix is only {len(policy.known_prefix)} bytes; "
                f"at least {MIN_CONFIRM_PREFIX} are required for confirmation",
                hint="a short prefix is matched by too many wrong keys; supply more known plaintext",
            )
        if policy.mode == "strict" and not policy.has_prefix:
            raise UsageError(
                "--policy strict needs --known-prefix for openssl enc files",
                hint="openssl enc has no MAC; only an exact plaintext oracle can confirm a key",
            )
        if cipher.mode in ("cbc", "ecb") and self.layout.nopad and policy.mode == "any":
            raise UsageError(
                "--policy any requires PKCS#7 padding; this file has none (-nopad)",
                hint="supply a known prefix, or use --policy auto/text/magic for a heuristic",
            )
        if cipher.mode in ("ctr", "cfb", "cfb1", "cfb8", "ofb") and not policy.has_prefix:
            raise UsageError(
                f"{cipher.mode.upper()} has no padding and openssl enc has no MAC",
                hint="supply --known-prefix (for example the first bytes of the plaintext) to verify candidates",
            )

        if policy.has_prefix:
            if cipher.mode in ("cbc", "ecb"):
                plain_limit = (
                    self.ciphertext_length if self.layout.nopad else self.ciphertext_length - 1
                )
            else:
                plain_limit = self.ciphertext_length
            if len(policy.known_prefix) > plain_limit:
                raise UsageError(
                    f"known prefix is {len(policy.known_prefix)} bytes but the plaintext "
                    f"can be at most {plain_limit} bytes"
                )
        if cipher.mode in ("cbc", "ecb"):
            if self.ciphertext_length < AES_BLOCK_SIZE:
                raise FormatError("ciphertext is too short for a block cipher")
            if self.ciphertext_length % AES_BLOCK_SIZE:
                raise FormatError("ciphertext is not a multiple of the AES block size")
        return OpenSSLVerifier(
            cipher_name=cipher.name,
            key_len=cipher.key_len,
            mode=cipher.mode,
            digest=self.layout.digest,
            use_pbkdf2=self.layout.pbkdf2,
            iterations=self.layout.iterations,
            salt=self.salt,
            first_ct=self.first_ct,
            ciphertext_length=self.ciphertext_length,
            last_ct=self.last_ct,
            previous_ct=self.previous_ct,
            policy=policy,
            nopad=self.layout.nopad,
        )

    def require_cipher(self) -> CipherSpec:
        if self.cipher is None:
            raise UsageError(
                "OpenSSL enc files do not record their cipher",
                hint="pass --openssl-cipher (for example aes-256-cbc) and --openssl-digest (default sha256)",
            )
        return self.cipher

    # -- decryption --------------------------------------------------------

    def decrypt(self, password: bytes, handle: BinaryIO) -> DecryptReport:
        cipher = self.require_cipher()
        key, iv = _derive(
            password,
            self.salt,
            cipher.key_len,
            cipher.iv_len,
            self.layout.digest,
            self.layout.pbkdf2,
            self.layout.iterations,
        )
        prefix = self.policy.known_prefix
        if prefix and len(prefix) < MIN_CONFIRM_PREFIX:
            raise UsageError(
                f"known prefix is only {len(prefix)} bytes; "
                f"at least {MIN_CONFIRM_PREFIX} are required for a meaningful check"
            )
        seen = b""

        def emit(plaintext: bytes) -> int:
            nonlocal seen
            if len(seen) < len(prefix):
                seen += plaintext[: len(prefix) - len(seen)]
            if plaintext:
                handle.write(plaintext)
                return len(plaintext)
            return 0

        written = 0
        if cipher.mode in ("ctr", "cfb", "cfb1", "cfb8", "ofb"):
            decryptor = _stream_cipher(cipher.mode, key, iv)
            for chunk in self.iter_ciphertext():
                written += emit(decryptor.decrypt(chunk))
            padding_valid = None
        elif self.ciphertext_length == 0 and self.layout.nopad:
            padding_valid = None
        else:
            decryptor = (
                AES.new(key, AES.MODE_ECB)
                if cipher.mode == "ecb"
                else AES.new(key, AES.MODE_CBC, iv=iv)
            )
            remaining = self.ciphertext_length
            offset = 0
            while remaining > AES_BLOCK_SIZE:
                size = min(DEFAULT_BUFFER, remaining - AES_BLOCK_SIZE)
                size -= size % AES_BLOCK_SIZE
                block = self.read_ciphertext(offset, size)
                offset += size
                remaining -= size
                written += emit(decryptor.decrypt(block))
            final = self.read_ciphertext(offset, AES_BLOCK_SIZE)
            if len(final) != AES_BLOCK_SIZE:
                raise DecryptionError("unexpected end of OpenSSL ciphertext")
            final_plain = decryptor.decrypt(final)
            if self.layout.nopad:
                written += emit(final_plain)
                padding_valid = None
            else:
                unpadded = pkcs7_unpad(final_plain)
                written += emit(unpadded)
                padding_valid = True

        if len(seen) < len(prefix):
            raise DecryptionError(
                "plaintext is shorter than the supplied known prefix; wrong key or wrong cipher"
            )
        if prefix and not hmac.compare_digest(seen[: len(prefix)], prefix):
            raise DecryptionError(
                "known plaintext prefix does not match: wrong password, cipher, digest, or KDF parameters"
            )

        verification = (
            "known plaintext prefix matched; OpenSSL enc provides no authentication"
            if prefix
            else "none (OpenSSL enc has no authentication)"
        )
        return DecryptReport(
            format_name=self.format_name,
            output=None,
            bytes_written=written,
            verification=verification,
            details={
                "cipher": cipher.name,
                "kdf": (
                    f"PBKDF2-HMAC-{self.layout.digest.upper()}/{self.layout.iterations}"
                    if self.layout.pbkdf2
                    else f"EVP_BytesToKey-{self.layout.digest.upper()}"
                ),
                "salt": self.salt.hex() if self.salt else None,
                "padding_valid": padding_valid,
                "prefix_checked": bool(prefix),
                "authenticated": False,
                "plaintext_bytes": written,
                "source_encoding": self.source_encoding,
            },
        )

    def default_decrypted_name(self) -> str:
        name = self.path.name
        for suffix in (".enc", ".aes"):
            if name.lower().endswith(suffix):
                return name[: -len(suffix)]
        return name + ".dec"


def _stream_cipher(mode: str, key: bytes, iv: bytes):
    if mode == "ctr":
        return aes_ctr_cipher(key, iv)
    if mode == "cfb1":
        return aes_cfb1_cipher(key, iv)
    if mode in ("cfb", "cfb8"):
        segment = {"cfb": 128, "cfb8": 8}[mode]
        return aes_cfb_cipher(key, iv, segment_size=segment)
    if mode == "ofb":
        return aes_ofb_cipher(key, iv)
    raise ValueError(f"not a stream mode: {mode}")


# ---------------------------------------------------------------------------
# Encryption (compatibility fixtures and lab data)
# ---------------------------------------------------------------------------


def encrypt_stream(
    source: BinaryIO,
    destination: BinaryIO,
    password: bytes,
    *,
    cipher_name: str,
    digest: str = "sha256",
    use_pbkdf2: bool = False,
    iterations: int = 10000,
    salted: bool = True,
    salt: Optional[bytes] = None,
    nopad: bool = False,
    buffer_size: int = DEFAULT_BUFFER,
) -> None:
    cipher = parse_cipher(cipher_name)
    if cipher.mode == "gcm":
        raise UnsupportedError("openssl enc does not produce AES-GCM files")
    if nopad and cipher.mode not in ("cbc", "ecb"):
        raise UsageError("openssl -nopad only applies to CBC/ECB modes")
    digest = normalize_digest(digest)
    if use_pbkdf2 and iterations < 1:
        raise UsageError("PBKDF2 iterations must be at least 1")
    if buffer_size % AES_BLOCK_SIZE:
        raise ValueError("buffer size must be a multiple of 16")

    if salt is None:
        salt = random_bytes(SALT_LENGTH) if salted else b""
    if salted:
        if len(salt) != SALT_LENGTH:
            raise ValueError("OpenSSL salt must be exactly 8 bytes")
        destination.write(SALTED_MAGIC)
        destination.write(salt)
    elif salt:
        raise ValueError("a salt was supplied with salted=False")

    key, iv = _derive(
        password,
        salt,
        cipher.key_len,
        cipher.iv_len,
        digest,
        use_pbkdf2,
        iterations,
    )

    if cipher.mode in ("cbc", "ecb"):
        encryptor = (
            AES.new(key, AES.MODE_ECB)
            if cipher.mode == "ecb"
            else AES.new(key, AES.MODE_CBC, iv=iv)
        )
        pending = b""
        while True:
            chunk = _read_full(source, buffer_size)
            if not chunk:
                break
            pending += chunk
            while len(pending) >= buffer_size:
                block = pending[:buffer_size]
                destination.write(encryptor.encrypt(block))
                pending = pending[buffer_size:]
        if nopad:
            if len(pending) % AES_BLOCK_SIZE:
                raise UsageError(
                    "openssl -nopad requires the plaintext length to be a multiple of 16"
                )
            if pending:
                destination.write(encryptor.encrypt(pending))
        else:
            destination.write(encryptor.encrypt(pkcs7_pad(pending)))
    else:
        encryptor = _stream_cipher(cipher.mode, key, iv)
        while True:
            chunk = _read_full(source, buffer_size)
            if not chunk:
                break
            destination.write(encryptor.encrypt(chunk))


def _read_full(source: BinaryIO, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = source.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def encrypt_bytes(
    plaintext: bytes,
    password: bytes,
    *,
    cipher_name: str = "aes-256-cbc",
    digest: str = "sha256",
    use_pbkdf2: bool = False,
    iterations: int = 10000,
    salted: bool = True,
    salt: Optional[bytes] = None,
    nopad: bool = False,
) -> bytes:
    source = io.BytesIO(plaintext)
    destination = io.BytesIO()
    encrypt_stream(
        source,
        destination,
        password,
        cipher_name=cipher_name,
        digest=digest,
        use_pbkdf2=use_pbkdf2,
        iterations=iterations,
        salted=salted,
        salt=salt,
        nopad=nopad,
    )
    return destination.getvalue()
