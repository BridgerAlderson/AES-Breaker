"""Explicit-spec raw AES cracking.

This module does **not** guess a mode, IV, or KDF.  A JSON spec
describes one exact scheme, and a real verification oracle must be supplied:

* ``known_prefix`` -- at least 8 known plaintext bytes at offset 0 (confirmed);
* ``known_block``  -- one full known 16-byte plaintext block at a block-aligned
  offset for CBC/ECB (confirmed);
* ``gcm_tag``      -- a GCM authentication tag (confirmed).

If and only if ``allow_heuristic`` is true, a spec without such an oracle is
accepted and candidates can only become ``PROBABLE`` (text/magic) or ``WEAK``
(padding only).  This keeps the old 1.x "readability means success" failure out
of the tool.

Spec version 1 schema::

    {
      "version": 1,
      "cipher": "aes-256-cbc",
      "input_encoding": "base64",
      "ciphertext_offset": 32,
      "ciphertext_length": null,
      "ctr_little_endian": false,
      "kdf": {
        "type": "pbkdf2",
        "digest": "sha256",
        "iterations": 10000,
        "salt_hex": "0011223344556677",
        "password_encoding": "raw"
      },
      "iv": {"source": "explicit", "hex": "..."},
      "padding": "pkcs7",
      "oracle": {"type": "known_prefix", "hex": "7b2276657273696f6e223a"},
      "allow_heuristic": false
    }

Salt and IV can also be read from the decoded payload with ``salt_offset`` /
``salt_length`` and ``iv.offset`` / ``iv.length``.  A GCM tag can be supplied
as ``tag_hex`` or read from the payload with ``tag_offset`` / ``tag_length``.
"""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Optional

from Crypto.Cipher import AES

from ..crypto import (
    AES_BLOCK_SIZE,
    CipherSpec,
    aes_cbc_encrypt,
    aes_cfb1_cipher,
    aes_cfb_cipher,
    aes_ctr_cipher,
    aes_ecb_decrypt_block,
    aes_gcm_encrypt,
    aes_ofb_cipher,
    parse_cipher,
    pkcs7_pad,
    pkcs7_unpad,
    pkcs7_valid_last_block,
    xor_bytes,
)
from ..errors import DecryptionError, FormatError, InputError, UsageError
from ..kdf import evp_bytes_to_key, hkdf, normalize_digest, pbkdf2
from ..signatures import assess_plaintext
from ..util import decode_encoded_bytes, parse_hex_data, random_bytes, read_file
from .base import (
    MIN_CONFIRM_PREFIX,
    Artifact,
    DecryptReport,
    Outcome,
    ValidationPolicy,
    Verifier,
)
from .raw import RawSpec, decrypt_stream

SUPPORTED_MODES = ("cbc", "ecb", "ctr", "cfb", "cfb1", "cfb8", "ofb", "gcm")
PASSWORD_ENCODINGS = ("raw", "utf-8", "utf-16-le", "utf-16-be")
INPUT_ENCODINGS = ("raw", "hex", "base64")
ORACLE_TYPES = ("known_prefix", "known_block", "gcm_tag")

_TOP_KEYS = {
    "version",
    "cipher",
    "input_encoding",
    "ciphertext_offset",
    "ciphertext_length",
    "ctr_little_endian",
    "kdf",
    "iv",
    "padding",
    "oracle",
    "allow_heuristic",
}
_KDF_KEYS = {
    "type",
    "digest",
    "iterations",
    "salt_hex",
    "salt_offset",
    "salt_length",
    "password_encoding",
    "n",
    "r",
    "p",
    "info_hex",
    "time_cost",
    "memory_cost",
    "parallelism",
}
_IV_KEYS = {"source", "hex", "offset", "length"}
_ORACLE_KEYS = {
    "type",
    "hex",
    "offset",
    "tag_hex",
    "tag_offset",
    "tag_length",
    "aad_hex",
}


def _kdf_label(config: CustomConfig) -> str:
    if config.kdf_kind == "pbkdf2":
        return f"PBKDF2-HMAC-{config.digest.upper()} ({config.iterations} iterations)"
    if config.kdf_kind == "evp":
        return f"EVP_BytesToKey({config.digest.upper()}, 1 iteration)"
    if config.kdf_kind == "scrypt":
        return (
            "scrypt "
            f"(N={config.kdf_params['n']}, r={config.kdf_params['r']}, "
            f"p={config.kdf_params['p']})"
        )
    if config.kdf_kind == "hkdf":
        return f"HKDF-HMAC-{config.digest.upper()}"
    if config.kdf_kind == "argon2":
        return (
            "Argon2id "
            f"(t={config.kdf_params['time_cost']}, "
            f"m={config.kdf_params['memory_cost']}, "
            f"p={config.kdf_params['parallelism']})"
        )
    return config.kdf_kind


def _spec_error(message: str) -> FormatError:
    return FormatError(f"custom spec: {message}")


def _mapping(value: Any, what: str) -> dict:
    if not isinstance(value, dict):
        raise _spec_error(f"{what} must be a JSON object")
    return value


def _check_keys(mapping: dict, allowed: set[str], what: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise _spec_error(f"unknown {what} key(s): {', '.join(unknown)}")


def _string(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise _spec_error(f"{what} must be a non-empty string")
    return value


def _bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise _spec_error(f"{what} must be true or false")
    return value


def _integer(value: Any, what: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _spec_error(f"{what} must be an integer")
    if value < minimum:
        raise _spec_error(f"{what} must be at least {minimum}")
    return value


def _hex(value: Any, what: str) -> bytes:
    text = _string(value, what)
    try:
        return parse_hex_data(text, what=what)
    except InputError as exc:
        raise _spec_error(str(exc)) from None


def _slice(payload: bytes, offset: int, length: int, what: str) -> bytes:
    if offset < 0 or length < 0 or offset + length > len(payload):
        raise _spec_error(
            f"{what} range {offset}..{offset + length} is outside the "
            f"{len(payload)}-byte decoded payload"
        )
    return payload[offset : offset + length]


@dataclass(frozen=True)
class CustomConfig:
    cipher: CipherSpec
    payload_size: int
    input_encoding: str
    ciphertext_offset: int
    ciphertext: bytes
    salt: bytes
    kdf_kind: str
    digest: str
    iterations: int
    kdf_params: dict[str, Any]
    password_encoding: str
    iv_source: str
    iv_value: bytes
    iv_length: int
    padding: str
    ctr_little_endian: bool
    oracle_type: Optional[str]
    oracle_value: bytes
    oracle_offset: int
    tag: bytes
    aad: bytes
    allow_heuristic: bool

    @property
    def needs_derived_iv(self) -> bool:
        return self.iv_source == "derived"

    @property
    def kdf_output_length(self) -> int:
        extra = self.iv_length if self.needs_derived_iv else 0
        return self.cipher.key_len + extra

    def password_bytes(self, candidate: bytes) -> Optional[bytes]:
        if self.password_encoding == "raw":
            return candidate
        try:
            text = candidate.decode("utf-8")
        except UnicodeDecodeError:
            return None
        try:
            if self.password_encoding == "utf-8":
                return text.encode("utf-8")
            if self.password_encoding == "utf-16-le":
                return text.encode("utf-16-le")
            if self.password_encoding == "utf-16-be":
                return text.encode("utf-16-be")
        except UnicodeEncodeError:
            return None
        return None

    def derive(self, candidate: bytes) -> Optional[tuple[bytes, bytes]]:
        password = self.password_bytes(candidate)
        if password is None:
            return None
        wanted = self.kdf_output_length
        try:
            if self.kdf_kind == "pbkdf2":
                material = pbkdf2(
                    password,
                    self.salt,
                    self.iterations,
                    wanted,
                    digest=self.digest,
                )
                key = material[: self.cipher.key_len]
                if self.needs_derived_iv:
                    return key, material[self.cipher.key_len : wanted]
                return key, self.iv_value
            if self.kdf_kind == "evp":
                key, derived_iv = evp_bytes_to_key(
                    password,
                    self.salt,
                    self.cipher.key_len,
                    self.iv_length if self.needs_derived_iv else 0,
                    digest=self.digest,
                )
                return key, derived_iv if self.needs_derived_iv else self.iv_value
            if self.kdf_kind == "scrypt":
                material = hashlib.scrypt(
                    password,
                    salt=self.salt,
                    n=int(self.kdf_params["n"]),
                    r=int(self.kdf_params["r"]),
                    p=int(self.kdf_params["p"]),
                    dklen=wanted,
                )
            elif self.kdf_kind == "hkdf":
                material = hkdf(
                    password,
                    self.salt,
                    self.kdf_params.get("info", b""),
                    wanted,
                    digest=self.digest,
                )
            elif self.kdf_kind == "argon2":
                from argon2.low_level import Type, hash_secret_raw

                material = hash_secret_raw(
                    secret=password,
                    salt=self.salt,
                    time_cost=int(self.kdf_params["time_cost"]),
                    memory_cost=int(self.kdf_params["memory_cost"]),
                    parallelism=int(self.kdf_params["parallelism"]),
                    hash_len=wanted,
                    type=Type.ID,
                )
            else:
                return None
        except Exception:
            return None
        key = material[: self.cipher.key_len]
        if self.needs_derived_iv:
            return key, material[self.cipher.key_len : wanted]
        return key, self.iv_value


def _resolve_salt(kdf: dict, payload: bytes) -> bytes:
    has_hex = "salt_hex" in kdf
    has_offset = "salt_offset" in kdf or "salt_length" in kdf
    if has_hex and has_offset:
        raise _spec_error("kdf.salt_hex and kdf.salt_offset are mutually exclusive")
    if has_hex:
        return _hex(kdf["salt_hex"], "kdf.salt_hex")
    if has_offset:
        if "salt_offset" not in kdf or "salt_length" not in kdf:
            raise _spec_error("kdf.salt_offset and kdf.salt_length must be used together")
        offset = _integer(kdf["salt_offset"], "kdf.salt_offset")
        length = _integer(kdf["salt_length"], "kdf.salt_length", minimum=1)
        return _slice(payload, offset, length, "kdf salt")
    return b""


def _resolve_iv(
    iv_data: Optional[dict], cipher: CipherSpec, payload: bytes
) -> tuple[str, bytes, int]:
    if cipher.mode == "ecb":
        if iv_data is not None:
            raise _spec_error("ECB does not use an IV")
        return "none", b"", 0
    if iv_data is None:
        raise _spec_error(f"{cipher.mode.upper()} requires an iv object")
    iv_data = _mapping(iv_data, "iv")
    _check_keys(iv_data, _IV_KEYS, "iv")
    source = _string(iv_data.get("source"), "iv.source")
    if source not in ("explicit", "zero", "derived", "embedded"):
        raise _spec_error("iv.source must be explicit, zero, derived, or embedded")
    default_length = 12 if cipher.mode == "gcm" else AES_BLOCK_SIZE
    if source == "explicit":
        if "hex" not in iv_data:
            raise _spec_error("iv.hex is required for source=explicit")
        if "offset" in iv_data or "length" in iv_data:
            raise _spec_error("iv.hex cannot be combined with iv.offset/iv.length")
        value = _hex(iv_data["hex"], "iv.hex")
        _validate_iv_length(len(value), cipher)
        return source, value, len(value)
    if source == "embedded":
        if "offset" not in iv_data or "length" not in iv_data:
            raise _spec_error("iv.offset and iv.length are required for source=embedded")
        if "hex" in iv_data:
            raise _spec_error("iv.offset cannot be combined with iv.hex")
        offset = _integer(iv_data["offset"], "iv.offset")
        length = _integer(iv_data["length"], "iv.length", minimum=1)
        _validate_iv_length(length, cipher)
        return source, _slice(payload, offset, length, "iv"), length
    if "hex" in iv_data or "offset" in iv_data:
        raise _spec_error(f"iv source={source} does not take iv.hex/iv.offset")
    length = default_length
    if "length" in iv_data:
        length = _integer(iv_data["length"], "iv.length", minimum=1)
    _validate_iv_length(length, cipher)
    return source, b"\x00" * length if source == "zero" else b"", length


def _validate_iv_length(length: int, cipher: CipherSpec) -> None:
    if cipher.mode == "gcm":
        if not 1 <= length <= 64:
            raise _spec_error("GCM nonce length must be between 1 and 64 bytes")
    elif length != AES_BLOCK_SIZE:
        raise _spec_error(f"{cipher.mode.upper()} IV must be exactly 16 bytes")


def _parse_oracle(
    oracle_data: Any, cipher: CipherSpec, payload: bytes, allow_heuristic: bool
) -> tuple[Optional[str], bytes, int, bytes, bytes]:
    """Return (type, value, offset, gcm_tag, aad)."""
    if oracle_data is None:
        if cipher.mode == "gcm":
            raise _spec_error("GCM requires a gcm_tag oracle")
        if not allow_heuristic:
            raise _spec_error(
                "a verification oracle is required; set allow_heuristic=true "
                "only if text/magic evidence is acceptable"
            )
        return None, b"", 0, b"", b""
    oracle = _mapping(oracle_data, "oracle")
    _check_keys(oracle, _ORACLE_KEYS, "oracle")
    kind = _string(oracle.get("type"), "oracle.type")
    if kind not in ORACLE_TYPES:
        raise _spec_error("oracle.type must be known_prefix, known_block, or gcm_tag")
    if cipher.mode == "gcm" and kind != "gcm_tag":
        raise _spec_error("GCM requires a gcm_tag oracle (not a plaintext prefix/block)")
    if kind != "gcm_tag" and cipher.mode == "gcm":
        raise _spec_error("gcm_tag oracle is only valid for GCM")

    if kind == "known_prefix":
        if any(
            key in oracle for key in ("offset", "tag_hex", "tag_offset", "tag_length", "aad_hex")
        ):
            raise _spec_error("known_prefix only accepts oracle.hex; tag/AAD fields are not used")
        if "hex" not in oracle:
            raise _spec_error("known_prefix requires oracle.hex")
        value = _hex(oracle["hex"], "oracle.hex")
        if len(value) < MIN_CONFIRM_PREFIX:
            raise _spec_error(f"known prefix must be at least {MIN_CONFIRM_PREFIX} bytes")
        return kind, value, 0, b"", b""

    if kind == "known_block":
        if cipher.mode not in ("cbc", "ecb"):
            raise _spec_error("known_block is only supported for CBC and ECB")
        if any(key in oracle for key in ("tag_hex", "tag_offset", "tag_length", "aad_hex")):
            raise _spec_error("known_block only accepts oracle.hex and oracle.offset")
        if "hex" not in oracle or "offset" not in oracle:
            raise _spec_error("known_block requires oracle.hex and oracle.offset")
        value = _hex(oracle["hex"], "oracle.hex")
        if len(value) != AES_BLOCK_SIZE:
            raise _spec_error("known_block must be exactly 16 bytes")
        offset = _integer(oracle["offset"], "oracle.offset")
        if offset % AES_BLOCK_SIZE:
            raise _spec_error("known_block offset must be a multiple of 16")
        return kind, value, offset, b"", b""

    # gcm_tag
    if cipher.mode != "gcm":
        raise _spec_error("gcm_tag oracle is only valid for GCM")
    if "hex" in oracle or "offset" in oracle:
        raise _spec_error("gcm_tag accepts tag_hex/tag_offset/tag_length, not oracle.hex/offset")
    has_hex = "tag_hex" in oracle
    has_offset = "tag_offset" in oracle or "tag_length" in oracle
    if has_hex and has_offset:
        raise _spec_error("oracle.tag_hex and oracle.tag_offset are mutually exclusive")
    if has_hex:
        tag = _hex(oracle["tag_hex"], "oracle.tag_hex")
        tag_offset = -1
    elif has_offset:
        if "tag_offset" not in oracle or "tag_length" not in oracle:
            raise _spec_error("oracle.tag_offset and oracle.tag_length must be used together")
        tag_offset = _integer(oracle["tag_offset"], "oracle.tag_offset")
        tag_length = _integer(oracle["tag_length"], "oracle.tag_length", minimum=1)
        tag = _slice(payload, tag_offset, tag_length, "GCM tag")
    else:
        raise _spec_error("GCM requires oracle.tag_hex or oracle.tag_offset/tag_length")
    if not 8 <= len(tag) <= 16:
        raise _spec_error(
            "GCM tag must be between 8 and 16 bytes; shorter tags cannot confirm a password"
        )
    aad = _hex(oracle["aad_hex"], "oracle.aad_hex") if "aad_hex" in oracle else b""
    return kind, b"", tag_offset, tag, aad


def parse_spec(document: Any, payload: bytes) -> CustomConfig:
    document = _mapping(document, "spec")
    _check_keys(document, _TOP_KEYS, "top-level")
    version = document.get("version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        raise _spec_error(f"unsupported spec version {version!r}; expected 1")
    cipher = parse_cipher(_string(document.get("cipher"), "cipher"))
    if cipher.mode not in SUPPORTED_MODES:
        raise _spec_error(
            f"custom specs support {', '.join(SUPPORTED_MODES)}; "
            f"{cipher.mode.upper()} is not available"
        )
    input_encoding = document.get("input_encoding", "base64")
    if input_encoding not in INPUT_ENCODINGS:
        raise _spec_error("input_encoding must be raw, hex, or base64")

    ciphertext_offset = _integer(document.get("ciphertext_offset", 0), "ciphertext_offset")
    ctr_little_endian = _bool(document.get("ctr_little_endian", False), "ctr_little_endian")
    if ctr_little_endian and cipher.mode != "ctr":
        raise _spec_error("ctr_little_endian only applies to CTR")

    kdf = _mapping(document.get("kdf"), "kdf")
    _check_keys(kdf, _KDF_KEYS, "kdf")
    kdf_kind = _string(kdf.get("type"), "kdf.type")
    if kdf_kind not in ("pbkdf2", "evp", "scrypt", "hkdf", "argon2"):
        raise _spec_error("kdf.type must be pbkdf2, evp, scrypt, hkdf, or argon2")
    kdf_params: dict[str, Any] = {}
    if kdf_kind in ("pbkdf2", "evp", "hkdf"):
        digest = normalize_digest(_string(kdf.get("digest", "sha256"), "kdf.digest"))
    else:
        if "digest" in kdf:
            raise _spec_error(f"kdf.digest is not used by {kdf_kind}")
        digest = "sha256"
    if kdf_kind == "pbkdf2":
        iterations = _integer(kdf.get("iterations", 10000), "kdf.iterations", minimum=1)
    else:
        if "iterations" in kdf:
            raise _spec_error(f"kdf.iterations does not apply to {kdf_kind}")
        iterations = 0
    if kdf_kind == "scrypt":
        if "n" not in kdf or "r" not in kdf or "p" not in kdf:
            raise _spec_error("scrypt requires kdf.n, kdf.r, and kdf.p")
        n = _integer(kdf["n"], "kdf.n", minimum=2)
        r = _integer(kdf["r"], "kdf.r", minimum=1)
        p = _integer(kdf["p"], "kdf.p", minimum=1)
        if n & (n - 1):
            raise _spec_error("kdf.n must be a power of two")
        if n > (1 << 20):
            raise _spec_error("kdf.n is unreasonably large")
        if 128 * n * r > (1 << 30):
            raise _spec_error("scrypt memory cost exceeds 1 GiB")
        kdf_params = {"n": n, "r": r, "p": p}
    elif kdf_kind == "hkdf":
        kdf_params = {"info": (_hex(kdf["info_hex"], "kdf.info_hex") if "info_hex" in kdf else b"")}
    elif kdf_kind == "argon2":
        try:
            import argon2  # noqa: F401
        except ImportError:
            raise _spec_error("argon2 specs require the optional argon2-cffi package") from None
        kdf_params = {
            "time_cost": _integer(kdf.get("time_cost", 3), "kdf.time_cost", minimum=1),
            "memory_cost": _integer(kdf.get("memory_cost", 65536), "kdf.memory_cost", minimum=8),
            "parallelism": _integer(kdf.get("parallelism", 4), "kdf.parallelism", minimum=1),
        }
    password_encoding = kdf.get("password_encoding", "raw")
    if password_encoding not in PASSWORD_ENCODINGS:
        raise _spec_error("kdf.password_encoding must be raw, utf-8, utf-16-le, or utf-16-be")
    salt = _resolve_salt(kdf, payload)

    allow_heuristic = _bool(document.get("allow_heuristic", False), "allow_heuristic")
    iv_source, iv_value, iv_length = _resolve_iv(document.get("iv"), cipher, payload)
    padding = document.get("padding")
    if padding is None:
        padding = "pkcs7" if cipher.mode in ("cbc", "ecb") else "none"
    if padding not in ("pkcs7", "none"):
        raise _spec_error("padding must be pkcs7 or none")
    if cipher.mode not in ("cbc", "ecb") and padding != "none":
        raise _spec_error(f"{cipher.mode.upper()} requires padding=none")
    if cipher.mode in ("cbc", "ecb") and padding not in ("pkcs7", "none"):
        raise _spec_error("block modes use pkcs7 or none padding")

    oracle_type, oracle_value, oracle_offset, tag, aad = _parse_oracle(
        document.get("oracle"), cipher, payload, allow_heuristic
    )

    if "ciphertext_length" in document and document["ciphertext_length"] is not None:
        ciphertext_length = _integer(document["ciphertext_length"], "ciphertext_length")
    elif (
        cipher.mode == "gcm"
        and oracle_type == "gcm_tag"
        and tag
        and "tag_offset" in (document.get("oracle") or {})
    ):
        tag_offset = oracle_offset
        if tag_offset < ciphertext_offset:
            raise _spec_error("GCM tag_offset precedes ciphertext_offset")
        ciphertext_length = tag_offset - ciphertext_offset
    else:
        ciphertext_length = len(payload) - ciphertext_offset
    if ciphertext_offset + ciphertext_length > len(payload):
        raise _spec_error(
            "ciphertext range is outside the decoded payload "
            f"({ciphertext_offset}+{ciphertext_length} > {len(payload)})"
        )
    if ciphertext_length < 0 or (ciphertext_length == 0 and cipher.mode != "gcm"):
        raise _spec_error("ciphertext is empty")
    if cipher.mode in ("cbc", "ecb") and ciphertext_length % AES_BLOCK_SIZE:
        raise _spec_error("CBC/ECB ciphertext length must be a multiple of 16")
    ciphertext = payload[ciphertext_offset : ciphertext_offset + ciphertext_length]

    if oracle_type == "gcm_tag" and tag and "tag_offset" in (document.get("oracle") or {}):
        tag_start = oracle_offset
        tag_end = oracle_offset + len(tag)
        ct_start = ciphertext_offset
        ct_end = ciphertext_offset + ciphertext_length
        if not (tag_end <= ct_start or tag_start >= ct_end):
            raise _spec_error("GCM tag overlaps the ciphertext range")

    if oracle_type == "known_prefix":
        plain_limit = (
            ciphertext_length - 1
            if cipher.mode in ("cbc", "ecb") and padding == "pkcs7"
            else ciphertext_length
        )
        if len(oracle_value) > plain_limit:
            raise _spec_error(
                f"known prefix is {len(oracle_value)} bytes but plaintext "
                f"can be at most {plain_limit} bytes"
            )
    if oracle_type == "known_block":
        if oracle_offset + AES_BLOCK_SIZE > ciphertext_length:
            raise _spec_error("known_block offset is outside the ciphertext")

    return CustomConfig(
        cipher=cipher,
        payload_size=len(payload),
        input_encoding=input_encoding,
        ciphertext_offset=ciphertext_offset,
        ciphertext=ciphertext,
        salt=salt,
        kdf_kind=kdf_kind,
        digest=digest,
        iterations=iterations,
        kdf_params=kdf_params,
        password_encoding=password_encoding,
        iv_source=iv_source,
        iv_value=iv_value,
        iv_length=iv_length,
        padding=padding,
        ctr_little_endian=ctr_little_endian,
        oracle_type=oracle_type,
        oracle_value=oracle_value,
        oracle_offset=oracle_offset,
        tag=tag,
        aad=aad,
        allow_heuristic=allow_heuristic,
    )


def _block_plaintext(key: bytes, iv: bytes, ciphertext: bytes, index: int) -> bytes:
    block = ciphertext[index * AES_BLOCK_SIZE : (index + 1) * AES_BLOCK_SIZE]
    intermediate = aes_ecb_decrypt_block(key, block)
    if index == 0:
        return xor_bytes(intermediate, iv)
    previous = ciphertext[(index - 1) * AES_BLOCK_SIZE : index * AES_BLOCK_SIZE]
    return xor_bytes(intermediate, previous)


def _last_block(key: bytes, iv: bytes, ciphertext: bytes, ecb: bool) -> bytes:
    if ecb:
        return aes_ecb_decrypt_block(key, ciphertext[-AES_BLOCK_SIZE:])
    return _block_plaintext(key, iv, ciphertext, len(ciphertext) // AES_BLOCK_SIZE - 1)


@dataclass(frozen=True)
class CustomVerifier(Verifier):
    format_name = "custom"
    config: CustomConfig

    def describe(self) -> dict:
        c = self.config
        return {
            "format": "custom",
            "display_name": "Custom raw AES (JSON spec)",
            "cipher": c.cipher.name,
            "kdf": _kdf_label(c),
            "password_encoding": c.password_encoding,
            "salt": c.salt.hex() if c.salt else None,
            "iv_source": c.iv_source,
            "iv_bytes": c.iv_length,
            "padding": c.padding,
            "ciphertext_bytes": len(c.ciphertext),
            "oracle": c.oracle_type or "none (heuristic)",
            "oracle_bytes": len(c.oracle_value) if c.oracle_type == "known_prefix" else None,
            "known_block_offset": c.oracle_offset if c.oracle_type == "known_block" else None,
            "gcm_tag": bool(c.tag),
            "tag_offset": (
                c.oracle_offset if c.oracle_type == "gcm_tag" and c.oracle_offset >= 0 else None
            ),
            "allow_heuristic": c.allow_heuristic,
        }

    def verification_label(self) -> str:
        c = self.config
        if c.oracle_type == "known_prefix":
            return f"exact known-plaintext prefix ({len(c.oracle_value)} bytes)"
        if c.oracle_type == "known_block":
            return f"known plaintext block at offset {c.oracle_offset}"
        if c.oracle_type == "gcm_tag":
            return f"GCM tag ({len(c.tag) * 8}-bit)"
        return "heuristic only (no MAC or known plaintext)" if c.allow_heuristic else "none"

    def _decrypt_prefix(self, key: bytes, iv: bytes, length: int) -> bytes:
        c = self.config
        if c.cipher.mode == "ctr":
            return aes_ctr_cipher(key, iv, little_endian=c.ctr_little_endian).decrypt(
                c.ciphertext[:length]
            )
        if c.cipher.mode == "cfb1":
            return aes_cfb1_cipher(key, iv).decrypt(c.ciphertext[:length])
        if c.cipher.mode in ("cfb", "cfb8"):
            segment = 128 if c.cipher.mode == "cfb" else 8
            return aes_cfb_cipher(key, iv, segment_size=segment).decrypt(c.ciphertext[:length])
        if c.cipher.mode == "ofb":
            return aes_ofb_cipher(key, iv).decrypt(c.ciphertext[:length])
        take = ((length + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE) * AES_BLOCK_SIZE
        take = min(take, len(c.ciphertext))
        if c.cipher.mode == "cbc":
            plain = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(c.ciphertext[:take])
        else:  # ecb
            plain = AES.new(key, AES.MODE_ECB).decrypt(c.ciphertext[:take])
        return plain[:length]

    def verify(self, password: bytes) -> Outcome:
        c = self.config
        derived = c.derive(password)
        if derived is None:
            return Outcome.REJECT
        key, iv = derived

        try:
            if c.oracle_type == "gcm_tag":
                try:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=len(c.tag))
                    if c.aad:
                        cipher.update(c.aad)
                    cipher.decrypt_and_verify(c.ciphertext, c.tag)
                except ValueError:
                    return Outcome.REJECT
                return Outcome.CONFIRMED

            if c.oracle_type == "known_prefix":
                plain = self._decrypt_prefix(key, iv, len(c.oracle_value))
                return Outcome.CONFIRMED if plain == c.oracle_value else Outcome.REJECT

            if c.oracle_type == "known_block":
                index = c.oracle_offset // AES_BLOCK_SIZE
                if c.cipher.mode == "ecb":
                    plain = aes_ecb_decrypt_block(
                        key,
                        c.ciphertext[index * AES_BLOCK_SIZE : (index + 1) * AES_BLOCK_SIZE],
                    )
                else:
                    plain = _block_plaintext(key, iv, c.ciphertext, index)
                return Outcome.CONFIRMED if plain == c.oracle_value else Outcome.REJECT
        except Exception:
            return Outcome.REJECT

        # No oracle: heuristic evidence only.
        if not c.allow_heuristic:
            return Outcome.REJECT
        try:
            if c.cipher.mode in ("cbc", "ecb"):
                if c.padding == "pkcs7" and not pkcs7_valid_last_block(
                    _last_block(key, iv, c.ciphertext, c.cipher.mode == "ecb")
                ):
                    return Outcome.REJECT
                if len(c.ciphertext) <= 64:
                    if c.cipher.mode == "cbc":
                        probe = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(c.ciphertext)
                    else:
                        probe = AES.new(key, AES.MODE_ECB).decrypt(c.ciphertext)
                    if c.padding == "pkcs7":
                        probe = pkcs7_unpad(probe)
                else:
                    if c.cipher.mode == "cbc":
                        probe = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(c.ciphertext[:64])
                    else:
                        probe = AES.new(key, AES.MODE_ECB).decrypt(c.ciphertext[:64])
            elif c.cipher.mode == "ctr":
                probe = aes_ctr_cipher(key, iv, little_endian=c.ctr_little_endian).decrypt(
                    c.ciphertext[:64]
                )
            elif c.cipher.mode == "cfb1":
                probe = aes_cfb1_cipher(key, iv).decrypt(c.ciphertext[:64])
            elif c.cipher.mode in ("cfb", "cfb8"):
                segment = 128 if c.cipher.mode == "cfb" else 8
                probe = aes_cfb_cipher(key, iv, segment_size=segment).decrypt(c.ciphertext[:64])
            elif c.cipher.mode == "ofb":
                probe = aes_ofb_cipher(key, iv).decrypt(c.ciphertext[:64])
            else:
                return Outcome.REJECT
        except Exception:
            return Outcome.REJECT
        plausibility = assess_plaintext(probe)
        if plausibility.is_magic or plausibility.is_text:
            return Outcome.PROBABLE
        return Outcome.WEAK


class CustomArtifact(Artifact):
    format_name = "custom"
    display_name = "Custom raw AES (JSON spec)"

    def __init__(self, path: str | Path, spec_path: str | Path) -> None:
        path = Path(path)
        spec_file = Path(spec_path)
        try:
            raw_spec = spec_file.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            raise FormatError(f"cannot read custom spec {spec_file}: {exc}") from None
        try:
            document = json.loads(raw_spec)
        except json.JSONDecodeError as exc:
            raise FormatError(f"custom spec is not valid JSON: {exc}") from None
        payload = decode_encoded_bytes(
            read_file(path),
            document.get("input_encoding", "base64") if isinstance(document, dict) else "base64",
            what="custom input",
        )
        self.spec_path = spec_file
        self.config = parse_spec(document, payload)
        super().__init__(path, path.stat().st_size)

    def inspect(self) -> dict:
        c = self.config
        return {
            "format": "custom",
            "display_name": "Custom raw AES (JSON spec)",
            "spec": str(self.spec_path),
            "decoded_payload_bytes": c.payload_size,
            "input_encoding": c.input_encoding,
            "cipher": c.cipher.name,
            "kdf": _kdf_label(c),
            "password_encoding": c.password_encoding,
            "salt": c.salt.hex() if c.salt else None,
            "iv_source": c.iv_source,
            "iv_bytes": c.iv_length,
            "ciphertext_offset": c.ciphertext_offset,
            "ciphertext_bytes": len(c.ciphertext),
            "padding": c.padding,
            "ctr_little_endian": c.ctr_little_endian,
            "oracle": c.oracle_type or "none (heuristic)",
            "oracle_bytes": (len(c.oracle_value) if c.oracle_type == "known_prefix" else None),
            "oracle_offset": (c.oracle_offset if c.oracle_type == "known_block" else None),
            "gcm_tag_bytes": len(c.tag) if c.tag else None,
            "tag_offset": (
                c.oracle_offset if c.oracle_type == "gcm_tag" and c.oracle_offset >= 0 else None
            ),
            "aad_bytes": len(c.aad),
            "allow_heuristic": c.allow_heuristic,
            "structural_status": "valid",
        }

    def verifier(self, policy: ValidationPolicy) -> Verifier:
        # The spec's oracle is authoritative; CLI policy flags are rejected
        # before this point.
        return CustomVerifier(config=self.config)

    def decrypt(self, password: bytes, handle) -> DecryptReport:
        verifier = CustomVerifier(config=self.config)
        outcome = verifier.verify(password)
        if self.config.oracle_type is not None and outcome < Outcome.CONFIRMED:
            raise DecryptionError("password did not satisfy the custom spec's verification oracle")
        # With no oracle, decryption is permitted for a known password, but the
        # result is explicitly labelled unverified; RawSpec still validates
        # GCM tags and PKCS#7 padding and the CLI uses an atomic output.
        derived = self.config.derive(password)
        if derived is None:
            raise DecryptionError(
                "password cannot be encoded with the custom spec's password_encoding"
            )
        key, iv = derived
        c = self.config
        raw_spec = RawSpec(
            cipher=c.cipher,
            key=key,
            iv=b"" if c.cipher.mode == "gcm" else iv,
            nonce=iv if c.cipher.mode == "gcm" else b"",
            tag=c.tag,
            aad=c.aad,
            padding=c.padding,
            ctr_little_endian=c.ctr_little_endian,
        ).validate()
        written = decrypt_stream(io.BytesIO(c.ciphertext), handle, raw_spec)
        return DecryptReport(
            format_name=self.format_name,
            output=None,
            bytes_written=written,
            verification=verifier.verification_label(),
            details={
                "cipher": c.cipher.name,
                "kdf": _kdf_label(c),
                "oracle": c.oracle_type or "heuristic",
                "authenticated": c.oracle_type == "gcm_tag",
                "plaintext_bytes": written,
            },
        )

    def default_decrypted_name(self) -> str:
        name = self.path.name
        for suffix in (".enc", ".aes"):
            if name.lower().endswith(suffix):
                return name[: -len(suffix)]
        return name + ".dec"


def _load_spec_document(spec_path: str | Path) -> dict:
    path = Path(spec_path)
    try:
        raw = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise FormatError(f"cannot read custom spec {path}: {exc}") from None
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FormatError(f"custom spec is not valid JSON: {exc}") from None
    return _mapping(document, "spec")


def _ranges_overlap(ranges: list[tuple[str, int, int]]) -> None:
    active = [item for item in ranges if item[2] > 0]
    for index, (left_name, left_start, left_length) in enumerate(active):
        for right_name, right_start, right_length in active[index + 1 :]:
            if left_start < right_start + right_length and right_start < left_start + left_length:
                raise FormatError(f"custom writer ranges overlap: {left_name} and {right_name}")


def encrypt_document(document: dict, plaintext: bytes, password: bytes) -> bytes:
    """Create one blob from a custom spec.

    The same verification schema is used, but an oracle is not required for
    writing. Embedded salt/IV fields are generated randomly at their declared
    offsets; explicit/derived/zero IVs are used as declared. GCM requires a
    tag_offset/tag_length oracle so the generated tag has a place to go.
    """
    document = _mapping(document, "spec")
    cipher = parse_cipher(_string(document.get("cipher"), "cipher"))
    if cipher.mode not in SUPPORTED_MODES:
        raise FormatError(f"unsupported custom cipher mode: {cipher.mode}")

    kdf_doc = _mapping(document.get("kdf"), "kdf")
    iv_doc = document.get("iv")
    if cipher.mode != "ecb" and not isinstance(iv_doc, dict):
        raise FormatError("custom writer requires an iv object")

    # Build a dummy payload large enough for every declared offset, then use
    # the normal parser for all cipher/KDF/IV/padding validation.
    offsets = [int(document.get("ciphertext_offset", 0) or 0)]
    if "salt_offset" in kdf_doc:
        offsets.append(int(kdf_doc.get("salt_offset", 0)) + int(kdf_doc.get("salt_length", 0)))
    if isinstance(iv_doc, dict) and iv_doc.get("source") == "embedded":
        offsets.append(int(iv_doc.get("offset", 0)) + int(iv_doc.get("length", 0)))
    dummy_size = max(16, max(offsets) + 16)
    dummy = dict(document)
    dummy["input_encoding"] = "raw"
    dummy["ciphertext_offset"] = 0
    dummy["ciphertext_length"] = 16
    dummy["allow_heuristic"] = False
    if cipher.mode == "gcm":
        dummy["oracle"] = {"type": "gcm_tag", "tag_hex": "00" * 8}
    else:
        dummy["oracle"] = {"type": "known_prefix", "hex": "00" * 8}
    config = parse_spec(dummy, b"\x00" * dummy_size)

    salt = config.salt
    if "salt_offset" in kdf_doc:
        salt = random_bytes(int(kdf_doc["salt_length"]))
    iv = config.iv_value
    if isinstance(iv_doc, dict) and iv_doc.get("source") == "embedded":
        iv = random_bytes(int(iv_doc["length"]))
        config = replace(config, iv_value=iv)
    config = replace(config, salt=salt)
    derived = config.derive(password)
    if derived is None:
        raise UsageError("cannot derive a key from this custom spec")
    key, derived_iv = derived
    if config.iv_source == "derived":
        iv = derived_iv

    if config.padding == "pkcs7":
        padded = pkcs7_pad(plaintext)
    elif cipher.mode in ("cbc", "ecb") and len(plaintext) % AES_BLOCK_SIZE:
        raise UsageError("padding=none requires a block-aligned plaintext")
    else:
        padded = plaintext

    tag = b""
    if cipher.mode == "gcm":
        oracle = _mapping(document.get("oracle"), "oracle")
        if oracle.get("type") != "gcm_tag":
            raise FormatError("GCM writer requires a gcm_tag oracle with tag_offset")
        if "tag_offset" not in oracle or "tag_length" not in oracle:
            raise FormatError("GCM writer requires tag_offset and tag_length")
        tag_length = int(oracle["tag_length"])
        if not 8 <= tag_length <= 16:
            raise FormatError("GCM writer tag_length must be 8..16")
        aad = _hex(oracle["aad_hex"], "oracle.aad_hex") if "aad_hex" in oracle else b""
        ciphertext, full_tag = aes_gcm_encrypt(key, iv, plaintext, aad=aad)
        tag = full_tag[:tag_length]
    elif cipher.mode == "cbc":
        ciphertext = aes_cbc_encrypt(key, iv, padded)
    elif cipher.mode == "ecb":
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(padded)
    elif cipher.mode == "ctr":
        ciphertext = aes_ctr_cipher(key, iv, little_endian=config.ctr_little_endian).encrypt(
            plaintext
        )
    elif cipher.mode == "cfb1":
        ciphertext = aes_cfb1_cipher(key, iv).encrypt(plaintext)
    elif cipher.mode in ("cfb", "cfb8"):
        segment = 128 if cipher.mode == "cfb" else 8
        ciphertext = aes_cfb_cipher(key, iv, segment_size=segment).encrypt(plaintext)
    elif cipher.mode == "ofb":
        ciphertext = aes_ofb_cipher(key, iv).encrypt(plaintext)
    else:
        raise FormatError(f"unsupported custom cipher mode: {cipher.mode}")

    ct_offset = int(document.get("ciphertext_offset", 0) or 0)
    ranges: list[tuple[str, int, int]] = []
    salt_offset = None
    if "salt_offset" in kdf_doc:
        salt_offset = int(kdf_doc["salt_offset"])
        ranges.append(("salt", salt_offset, len(salt)))
    iv_offset = None
    if isinstance(iv_doc, dict) and iv_doc.get("source") == "embedded":
        iv_offset = int(iv_doc["offset"])
        ranges.append(("iv", iv_offset, len(iv)))
    ranges.append(("ciphertext", ct_offset, len(ciphertext)))
    tag_offset = None
    if tag:
        tag_offset = int(_mapping(document.get("oracle"), "oracle")["tag_offset"])
        ranges.append(("gcm_tag", tag_offset, len(tag)))
    _ranges_overlap(ranges)

    length = max(start + size for _, start, size in ranges)
    payload = bytearray(length)
    if salt_offset is not None:
        payload[salt_offset : salt_offset + len(salt)] = salt
    if iv_offset is not None:
        payload[iv_offset : iv_offset + len(iv)] = iv
    payload[ct_offset : ct_offset + len(ciphertext)] = ciphertext
    if tag_offset is not None:
        payload[tag_offset : tag_offset + len(tag)] = tag
    return bytes(payload)


def encrypt_spec_file(spec_path: str | Path, plaintext: bytes, password: bytes) -> bytes:
    document = _load_spec_document(spec_path)
    return encrypt_document(document, plaintext, password)
