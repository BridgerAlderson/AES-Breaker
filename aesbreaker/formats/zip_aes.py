"""WinZip AES (AE-1/AE-2) archive support.

For every encrypted entry the ZIP stores:

* a random salt (8, 12, or 16 bytes for AES-128/192/256),
* a 2-byte password verification value,
* AES-CTR ciphertext (128-bit little-endian counter starting at 1),
* a 10-byte truncated HMAC-SHA1 authentication code over the ciphertext.

The key material is ``PBKDF2-HMAC-SHA1(password, salt, 1000, 2*keylen + 2)``:
the first ``keylen`` bytes are the AES key, the next ``keylen`` are the HMAC
key, and the final two bytes are the password verification value.  The two
byte check is only a 1/65536 prefilter; the HMAC is the actual proof.

ZIP parsing here is independent of :mod:`zipfile` because that module refuses
AES entries.  Central-directory sizes and offsets, Zip64 fields, prepended
self-extractor data, and local-header data offsets are all handled explicitly.
"""

from __future__ import annotations

import bz2
import hashlib
import hmac
import os
import stat
import struct
import zlib
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Optional

from ..crypto import aes_ctr_cipher
from ..errors import (
    DecryptionError,
    FormatError,
    OutputError,
    UnsupportedError,
    UsageError,
)
from ..util import atomic_writer, random_bytes
from .base import Artifact, DecryptReport, Outcome, ValidationPolicy, Verifier

EOCD_SIGNATURE = 0x06054B50
ZIP64_EOCD_SIGNATURE = 0x06064B50
ZIP64_LOCATOR_SIGNATURE = 0x07064B50
CENTRAL_SIGNATURE = 0x02014B50
LOCAL_SIGNATURE = 0x04034B50
AES_EXTRA_ID = 0x9901
ZIP64_EXTRA_ID = 0x0001
AES_METHOD = 99
AES_VENDOR = b"AE"
AES_PBKDF2_ITERATIONS = 1000
AES_AUTH_CODE_LENGTH = 10
CHUNK_SIZE = 64 * 1024
DEFAULT_MAX_EXTRACT_BYTES = 8 * 1024 * 1024 * 1024
CENTRAL_DIRECTORY_LIMIT = 512 * 1024 * 1024

AES_PARAMETERS = {
    1: ("AES-128", 16, 8),
    2: ("AES-192", 24, 12),
    3: ("AES-256", 32, 16),
}
COMPRESSION_NAMES = {
    0: "stored",
    8: "deflate",
    12: "bzip2",
    14: "lzma",
    93: "zstd",
    99: "aes",
}
ENCRYPTION_NAMES = {
    "none": "none",
    "aes": "WinZip AES",
    "zipcrypto": "ZipCrypto (legacy, unsupported)",
    "other": "other/unknown",
}


@dataclass(frozen=True)
class ZipEntry:
    index: int
    raw_name: bytes
    name: str
    flags: int
    method: int
    dos_time: int
    dos_date: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int
    data_offset: int
    extra: bytes
    internal_attr: int
    external_attr: int
    aes_version: Optional[int] = None
    aes_vendor: Optional[bytes] = None
    aes_strength: Optional[int] = None
    actual_method: Optional[int] = None
    salt: bytes = b""
    pwd_verify: bytes = b""
    auth_code: bytes = b""

    @property
    def is_dir(self) -> bool:
        return self.name.endswith("/") or bool(
            self.external_attr & 0x10 and self.compressed_size == 0
        )

    @property
    def is_aes(self) -> bool:
        return self.method == AES_METHOD and self.aes_strength is not None

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def encryption(self) -> str:
        if self.is_aes:
            return "aes"
        if self.is_encrypted:
            return "zipcrypto"
        return "none"

    @property
    def aes_cipher(self) -> Optional[str]:
        if not self.is_aes:
            return None
        assert self.aes_strength is not None
        return AES_PARAMETERS[self.aes_strength][0]

    @property
    def aes_key_length(self) -> int:
        if not self.is_aes:
            return 0
        assert self.aes_strength is not None
        return AES_PARAMETERS[self.aes_strength][1]

    @property
    def aes_salt_length(self) -> int:
        if not self.is_aes:
            return 0
        assert self.aes_strength is not None
        return AES_PARAMETERS[self.aes_strength][2]

    @property
    def ciphertext_offset(self) -> int:
        if not self.is_aes:
            return self.data_offset
        return self.data_offset + self.aes_salt_length + 2

    @property
    def ciphertext_length(self) -> int:
        if not self.is_aes:
            return self.compressed_size
        return self.compressed_size - self.aes_salt_length - 2 - AES_AUTH_CODE_LENGTH

    @property
    def compression_method(self) -> int:
        if self.is_aes and self.actual_method is not None:
            return self.actual_method
        return self.method

    @property
    def compression_name(self) -> str:
        return COMPRESSION_NAMES.get(self.compression_method, f"method-{self.compression_method}")

    @property
    def unix_mode(self) -> int:
        return (self.external_attr >> 16) & 0xFFFF

    @property
    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.unix_mode)

    @property
    def utf8_name(self) -> bool:
        return bool(self.flags & 0x0800)

    def summary(self) -> dict:
        return {
            "index": self.index,
            "name": self.name,
            "encryption": self.encryption,
            "aes_version": self.aes_version,
            "aes_cipher": self.aes_cipher,
            "aes_strength": self.aes_strength,
            "compression": self.compression_name,
            "compression_method": self.compression_method,
            "flags": f"0x{self.flags:04x}",
            "crc32": f"{self.crc:08x}",
            "compressed_bytes": self.compressed_size,
            "uncompressed_bytes": self.uncompressed_size,
            "ciphertext_bytes": self.ciphertext_length if self.is_aes else None,
            "data_offset": self.data_offset,
            "utf8_name": self.utf8_name,
            "is_directory": self.is_dir,
            "is_symlink": self.is_symlink,
            "salt": self.salt.hex() if self.salt else None,
        }


@dataclass(frozen=True)
class ZipDirectory:
    entries: tuple[ZipEntry, ...]
    comment: bytes
    shift: int
    zip64: bool
    eocd_offset: int
    central_offset: int
    central_size: int


@dataclass(frozen=True)
class _Eocd:
    disk: int
    central_disk: int
    entries_disk: int
    entries_total: int
    central_size: int
    central_offset: int
    comment: bytes
    offset: int


def _read_exact(handle: BinaryIO, count: int, what: str) -> bytes:
    data = handle.read(count)
    if len(data) != count:
        raise FormatError(f"truncated ZIP {what}: wanted {count} bytes, got {len(data)}")
    return data


def _find_eocd(path: Path, size: int) -> _Eocd:
    tail_length = min(size, 22 + 0xFFFF)
    if tail_length < 22:
        raise FormatError("file is too short to be a ZIP archive")
    with path.open("rb") as handle:
        handle.seek(size - tail_length)
        tail = handle.read(tail_length)

    search_end = len(tail)
    while True:
        position = tail.rfind(b"PK\x05\x06", 0, search_end)
        if position < 0:
            break
        if position + 22 <= len(tail):
            (
                signature,
                disk,
                central_disk,
                entries_disk,
                entries_total,
                central_size,
                central_offset,
                comment_length,
            ) = struct.unpack_from("<IHHHHIIH", tail, position)
            if signature == EOCD_SIGNATURE:
                absolute = size - tail_length + position
                # A Zip64 archive may legitimately store 0xFFFFFFFF in the
                # classic EOCD fields; those sentinels must not be treated as
                # out-of-range offsets.
                central_offset_ok = central_offset == 0xFFFFFFFF or central_offset <= absolute
                central_size_ok = central_size == 0xFFFFFFFF or central_size <= absolute
                if (
                    position + 22 + comment_length <= len(tail)
                    and central_offset_ok
                    and central_size_ok
                ):
                    return _Eocd(
                        disk=disk,
                        central_disk=central_disk,
                        entries_disk=entries_disk,
                        entries_total=entries_total,
                        central_size=central_size,
                        central_offset=central_offset,
                        comment=tail[position + 22 : position + 22 + comment_length],
                        offset=absolute,
                    )
        search_end = position
    raise FormatError("not a ZIP archive: end-of-central-directory record not found")


def find_eocd_offset(path: str | Path) -> Optional[int]:
    path = Path(path)
    try:
        size = path.stat().st_size
        return _find_eocd(path, size).offset
    except (OSError, FormatError):
        return None


def _parse_zip64(path: Path, eocd: _Eocd, size: int) -> tuple[int, int, int, bool, int]:
    """Return (entries_total, central_size, central_offset, found, record_pos)."""
    locator_position = eocd.offset - 20
    if locator_position < 0:
        return eocd.entries_total, eocd.central_size, eocd.central_offset, False, -1
    with path.open("rb") as handle:
        handle.seek(locator_position)
        locator = handle.read(20)
        if len(locator) != 20:
            return eocd.entries_total, eocd.central_size, eocd.central_offset, False, -1
        signature, _, record_offset, _ = struct.unpack("<IIQI", locator)
        if signature != ZIP64_LOCATOR_SIGNATURE:
            return eocd.entries_total, eocd.central_size, eocd.central_offset, False, -1

        record_position = record_offset
        data = b""
        try:
            handle.seek(record_position)
            data = handle.read(56)
        except OSError:
            data = b""
        if len(data) < 56 or struct.unpack_from("<I", data, 0)[0] != ZIP64_EOCD_SIGNATURE:
            # The locator offset may be relative to a prepended self-extractor
            # stub, and the record may carry extensible data, so a fixed
            # "locator - 56" assumption is not enough.  Search a bounded
            # window backwards for the record signature instead.
            window_start = max(0, locator_position - (1 << 20))
            handle.seek(window_start)
            window = handle.read(locator_position - window_start)
            found = window.rfind(b"PK\x06\x06")
            if found < 0:
                raise FormatError("ZIP64 locator points outside the file")
            record_position = window_start + found
            handle.seek(record_position)
            data = _read_exact(handle, 56, "ZIP64 end-of-central-directory record")

    (
        signature,
        record_size,
        _version_made,
        _version_needed,
        _disk,
        _central_disk,
        _entries_disk,
        entries_total,
        central_size,
        central_offset,
    ) = struct.unpack_from("<IQHHIIQQQQ", data, 0)
    if signature != ZIP64_EOCD_SIGNATURE:
        raise FormatError("invalid ZIP64 end-of-central-directory record")
    if record_size < 44:
        raise FormatError("invalid ZIP64 end-of-central-directory size")
    return entries_total, central_size, central_offset, True, record_position


def _parse_extra(extra: bytes) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    position = 0
    while position + 4 <= len(extra):
        header_id, data_size = struct.unpack_from("<HH", extra, position)
        position += 4
        if position + data_size > len(extra):
            raise FormatError("truncated ZIP extra field")
        if header_id not in fields:
            fields[header_id] = extra[position : position + data_size]
        position += data_size
    return fields


def _zip64_values(
    fields: dict[int, bytes],
    compressed: int,
    uncompressed: int,
    local_offset: int,
    disk_start: int,
) -> tuple[int, int, int]:
    data = fields.get(ZIP64_EXTRA_ID)
    if data is None:
        return compressed, uncompressed, local_offset
    position = 0

    def take(count: int) -> int:
        nonlocal position
        if position + count > len(data):
            raise FormatError("truncated ZIP64 extra field")
        value = int.from_bytes(data[position : position + count], "little")
        position += count
        return value

    if uncompressed == 0xFFFFFFFF:
        uncompressed = take(8)
    if compressed == 0xFFFFFFFF:
        compressed = take(8)
    if local_offset == 0xFFFFFFFF:
        local_offset = take(8)
    if disk_start == 0xFFFF:
        take(4)
    return compressed, uncompressed, local_offset


def _decode_name(raw: bytes, flags: int) -> str:
    if flags & 0x0800:
        return raw.decode("utf-8", "replace")
    return raw.decode("cp437", "replace")


def _read_local_data_offset(
    path: Path,
    entry: ZipEntry,
    shift: int,
    size: int,
) -> tuple[int, int]:
    """Return (data_offset, local_header_position) for an entry."""
    candidates = []
    if shift:
        candidates.append(entry.local_offset + shift)
    candidates.append(entry.local_offset)
    if shift:
        candidates.append(entry.local_offset)
    last_error: Optional[Exception] = None
    for position in dict.fromkeys(candidates):
        if position < 0 or position + 30 > size:
            continue
        with path.open("rb") as handle:
            handle.seek(position)
            header = handle.read(30)
            if len(header) < 30:
                continue
            (
                signature,
                _version,
                _flags,
                _method,
                _time,
                _date,
                _crc,
                _compressed,
                _uncompressed,
                name_length,
                extra_length,
            ) = struct.unpack_from("<IHHHHHIIIHH", header, 0)
            if signature != LOCAL_SIGNATURE:
                continue
            data_offset = position + 30 + name_length + extra_length
            if data_offset + entry.compressed_size > size:
                last_error = FormatError(
                    f"ZIP entry {entry.name!r} extends past the end of the file"
                )
                continue
            return data_offset, position
    if last_error is not None:
        raise last_error
    raise FormatError(
        f"cannot locate local header for ZIP entry {entry.name!r} (offset {entry.local_offset})"
    )


def parse_zip(path: str | Path) -> ZipDirectory:
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FormatError(f"cannot read {path}: {exc}") from None
    eocd = _find_eocd(path, size)

    if eocd.disk not in (0, 0xFFFF) or eocd.central_disk not in (0, 0xFFFF):
        raise UnsupportedError("multi-disk ZIP archives are not supported")

    needs_zip64 = (
        eocd.entries_total == 0xFFFF
        or eocd.central_size == 0xFFFFFFFF
        or eocd.central_offset == 0xFFFFFFFF
    )
    if needs_zip64:
        entries_total, central_size, central_offset, zip64, zip64_position = _parse_zip64(
            path, eocd, size
        )
    else:
        entries_total = eocd.entries_total
        central_size = eocd.central_size
        central_offset = eocd.central_offset
        zip64 = False
        zip64_position = -1

    actual_central = central_offset
    shift = 0
    with path.open("rb") as handle:
        if central_size:
            handle.seek(central_offset)
            signature = handle.read(4)
            if signature != b"PK\x01\x02":
                reference = zip64_position if zip64_position >= 0 else eocd.offset
                candidate = reference - central_size
                if candidate < 0:
                    raise FormatError("ZIP central directory pointer is invalid")
                handle.seek(candidate)
                if handle.read(4) == b"PK\x01\x02":
                    actual_central = candidate
                    shift = candidate - central_offset
                else:
                    raise FormatError("ZIP central directory not found at its recorded offset")

        if central_size > CENTRAL_DIRECTORY_LIMIT:
            raise UnsupportedError("central directory is larger than the 512 MiB safety limit")
        if actual_central + central_size > eocd.offset:
            raise FormatError("ZIP central directory extends past the EOCD record")
        handle.seek(actual_central)
        central = handle.read(central_size)
        if len(central) != central_size:
            raise FormatError("truncated ZIP central directory")

    entries: list[ZipEntry] = []
    position = 0
    index = 0
    while position + 46 <= len(central):
        signature = struct.unpack_from("<I", central, position)[0]
        if signature != CENTRAL_SIGNATURE:
            break
        (
            _signature,
            _version_made,
            _version_needed,
            flags,
            method,
            dos_time,
            dos_date,
            crc,
            compressed_size,
            uncompressed_size,
            name_length,
            extra_length,
            comment_length,
            disk_start,
            internal_attr,
            external_attr,
            local_offset,
        ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", central, position)

        record_end = position + 46 + name_length + extra_length + comment_length
        if record_end > len(central):
            raise FormatError("truncated ZIP central directory entry")
        raw_name = central[position + 46 : position + 46 + name_length]
        extra = central[position + 46 + name_length : position + 46 + name_length + extra_length]
        name = _decode_name(raw_name, flags)
        fields = _parse_extra(extra)
        compressed_size, uncompressed_size, local_offset = _zip64_values(
            fields, compressed_size, uncompressed_size, local_offset, disk_start
        )

        aes_version = aes_vendor = aes_strength = actual_method = None
        aes_extra = fields.get(AES_EXTRA_ID)
        if aes_extra is not None:
            if len(aes_extra) != 7:
                raise FormatError("invalid WinZip AES extra field length")
            aes_version, aes_vendor, aes_strength, actual_method = struct.unpack(
                "<H2sBH", aes_extra
            )
            if aes_vendor != AES_VENDOR:
                raise FormatError(f"unsupported AES vendor {aes_vendor!r} in entry {name!r}")
            if aes_version not in (1, 2):
                raise FormatError(f"unsupported WinZip AES version {aes_version} in entry {name!r}")
            if aes_strength not in AES_PARAMETERS:
                raise FormatError(f"invalid WinZip AES strength {aes_strength} in entry {name!r}")
        if method == AES_METHOD and aes_extra is None:
            raise FormatError(f"ZIP entry {name!r} uses method 99 but has no AES extra field")

        entry = ZipEntry(
            index=index,
            raw_name=raw_name,
            name=name,
            flags=flags,
            method=method,
            dos_time=dos_time,
            dos_date=dos_date,
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            local_offset=local_offset,
            data_offset=0,
            extra=extra,
            internal_attr=internal_attr,
            external_attr=external_attr,
            aes_version=aes_version,
            aes_vendor=aes_vendor,
            aes_strength=aes_strength,
            actual_method=actual_method,
        )

        data_offset, _local_position = _read_local_data_offset(path, entry, shift, size)
        entry = replace(entry, data_offset=data_offset)

        if entry.is_aes:
            salt_length = entry.aes_salt_length
            minimum = salt_length + 2 + AES_AUTH_CODE_LENGTH
            if entry.compressed_size < minimum:
                raise FormatError(f"AES entry {name!r} is shorter than its salt/verifier/auth code")
            if entry.ciphertext_length < 0:
                raise FormatError(f"AES entry {name!r} has a negative ciphertext length")
            with path.open("rb") as handle:
                handle.seek(entry.data_offset)
                blob = handle.read(minimum)
            if len(blob) != minimum:
                raise FormatError(f"truncated AES entry {name!r}")
            salt = blob[:salt_length]
            pwd_verify = blob[salt_length : salt_length + 2]
            with path.open("rb") as handle:
                handle.seek(entry.data_offset + entry.compressed_size - AES_AUTH_CODE_LENGTH)
                auth_code = handle.read(AES_AUTH_CODE_LENGTH)
            if len(auth_code) != AES_AUTH_CODE_LENGTH:
                raise FormatError(f"truncated AES auth code for {name!r}")
            entry = replace(
                entry,
                salt=salt,
                pwd_verify=pwd_verify,
                auth_code=auth_code,
            )

        entries.append(entry)
        position = record_end
        index += 1

    if position != len(central):
        if any(central[position:]):
            raise FormatError("trailing data in the ZIP central directory")
    if entries_total not in (0xFFFF, len(entries)):
        raise FormatError(
            f"ZIP entry count mismatch: directory says {entries_total}, parsed {len(entries)}"
        )

    return ZipDirectory(
        entries=tuple(entries),
        comment=eocd.comment,
        shift=shift,
        zip64=zip64,
        eocd_offset=eocd.offset,
        central_offset=actual_central,
        central_size=central_size,
    )


def looks_like_zip(path: str | Path) -> bool:
    path = Path(path)
    try:
        with path.open("rb") as handle:
            head = handle.read(4)
        if head in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
            return True
        return find_eocd_offset(path) is not None
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _derive_entry_keys(password: bytes, salt: bytes, key_length: int) -> tuple[bytes, bytes, bytes]:
    material = hashlib.pbkdf2_hmac(
        "sha1",
        password,
        salt,
        AES_PBKDF2_ITERATIONS,
        dklen=2 * key_length + 2,
    )
    key = material[:key_length]
    auth_key = material[key_length : 2 * key_length]
    pwd_verify = material[2 * key_length :]
    return key, auth_key, pwd_verify


def _entry_hmac(path: Path, entry: ZipEntry, auth_key: bytes) -> bytes:
    digest = hmac.new(auth_key, digestmod=hashlib.sha1)
    with path.open("rb") as handle:
        handle.seek(entry.ciphertext_offset)
        remaining = entry.ciphertext_length
        while remaining:
            chunk = handle.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise DecryptionError(f"unexpected end of ciphertext for {entry.name!r}")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.digest()[:AES_AUTH_CODE_LENGTH]


def _verify_entry_key(path: Path, entry: ZipEntry, password: bytes) -> tuple[Optional[bytes], str]:
    """Return (key, reason).  ``key`` is None when the candidate fails."""
    if not entry.is_aes:
        return None, "not-aes"
    key, auth_key, pwd_verify = _derive_entry_keys(password, entry.salt, entry.aes_key_length)
    if not hmac.compare_digest(pwd_verify, entry.pwd_verify):
        return None, "password-mismatch"
    actual = _entry_hmac(path, entry, auth_key)
    if not hmac.compare_digest(actual, entry.auth_code):
        return None, "auth-code-mismatch"
    return key, "ok"


@dataclass(frozen=True)
class ZipAesVerifier(Verifier):
    format_name = "zip-aes"
    path: str
    ciphertext_offset: int
    ciphertext_length: int
    salt: bytes
    pwd_verify: bytes
    auth_code: bytes
    key_length: int
    aes_strength: int
    aes_version: int
    entry_name: str

    @property
    def cipher_name(self) -> str:
        return AES_PARAMETERS[self.aes_strength][0]

    def describe(self) -> dict:
        return {
            "format": "zip-aes",
            "display_name": f"WinZip AES (AE-{self.aes_version})",
            "entry": self.entry_name,
            "cipher": f"{self.cipher_name}-CTR",
            "kdf": "PBKDF2-HMAC-SHA1, 1000 iterations",
            "authentication": "HMAC-SHA1 auth code (80-bit)",
            "password_prefilter": "2-byte PBKDF2 verification value (1/65536)",
        }

    def verification_label(self) -> str:
        return f"WinZip AES HMAC-SHA1 auth code (80-bit, {self.cipher_name})"

    def verify(self, password: bytes) -> Outcome:
        key, auth_key, pwd_verify = _derive_entry_keys(password, self.salt, self.key_length)
        if not hmac.compare_digest(pwd_verify, self.pwd_verify):
            return Outcome.REJECT
        digest = hmac.new(auth_key, digestmod=hashlib.sha1)
        try:
            with open(self.path, "rb") as handle:
                handle.seek(self.ciphertext_offset)
                remaining = self.ciphertext_length
                while remaining:
                    chunk = handle.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        return Outcome.REJECT
                    digest.update(chunk)
                    remaining -= len(chunk)
        except OSError:
            return Outcome.REJECT
        if hmac.compare_digest(digest.digest()[:AES_AUTH_CODE_LENGTH], self.auth_code):
            return Outcome.CONFIRMED
        return Outcome.REJECT


# ---------------------------------------------------------------------------
# Artifact and extraction
# ---------------------------------------------------------------------------


def _select_entry(directory: ZipDirectory, selection: Optional[str]) -> ZipEntry:
    if selection is not None:
        named = [entry for entry in directory.entries if entry.name == selection]
        if named:
            entry = named[0]
        elif selection.isdigit():
            index = int(selection)
            if not 0 <= index < len(directory.entries):
                raise UsageError(f"ZIP entry index out of range: {selection}")
            entry = directory.entries[index]
        else:
            raise UsageError(f"ZIP entry not found: {selection}")
        if not entry.is_aes:
            raise UnsupportedError(
                f"ZIP entry {entry.name!r} is not WinZip AES encrypted ({entry.encryption})"
            )
        if entry.is_dir:
            raise UsageError(f"ZIP entry {entry.name!r} is a directory")
        return entry

    aes_entries = [entry for entry in directory.entries if entry.is_aes and not entry.is_dir]
    if not aes_entries:
        if any(entry.is_encrypted for entry in directory.entries):
            raise UnsupportedError(
                "archive has no WinZip AES entries",
                hint="legacy ZipCrypto entries are not AES and are intentionally not attacked here",
            )
        raise UnsupportedError("archive has no encrypted entries")
    return aes_entries[0]


class ZipAesArtifact(Artifact):
    format_name = "zip-aes"
    display_name = "WinZip AES ZIP"
    output_kind = "directory"

    def __init__(self, path: str | Path, options) -> None:
        path = Path(path)
        directory = parse_zip(path)
        super().__init__(path, path.stat().st_size)
        self.directory = directory
        self.options = options
        self.target = _select_entry(directory, options.entry)

    def inspect(self) -> dict:
        entries = [entry.summary() for entry in self.directory.entries]
        return {
            "format": "zip-aes",
            "display_name": "ZIP archive",
            "entry_count": len(self.directory.entries),
            "aes_entry_count": sum(1 for entry in self.directory.entries if entry.is_aes),
            "encrypted_entry_count": sum(
                1 for entry in self.directory.entries if entry.is_encrypted
            ),
            "zip64": self.directory.zip64,
            "archive_shift": self.directory.shift,
            "comment": self.directory.comment.decode("utf-8", "replace")
            if self.directory.comment
            else None,
            "central_directory_offset": self.directory.central_offset,
            "central_directory_size": self.directory.central_size,
            "selected_entry": self.target.name,
            "kdf": "PBKDF2-HMAC-SHA1 (1000 iterations) for WinZip AES entries",
            "authentication": "HMAC-SHA1 truncated auth code (10 bytes)",
            "entries": entries,
            "structural_status": "valid",
            "notes": [
                "AE-1 and AE-2 are both parsed; the auth code is the integrity check.",
                "ZipCrypto entries are recognized but not attacked because they are not AES.",
            ],
        }

    def verifier(self, policy: ValidationPolicy) -> Verifier:
        target = self.target
        return ZipAesVerifier(
            path=str(self.path),
            ciphertext_offset=target.ciphertext_offset,
            ciphertext_length=target.ciphertext_length,
            salt=target.salt,
            pwd_verify=target.pwd_verify,
            auth_code=target.auth_code,
            key_length=target.aes_key_length,
            aes_strength=target.aes_strength or 3,
            aes_version=target.aes_version or 2,
            entry_name=target.name,
        )

    def decrypt(self, password: bytes, handle: BinaryIO) -> DecryptReport:
        raise UnsupportedError(
            "ZIP archives are extracted to a directory",
            hint="use the extract path of the CLI (--out DIR); the command does this automatically",
        )

    def default_decrypted_name(self) -> str:
        name = self.path.name
        stem = name[:-4] if name.lower().endswith(".zip") else name
        return stem + ".extracted"

    # -- extraction --------------------------------------------------------

    def extract(
        self,
        password: bytes,
        directory: str,
        *,
        overwrite: bool = False,
        max_output_bytes: Optional[int] = DEFAULT_MAX_EXTRACT_BYTES,
    ) -> DecryptReport:
        base = Path(directory)
        try:
            base.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise OutputError(f"cannot create extraction directory {base}: {exc}") from None
        if not base.is_dir():
            raise OutputError(f"extraction target is not a directory: {base}")

        key, reason = _verify_entry_key(self.path, self.target, password)
        if key is None:
            if reason == "auth-code-mismatch":
                raise DecryptionError(
                    f"AES auth code failed for {self.target.name!r}; "
                    "the entry is corrupt or the password is wrong"
                )
            raise DecryptionError("incorrect password for this WinZip AES archive")

        from ..util import safe_zip_target

        planned: list[tuple[ZipEntry, Path, str]] = []
        seen: set[str] = set()
        for entry in self.directory.entries:
            if entry.name in seen:
                planned.append((entry, Path(), "duplicate-name"))
                continue
            seen.add(entry.name)
            if entry.is_symlink:
                planned.append((entry, Path(), "symlink-refused"))
                continue
            target = safe_zip_target(base, entry.name)
            if entry.is_dir:
                planned.append((entry, target, "directory"))
                continue
            if target.exists() and not target.is_file() and not target.is_symlink():
                raise OutputError(f"archive output collides with a non-file: {target}")
            if target.exists() and not overwrite:
                raise OutputError(
                    f"output file already exists: {target}",
                    hint="pass --overwrite to replace extracted files",
                )
            if entry.encryption == "zipcrypto":
                planned.append((entry, target, "unsupported-zipcrypto"))
                continue
            planned.append((entry, target, "file"))

        total_written = 0
        results: list[dict] = []
        errors: list[str] = []
        extracted = 0
        for entry, target, action in planned:
            if action == "duplicate-name":
                results.append({"name": entry.name, "status": "skipped-duplicate-name"})
                continue
            if action == "symlink-refused":
                message = f"refusing to create symlink for {entry.name!r}"
                errors.append(message)
                results.append({"name": entry.name, "status": "symlink-refused"})
                continue
            if action == "unsupported-zipcrypto":
                message = f"{entry.name}: ZipCrypto entries are not supported"
                errors.append(message)
                results.append(
                    {
                        "name": entry.name,
                        "status": "unsupported-zipcrypto",
                        "error": message,
                    }
                )
                continue
            if action == "directory":
                try:
                    target.mkdir(parents=True, exist_ok=True)
                    results.append({"name": entry.name, "status": "directory"})
                except OSError as exc:
                    errors.append(f"{entry.name}: {exc}")
                    results.append({"name": entry.name, "status": "error", "error": str(exc)})
                continue

            entry_key: Optional[bytes] = None
            if entry.encryption == "aes":
                entry_key, entry_reason = _verify_entry_key(self.path, entry, password)
                if entry_key is None:
                    status = (
                        "different-password"
                        if entry_reason == "password-mismatch"
                        else "auth-code-failed"
                    )
                    message = f"{entry.name}: {status}"
                    errors.append(message)
                    results.append({"name": entry.name, "status": status, "error": message})
                    continue
            elif entry.encryption != "none":
                message = f"{entry.name}: unsupported encryption ({entry.encryption})"
                errors.append(message)
                results.append(
                    {
                        "name": entry.name,
                        "status": "unsupported-encryption",
                        "error": message,
                    }
                )
                continue

            try:
                written = self._extract_entry(
                    entry,
                    entry_key,
                    target,
                    overwrite=overwrite,
                    max_output_bytes=max_output_bytes,
                    already_written=total_written,
                )
            except (UnsupportedError, DecryptionError, OutputError) as exc:
                message = f"{entry.name}: {exc}"
                errors.append(message)
                results.append({"name": entry.name, "status": "error", "error": str(exc)})
                continue
            except OSError as exc:
                message = f"{entry.name}: {exc}"
                errors.append(message)
                results.append({"name": entry.name, "status": "error", "error": str(exc)})
                continue
            total_written += written
            extracted += 1
            results.append(
                {
                    "name": entry.name,
                    "status": "extracted",
                    "output": str(target),
                    "bytes": written,
                    "compression": entry.compression_name,
                    "encryption": entry.encryption,
                }
            )

        return DecryptReport(
            format_name=self.format_name,
            output=str(base),
            bytes_written=total_written,
            verification=(f"WinZip AES auth code verified on {self.target.name!r}"),
            details={
                "output_directory": str(base),
                "target_entry": self.target.name,
                "extracted_count": extracted,
                "entries": results,
                "errors": errors,
                "authenticated": True,
            },
        )

    def _extract_entry(
        self,
        entry: ZipEntry,
        key: Optional[bytes],
        target: Path,
        *,
        overwrite: bool,
        max_output_bytes: Optional[int],
        already_written: int,
    ) -> int:
        method = entry.compression_method
        if method not in (0, 8, 12):
            raise UnsupportedError(
                f"compression method {method} ({entry.compression_name}) is not supported"
            )
        if entry.ciphertext_length < 0:
            raise DecryptionError("negative ciphertext length")
        if entry.uncompressed_size > 0xFFFFFFFF:
            raise UnsupportedError("ZIP64 uncompressed sizes above 4 GiB are not supported")

        decompressor: Any = None
        if method == 8:
            decompressor = zlib.decompressobj(-15)
        elif method == 12:
            decompressor = bz2.BZ2Decompressor()

        cipher = None
        if entry.encryption == "aes":
            if key is None:
                raise DecryptionError("missing AES key")
            initial = b"\x01" + b"\x00" * 15
            cipher = aes_ctr_cipher(key, initial, little_endian=True)

        written = 0
        crc = 0
        with atomic_writer(target, overwrite=overwrite) as output:
            with self.path.open("rb") as source:
                source.seek(entry.ciphertext_offset)
                remaining = (
                    entry.ciphertext_length if entry.encryption == "aes" else entry.compressed_size
                )
                while remaining:
                    chunk = source.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise DecryptionError(f"unexpected end of data for {entry.name!r}")
                    remaining -= len(chunk)
                    if cipher is not None:
                        chunk = cipher.decrypt(chunk)
                    if decompressor is None:
                        plain = chunk
                    else:
                        plain = decompressor.decompress(chunk)
                    crc = zlib.crc32(plain, crc)
                    written += len(plain)
                    if max_output_bytes is not None and (
                        already_written + written > max_output_bytes
                    ):
                        raise OutputError("extraction exceeded the configured output limit")
                    output.write(plain)

            if method == 8 and decompressor is not None:
                plain = decompressor.flush()
                if plain:
                    crc = zlib.crc32(plain, crc)
                    written += len(plain)
                    if max_output_bytes is not None and (
                        already_written + written > max_output_bytes
                    ):
                        raise OutputError("extraction exceeded the configured output limit")
                    output.write(plain)
                if not decompressor.eof:
                    raise DecryptionError(f"deflate stream for {entry.name!r} is truncated")
                if decompressor.unused_data:
                    raise DecryptionError(f"deflate stream for {entry.name!r} has trailing data")
            elif method == 12 and decompressor is not None:
                if not decompressor.eof:
                    raise DecryptionError(f"bzip2 stream for {entry.name!r} is truncated")

        if entry.uncompressed_size not in (0xFFFFFFFF, 0) or written:
            if written != entry.uncompressed_size:
                raise DecryptionError(
                    f"uncompressed size mismatch for {entry.name!r}: "
                    f"expected {entry.uncompressed_size}, wrote {written}"
                )
        if entry.crc and (crc & 0xFFFFFFFF) != entry.crc:
            raise DecryptionError(
                f"CRC-32 mismatch for {entry.name!r}: "
                f"expected {entry.crc:08x}, got {crc & 0xFFFFFFFF:08x}"
            )
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return written


# ---------------------------------------------------------------------------
# Encryption (compatibility fixtures and lab data)
# ---------------------------------------------------------------------------


def _dos_datetime(moment: Optional[datetime]) -> tuple[int, int]:
    moment = moment or datetime.now()
    year = max(1980, min(2107, moment.year))
    dos_date = ((year - 1980) << 9) | (moment.month << 5) | moment.day
    dos_time = (moment.hour << 11) | (moment.minute << 5) | (moment.second // 2)
    return dos_time, dos_date


def _compress(data: bytes, compression: str) -> tuple[int, bytes]:
    normalized = compression.lower()
    if normalized in ("store", "stored", "none"):
        return 0, data
    if normalized in ("deflate", "zip", "default"):
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        packed = compressor.compress(data) + compressor.flush()
        return 8, packed
    raise UsageError(
        f"unsupported ZIP compression: {compression}",
        hint="choose deflate or store",
    )


def build_zip_aes(
    entry_name: str,
    data: bytes,
    password: bytes,
    *,
    strength: int = 3,
    compression: str = "deflate",
    timestamp: Optional[datetime] = None,
) -> bytes:
    if strength not in AES_PARAMETERS:
        raise UsageError("ZIP AES strength must be 1 (128), 2 (192), or 3 (256)")
    cipher_name, key_length, salt_length = AES_PARAMETERS[strength]
    actual_method, packed = _compress(data, compression)
    salt = random_bytes(salt_length)
    key, auth_key, pwd_verify = _derive_entry_keys(password, salt, key_length)
    initial = b"\x01" + b"\x00" * 15
    ciphertext = aes_ctr_cipher(key, initial, little_endian=True).encrypt(packed)
    auth_code = hmac.new(auth_key, ciphertext, hashlib.sha1).digest()[:AES_AUTH_CODE_LENGTH]
    payload = salt + pwd_verify + ciphertext + auth_code

    name_bytes = entry_name.encode("utf-8")
    flags = 0x0001
    if any(byte >= 0x80 for byte in name_bytes):
        flags |= 0x0800
    dos_time, dos_date = _dos_datetime(timestamp)
    aes_extra = struct.pack(
        "<HHH2sBH",
        AES_EXTRA_ID,
        7,
        2,  # AE-2
        AES_VENDOR,
        strength,
        actual_method,
    )
    version_needed = 51
    external_attr = (0o100644 << 16) & 0xFFFFFFFF

    local_header = struct.pack(
        "<IHHHHHIIIHH",
        LOCAL_SIGNATURE,
        version_needed,
        flags,
        AES_METHOD,
        dos_time,
        dos_date,
        0,  # CRC is zero for AE-2
        len(payload),
        len(data),
        len(name_bytes),
        len(aes_extra),
    )
    local = local_header + name_bytes + aes_extra + payload

    central_header = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        CENTRAL_SIGNATURE,
        (3 << 8) | version_needed,
        version_needed,
        flags,
        AES_METHOD,
        dos_time,
        dos_date,
        0,
        len(payload),
        len(data),
        len(name_bytes),
        len(aes_extra),
        0,
        0,
        0,
        external_attr,
        0,
    )
    central = central_header + name_bytes + aes_extra
    eocd = struct.pack(
        "<IHHHHIIH",
        EOCD_SIGNATURE,
        0,
        0,
        1,
        1,
        len(central),
        len(local),
        0,
    )
    return local + central + eocd


def zip_aes_encrypt_bytes(
    plaintext: bytes,
    password: bytes,
    *,
    entry_name: str = "data.bin",
    strength: int = 3,
    compression: str = "deflate",
) -> bytes:
    return build_zip_aes(
        entry_name,
        plaintext,
        password,
        strength=strength,
        compression=compression,
    )
