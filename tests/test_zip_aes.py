from __future__ import annotations

import base64
import shutil
import struct
import subprocess
import zlib
from pathlib import Path

import pytest

from aesbreaker.commands.selftest import ZIP_FIXTURE
from aesbreaker.errors import DecryptionError, OutputError, UnsupportedError, UsageError
from aesbreaker.formats.base import FormatOptions, Outcome, ValidationPolicy
from aesbreaker.formats.zip_aes import (
    ZipAesArtifact,
    parse_zip,
)

from .helpers import PLAINTEXT, make_zip


def test_external_fixture(tmp_path: Path):
    path = tmp_path / "fixture.zip"
    path.write_bytes(base64.b64decode(ZIP_FIXTURE))
    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.target.name == "plain.txt"
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    assert artifact.verifier(ValidationPolicy()).verify(b"wrong") == Outcome.REJECT

    out_dir = tmp_path / "out"
    report = artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert report.bytes_written == len(PLAINTEXT)
    assert (out_dir / "plain.txt").read_bytes() == PLAINTEXT
    details = artifact.inspect()
    assert details["aes_entry_count"] == 1
    assert details["entries"][0]["aes_cipher"] == "AES-256"


@pytest.mark.parametrize("strength", [1, 2, 3])
@pytest.mark.parametrize("compression", ["deflate", "store"])
def test_roundtrip_strengths_and_compression(tmp_path: Path, strength: int, compression: str):
    path = make_zip(
        tmp_path / f"{strength}-{compression}.zip",
        strength=strength,
        compression=compression,
        data=PLAINTEXT,
        name="nested/file.txt",
    )
    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.target.aes_strength == strength
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    out_dir = tmp_path / "out"
    report = artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert report.bytes_written == len(PLAINTEXT)
    assert (out_dir / "nested" / "file.txt").read_bytes() == PLAINTEXT


def test_wrong_password_rejected(tmp_path: Path):
    path = make_zip(tmp_path / "secret.zip")
    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.verifier(ValidationPolicy()).verify(b"wrong") == Outcome.REJECT
    with pytest.raises(DecryptionError):
        artifact.extract(b"wrong", str(tmp_path / "out"))


def test_corrupt_ciphertext_rejected(tmp_path: Path):
    path = make_zip(tmp_path / "secret.zip")
    artifact = ZipAesArtifact(path, FormatOptions())
    data = bytearray(path.read_bytes())
    data[artifact.target.ciphertext_offset] ^= 0x80
    path.write_bytes(bytes(data))
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.REJECT
    with pytest.raises(DecryptionError):
        artifact.extract(b"hunter2", str(tmp_path / "out"))


def test_zip_slip_rejected(tmp_path: Path):
    path = make_zip(tmp_path / "evil.zip", name="../evil.txt")
    artifact = ZipAesArtifact(path, FormatOptions())
    out_dir = tmp_path / "safe" / "inner"
    with pytest.raises(OutputError):
        artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert not (tmp_path / "safe" / "evil.txt").exists()


def test_symlink_entry_refused(tmp_path: Path):
    path = make_zip(tmp_path / "symlink.zip")
    directory = parse_zip(path)
    data = bytearray(path.read_bytes())
    # Central header: external attributes begin at +38.
    struct.pack_into("<I", data, directory.central_offset + 38, (0o120777 << 16) & 0xFFFFFFFF)
    path.write_bytes(bytes(data))
    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.target.is_symlink
    report = artifact.extract(b"hunter2", str(tmp_path / "out"), overwrite=True)
    assert report.details["extracted_count"] == 0
    assert any("symlink" in error for error in report.details["errors"])
    assert not (tmp_path / "out" / "secret.txt").exists()


def test_self_extracting_prefix_shift(tmp_path: Path):
    original = make_zip(tmp_path / "inner.zip")
    payload = b"SFX-STUB" * 16 + original.read_bytes()
    path = tmp_path / "sfx.exe"
    path.write_bytes(payload)
    directory = parse_zip(path)
    assert directory.shift > 0
    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    out_dir = tmp_path / "out"
    artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert (out_dir / "secret.txt").read_bytes() == PLAINTEXT


def test_large_entry(tmp_path: Path):
    data = b"0123456789abcdef" * 65536  # 1 MiB
    path = make_zip(tmp_path / "large.zip", data=data)
    artifact = ZipAesArtifact(path, FormatOptions())
    out_dir = tmp_path / "out"
    report = artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert report.bytes_written == len(data)
    assert (out_dir / "secret.txt").read_bytes() == data


def test_existing_output_requires_overwrite(tmp_path: Path):
    path = make_zip(tmp_path / "secret.zip")
    artifact = ZipAesArtifact(path, FormatOptions())
    out_dir = tmp_path / "out"
    artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    with pytest.raises(OutputError):
        artifact.extract(b"hunter2", str(out_dir), overwrite=False)
    artifact.extract(b"hunter2", str(out_dir), overwrite=True)


def test_entry_selection(tmp_path: Path):
    path = make_zip(tmp_path / "secret.zip", name="alpha.txt")
    options = FormatOptions(entry="alpha.txt")
    artifact = ZipAesArtifact(path, options)
    assert artifact.target.name == "alpha.txt"
    with pytest.raises(UsageError):
        ZipAesArtifact(path, FormatOptions(entry="missing.txt"))


def test_zipcrypto_is_not_treated_as_aes(tmp_path: Path):
    zip_binary = shutil.which("zip")
    if not zip_binary:
        pytest.skip("zip is not installed")
    payload = tmp_path / "plain.txt"
    payload.write_bytes(PLAINTEXT)
    archive = tmp_path / "zipcrypto.zip"
    result = subprocess.run(
        [zip_binary, "-q", "-e", "-P", "hunter2", str(archive), payload.name],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        pytest.skip(f"zip could not create a ZipCrypto archive: {result.stderr!r}")
    with pytest.raises(UnsupportedError):
        ZipAesArtifact(archive, FormatOptions())


def test_multi_entry_archive(tmp_path: Path):
    sevenzip = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
    if not sevenzip:
        pytest.skip("7z is not installed")
    first = tmp_path / "first.txt"
    second = tmp_path / "second.bin"
    first.write_bytes(b"first entry\n")
    second.write_bytes(b"\x00\x01\x02" * 100)
    archive = tmp_path / "multi.zip"
    result = subprocess.run(
        [
            sevenzip,
            "a",
            "-tzip",
            "-mem=AES256",
            "-phunter2",
            str(archive),
            first.name,
            second.name,
        ],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    artifact = ZipAesArtifact(archive, FormatOptions())
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    out_dir = tmp_path / "out"
    report = artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert (out_dir / "first.txt").read_bytes() == b"first entry\n"
    assert (out_dir / "second.bin").read_bytes() == b"\x00\x01\x02" * 100
    assert report.details["extracted_count"] == 2


def test_7zip_verifies_generated_archive(tmp_path: Path):
    sevenzip = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
    if not sevenzip:
        pytest.skip("7z is not installed")
    path = make_zip(tmp_path / "ours.zip")
    result = subprocess.run(
        [sevenzip, "t", "-phunter2", str(path)],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0


def test_ae1_version_and_crc(tmp_path: Path):
    path = make_zip(tmp_path / "ae1.zip")
    directory = parse_zip(path)
    data = bytearray(path.read_bytes())
    crc = zlib.crc32(PLAINTEXT)
    struct.pack_into("<I", data, 14, crc)  # local header CRC
    struct.pack_into("<I", data, directory.central_offset + 16, crc)
    needle = b"\x01\x99\x07\x00\x02\x00AE"
    assert data.count(needle) == 2
    data = data.replace(needle, b"\x01\x99\x07\x00\x01\x00AE")
    path.write_bytes(bytes(data))

    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.target.aes_version == 1
    assert artifact.target.crc == crc
    out_dir = tmp_path / "out"
    artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert (out_dir / "secret.txt").read_bytes() == PLAINTEXT


def test_ae1_crc_mismatch_is_reported(tmp_path: Path):
    path = make_zip(tmp_path / "ae1-bad.zip")
    directory = parse_zip(path)
    data = bytearray(path.read_bytes())
    struct.pack_into("<I", data, 14, 0xDEADBEEF)
    struct.pack_into("<I", data, directory.central_offset + 16, 0xDEADBEEF)
    needle = b"\x01\x99\x07\x00\x02\x00AE"
    data = data.replace(needle, b"\x01\x99\x07\x00\x01\x00AE")
    path.write_bytes(bytes(data))

    artifact = ZipAesArtifact(path, FormatOptions())
    report = artifact.extract(b"hunter2", str(tmp_path / "out"), overwrite=True)
    assert report.details["extracted_count"] == 0
    assert any("CRC-32" in error for error in report.details["errors"])


def _zip64_rewrite(path: Path, *, full_record: bool, extensible: bytes = b"") -> None:
    """Rewrite a single-entry AES ZIP with Zip64 size/offset fields."""
    directory = parse_zip(path)
    raw = path.read_bytes()
    cd_start, cd_size = directory.central_offset, directory.central_size
    local_data = raw[:cd_start]
    central = raw[cd_start : cd_start + cd_size]
    (
        sig,
        made,
        needed,
        flags,
        method,
        dos_time,
        dos_date,
        crc,
        csize,
        usize,
        nlen,
        elen,
        clen,
        disk,
        iattr,
        eattr,
        loff,
    ) = struct.unpack_from("<IHHHHHHIIIHHHHHII", central, 0)
    extra = central[46 + nlen : 46 + nlen + elen]
    comment = central[46 + nlen + elen : 46 + nlen + elen + clen]
    zip64_extra = struct.pack("<HHQQQ", 0x0001, 24, usize, csize, loff)
    new_extra = extra + zip64_extra
    new_central = bytearray(central[: 46 + nlen] + new_extra + comment)
    struct.pack_into("<I", new_central, 20, 0xFFFFFFFF)
    struct.pack_into("<I", new_central, 24, 0xFFFFFFFF)
    struct.pack_into("<I", new_central, 42, 0xFFFFFFFF)
    struct.pack_into("<H", new_central, 30, len(new_extra))
    struct.pack_into("<H", new_central, 6, 45)
    new_central = bytes(new_central)

    if not full_record:
        eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(new_central), cd_start, 0)
        path.write_bytes(local_data + new_central + eocd)
        return

    z64_offset = len(local_data) + len(new_central)
    record_size = 44 + len(extensible)
    record = (
        struct.pack(
            "<IQHHIIQQQQ",
            0x06064B50,
            record_size,
            45,
            45,
            0,
            0,
            1,
            1,
            len(new_central),
            cd_start,
        )
        + extensible
    )
    locator = struct.pack("<IIQI", 0x07064B50, 0, z64_offset, 1)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    path.write_bytes(local_data + new_central + record + locator + eocd)


def test_zip64_extra_fields(tmp_path: Path):
    path = make_zip(tmp_path / "zip64-extra.zip")
    _zip64_rewrite(path, full_record=False)
    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    out_dir = tmp_path / "out-extra"
    artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert (out_dir / "secret.txt").read_bytes() == PLAINTEXT


def test_zip64_end_record(tmp_path: Path):
    path = make_zip(tmp_path / "zip64-record.zip")
    _zip64_rewrite(path, full_record=True)
    directory = parse_zip(path)
    assert directory.zip64 is True
    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    out_dir = tmp_path / "out-record"
    artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert (out_dir / "secret.txt").read_bytes() == PLAINTEXT


def test_zip64_extensible_record_with_sfx_stub(tmp_path: Path):
    path = make_zip(tmp_path / "zip64-ext.zip")
    _zip64_rewrite(path, full_record=True, extensible=b"EXTENSIBLE!" * 2)
    payload = b"SFX" * 40 + path.read_bytes()
    path.write_bytes(payload)
    directory = parse_zip(path)
    assert directory.zip64 is True
    assert directory.shift > 0
    artifact = ZipAesArtifact(path, FormatOptions())
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    out_dir = tmp_path / "out-ext"
    artifact.extract(b"hunter2", str(out_dir), overwrite=True)
    assert (out_dir / "secret.txt").read_bytes() == PLAINTEXT


def test_partial_extraction_reports_errors(tmp_path: Path):
    sevenzip = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
    if not sevenzip:
        pytest.skip("7z is not installed")
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"first payload\n")
    second.write_bytes(b"second payload\n")
    archive = tmp_path / "partial.zip"
    result = subprocess.run(
        [
            sevenzip,
            "a",
            "-tzip",
            "-mem=AES256",
            "-phunter2",
            str(archive),
            first.name,
            second.name,
        ],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    directory = parse_zip(archive)
    target = directory.entries[1]
    data = bytearray(archive.read_bytes())
    data[target.ciphertext_offset] ^= 0x80
    archive.write_bytes(bytes(data))

    artifact = ZipAesArtifact(archive, FormatOptions())
    report = artifact.extract(b"hunter2", str(tmp_path / "out"), overwrite=True)
    assert report.details["extracted_count"] == 1
    assert report.details["errors"]
