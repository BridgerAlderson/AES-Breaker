from __future__ import annotations

import base64
import io
from pathlib import Path

import pytest

from aesbreaker.errors import DecryptionError, FormatError
from aesbreaker.formats.aescrypt import AesCryptArtifact, encrypt_bytes, parse_header
from aesbreaker.formats.base import Outcome, ValidationPolicy
from aesbreaker.kdf import aescrypt_stretch

from .helpers import PLAINTEXT, json_output, make_aescrypt, run_cli

V1_EMPTY_FIXTURE = (
    "QUVTAQBZvYMPl2V0Km3R3zOgkEKzh39HVKJRad8lncJEN+Rqe16qLWX2GjONWsFZt5wwEpwrvBCRZ2hw76Vj"
    "HQDOlW1IQfrkyXAvT0qNX6j4Q/RqLNmOELhWRePD39gRpiHFLecNAkAHg64xG/wkQiuUxUX5l83Cr9uwgBI"
    "2J3leAajhS8c="
)
V1_BLOCK_FIXTURE = (
    "QUVTAQC3fhTFBrOdWLS5t36ZxZWFseVQ8ocYw5vsw16r9wkWQAUWT/3+mXJM9rVqOaHZ/eDKgjy5UV4O"
    "2jhsc4NH0BHYKtIKIln7RVm/PpwlHcDoRC0vEQzn+FsyX50QTixOoBEgmVgilrutLgqTk9TjHtWaAE3LiT5J"
    "FYW25Uw0qR8TJeijvG0YiTRiR2PlFPwL9LVA"
)
V3_EMPTY_FIXTURE = (
    "QUVTAwAAG0NSRUFURURfQlkAYWVzY3J5cHQgNC4wLjAuMAAAAAAABZX1t1GP4qzItB4dBjCrnjo/liwHN7z3"
    "47dKRFRoKe3h6u0+kEve70W9wiHMQKfaWlWBaxhABd1o54aTxDaumcHW//fpDUaOLDdnYwltGfP783dUwr62"
    "y69SnrJibwtzwT/+TYC/+gqmQeyMi1V6wRChIwJLv3rwSF0eGdQ0HOncj+8wbtVprt2M0n2aQkCZaA=="
)
V3_BLOCK_FIXTURE = (
    "QUVTAwAAG0NSRUFURURfQlkAYWVzY3J5cHQgNC4wLjAuMAAAAAAABVWdZC1mtmUT35url3x7qB3e3B4w8eUO"
    "M8UpOSb3C4VywbICZF1FrVd9+YiQpuE/qTwx6MDqsNJVkdcjHSsnRM3QtPjYwIqLoad3jWc5MBzJgo32wL3O"
    "0jqxufuigaLwS1Vc04jRJtzWAo8gO7NpDzAfaPVJrzBo7rcmaunef+4Qn/AzxgR9h433oR/+c9gHxnqtMq/2"
    "jc4S9++V1myZ35o="
)


def test_parse_header_and_verify(tmp_path: Path):
    path = make_aescrypt(tmp_path / "secret.aes")
    header = parse_header(path)
    assert header.version == 2
    assert header.ciphertext_length == 80
    assert header.plaintext_length == 70
    assert header.fs16 == 6
    assert header.created_by == "test"

    artifact = AesCryptArtifact(path)
    verifier = artifact.verifier(ValidationPolicy())
    assert verifier.verify(b"hunter2") == Outcome.CONFIRMED
    assert verifier.verify(b"wrong") == Outcome.REJECT
    assert verifier.verify(b"\xff") == Outcome.REJECT

    output = io.BytesIO()
    report = artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT
    assert report.bytes_written == len(PLAINTEXT)
    assert report.details["header_hmac_verified"]
    assert report.details["ciphertext_hmac_verified"]


def test_header_hmac_is_the_password_check(tmp_path: Path):
    path = make_aescrypt(tmp_path / "secret.aes")
    header = parse_header(path)
    data = bytearray(path.read_bytes())
    data[header.ciphertext_offset - 70] ^= 0x01  # inside c_iv_key
    path.write_bytes(bytes(data))
    artifact = AesCryptArtifact(path)
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.REJECT
    with pytest.raises(DecryptionError):
        artifact.decrypt(b"hunter2", io.BytesIO())


def test_corrupt_ciphertext_rejected_before_output(tmp_path: Path):
    path = make_aescrypt(tmp_path / "secret.aes")
    header = parse_header(path)
    data = bytearray(path.read_bytes())
    data[header.ciphertext_offset] ^= 0x80
    path.write_bytes(bytes(data))
    artifact = AesCryptArtifact(path)
    # The header MAC still confirms the password; the payload MAC does not.
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    output = io.BytesIO()
    with pytest.raises(DecryptionError):
        artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == b""


def test_corrupt_fs16_is_a_structure_error(tmp_path: Path):
    path = make_aescrypt(tmp_path / "secret.aes")
    data = bytearray(path.read_bytes())
    data[-33] = 16
    path.write_bytes(bytes(data))
    with pytest.raises(FormatError):
        parse_header(path)


def test_truncated_and_wrong_magic(tmp_path: Path):
    path = make_aescrypt(tmp_path / "secret.aes")
    path.write_bytes(path.read_bytes()[:-10])
    with pytest.raises(FormatError):
        parse_header(path)

    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"NOPE" + b"\x00" * 200)
    with pytest.raises(FormatError):
        parse_header(bad)


def test_unsupported_version(tmp_path: Path):
    path = make_aescrypt(tmp_path / "secret.aes")
    data = bytearray(path.read_bytes())
    data[3] = 4
    path.write_bytes(bytes(data))
    with pytest.raises(FormatError, match="version"):
        parse_header(path)


def test_empty_plaintext_roundtrip(tmp_path: Path):
    path = tmp_path / "empty.aes"
    path.write_bytes(encrypt_bytes(b"", b"hunter2"))
    artifact = AesCryptArtifact(path)
    assert artifact.header.ciphertext_length == 0
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == b""


def test_multi_chunk_roundtrip(tmp_path: Path):
    plaintext = bytes(range(256)) * 1000  # 256 KiB, several 64 KiB buffers
    encoded = encrypt_bytes(plaintext, b"hunter2")
    path = tmp_path / "large.aes"
    path.write_bytes(encoded)
    artifact = AesCryptArtifact(path)
    output = io.BytesIO()
    report = artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == plaintext
    assert report.bytes_written == len(plaintext)
    assert report.details["padding_consistent"]


def test_password_requirements(tmp_path: Path):
    path = make_aescrypt(tmp_path / "secret.aes")
    artifact = AesCryptArtifact(path)
    with pytest.raises(DecryptionError, match="UTF-8"):
        artifact.decrypt(b"\xff", io.BytesIO())
    with pytest.raises(DecryptionError, match="UTF-8"):
        artifact.decrypt(b"x" * 1025, io.BytesIO())


def test_stretch_matches_reference():
    key = aescrypt_stretch(
        "hunter2".encode("utf-16-le"),
        bytes.fromhex("86f1de059e0c34a94c70068a73bd3b47"),
    )
    assert key.hex().startswith("f905adb1")


def test_pyaescrypt_interoperability(tmp_path: Path):
    pyAesCrypt = pytest.importorskip("pyAesCrypt")
    plain = tmp_path / "plain.bin"
    plain.write_bytes(PLAINTEXT)
    encrypted = tmp_path / "pyaes.aes"
    decrypted = tmp_path / "decrypted.bin"
    pyAesCrypt.encryptFile(str(plain), str(encrypted), "hunter2")
    artifact = AesCryptArtifact(encrypted)
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT

    ours = tmp_path / "ours.aes"
    ours.write_bytes(encrypt_bytes(PLAINTEXT, b"hunter2"))
    pyAesCrypt.decryptFile(str(ours), str(decrypted), "hunter2")
    assert decrypted.read_bytes() == PLAINTEXT


@pytest.mark.parametrize(
    ("fixture", "version", "plaintext"),
    [
        (V1_EMPTY_FIXTURE, 1, b""),
        (V1_BLOCK_FIXTURE, 1, b"0123456789ABCDEF"),
        (V3_EMPTY_FIXTURE, 3, b""),
        (V3_BLOCK_FIXTURE, 3, b"0123456789ABCDEF"),
    ],
)
def test_v1_and_v3_reference_vectors(tmp_path: Path, fixture: str, version: int, plaintext: bytes):
    path = tmp_path / f"v{version}.aes"
    path.write_bytes(base64.b64decode(fixture))
    artifact = AesCryptArtifact(path)
    assert artifact.header.version == version
    verifier = artifact.verifier(ValidationPolicy())
    assert verifier.verify(b"Hello") == Outcome.CONFIRMED
    assert verifier.verify(b"wrong") == Outcome.REJECT
    output = io.BytesIO()
    report = artifact.decrypt(b"Hello", output)
    assert output.getvalue() == plaintext
    assert report.details["header_hmac_verified"] is True
    assert report.details["ciphertext_hmac_verified"] is True


def test_v3_writer_roundtrip(tmp_path: Path):
    for plaintext in (b"", b"a", b"0123456789ABCDEF", b"x" * 100_000):
        path = tmp_path / "v3.aes"
        path.write_bytes(encrypt_bytes(plaintext, b"Hello", version=3, iterations=5))
        artifact = AesCryptArtifact(path)
        assert artifact.header.version == 3
        assert artifact.header.iterations == 5
        output = io.BytesIO()
        artifact.decrypt(b"Hello", output)
        assert output.getvalue() == plaintext


@pytest.mark.parametrize(
    ("fixture", "version"),
    [(V1_BLOCK_FIXTURE, 1), (V3_BLOCK_FIXTURE, 3)],
)
def test_cli_crack_v1_and_v3(tmp_path: Path, fixture: str, version: int):
    path = tmp_path / f"v{version}.aes"
    path.write_bytes(base64.b64decode(fixture))
    words = tmp_path / "words.txt"
    words.write_bytes(b"wrong\nHello\n")
    completed = run_cli(
        "crack",
        str(path),
        "-w",
        str(words),
        "--no-decrypt",
        "--json",
        "-j",
        "1",
        "-q",
        "--no-status",
    )
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["found"] is True
    assert payload["password"]["text"] == "Hello"
    assert payload["format"] == "aescrypt"


def test_cli_encrypt_v3_roundtrip(tmp_path: Path):
    plain = tmp_path / "plain.txt"
    plain.write_bytes(PLAINTEXT)
    encrypted = tmp_path / "v3.aes"
    completed = run_cli(
        "encrypt",
        str(plain),
        "-p",
        "hunter2",
        "--aescrypt-version",
        "3",
        "--aescrypt-iterations",
        "5",
        "-o",
        str(encrypted),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = AesCryptArtifact(encrypted)
    assert artifact.header.version == 3
    assert artifact.header.iterations == 5
    decrypted = tmp_path / "out.txt"
    completed = run_cli(
        "decrypt",
        str(encrypted),
        "-p",
        "hunter2",
        "-o",
        str(decrypted),
    )
    assert completed.returncode == 0, completed.stderr
    assert decrypted.read_bytes() == PLAINTEXT
