from __future__ import annotations

import base64
import io
import shutil
import subprocess
from pathlib import Path

import pytest

from aesbreaker.commands.selftest import OPENSSL_FIXTURES
from aesbreaker.errors import DecryptionError, FormatError, UsageError
from aesbreaker.formats.base import FormatOptions, Outcome, ValidationPolicy
from aesbreaker.formats.openssl_enc import OpenSSLArtifact, encrypt_bytes

from .helpers import PLAINTEXT, make_openssl


def test_external_fixtures(tmp_path: Path):
    for name, (encoded, options, prefix) in OPENSSL_FIXTURES.items():
        path = tmp_path / f"{name}.bin"
        path.write_bytes(base64.b64decode(encoded))
        artifact = OpenSSLArtifact(path, options)
        verifier = artifact.verifier(ValidationPolicy("auto", prefix))
        expected = Outcome.CONFIRMED if prefix else Outcome.PROBABLE
        assert verifier.verify(b"hunter2") >= expected, name
        assert verifier.verify(b"wrong") == Outcome.REJECT, name
        output = io.BytesIO()
        artifact.decrypt(b"hunter2", output)
        assert output.getvalue() == PLAINTEXT, name


def test_cbc_policy_modes(tmp_path: Path):
    path = make_openssl(tmp_path / "cbc.enc", cipher="aes-256-cbc", digest="sha256")
    artifact = OpenSSLArtifact(path, FormatOptions(cipher="aes-256-cbc", digest="sha256"))
    assert artifact.verifier(ValidationPolicy("auto")).verify(b"hunter2") == Outcome.PROBABLE
    assert artifact.verifier(ValidationPolicy("any")).verify(b"hunter2") == Outcome.PROBABLE
    assert artifact.verifier(ValidationPolicy("text")).verify(b"hunter2") == Outcome.PROBABLE
    assert artifact.verifier(ValidationPolicy("magic")).verify(b"hunter2") == Outcome.WEAK
    assert (
        artifact.verifier(ValidationPolicy("auto", b"The quick brown")).verify(b"hunter2")
        == Outcome.CONFIRMED
    )
    with pytest.raises(UsageError):
        artifact.verifier(ValidationPolicy("strict"))


def test_magic_policy(tmp_path: Path):
    png = b"\x89PNG\r\n\x1a\n" + b"payload" * 20
    path = tmp_path / "png.enc"
    path.write_bytes(encrypt_bytes(png, b"hunter2", cipher_name="aes-256-cbc", digest="sha256"))
    artifact = OpenSSLArtifact(path, FormatOptions(cipher="aes-256-cbc", digest="sha256"))
    assert artifact.verifier(ValidationPolicy("magic")).verify(b"hunter2") == Outcome.PROBABLE
    assert artifact.verifier(ValidationPolicy("text")).verify(b"hunter2") == Outcome.WEAK


@pytest.mark.parametrize("mode", ["ctr", "cfb", "ofb"])
def test_stream_modes_require_known_prefix(tmp_path: Path, mode: str):
    path = make_openssl(tmp_path / f"{mode}.enc", cipher=f"aes-256-{mode}", digest="sha256")
    artifact = OpenSSLArtifact(path, FormatOptions(cipher=f"aes-256-{mode}", digest="sha256"))
    with pytest.raises(UsageError):
        artifact.verifier(ValidationPolicy("auto"))
    verifier = artifact.verifier(ValidationPolicy("auto", b"The quick"))
    assert verifier.verify(b"hunter2") == Outcome.CONFIRMED
    assert verifier.verify(b"wrong") == Outcome.REJECT
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


def test_base64_input(tmp_path: Path):
    path = make_openssl(tmp_path / "cbc.enc")
    encoded = tmp_path / "cbc.b64"
    encoded.write_text(base64.encodebytes(path.read_bytes()).decode("ascii"))
    options = FormatOptions(cipher="aes-256-cbc", digest="sha256")
    artifact = OpenSSLArtifact(encoded, options)
    assert artifact.source_encoding == "base64"
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT

    options.in_encoding = "base64"
    artifact = OpenSSLArtifact(encoded, options)
    artifact.decrypt(b"hunter2", io.BytesIO())


def test_nosalt_roundtrip(tmp_path: Path):
    path = make_openssl(
        tmp_path / "nosalt.bin",
        cipher="aes-256-cbc",
        digest="md5",
        salted=False,
    )
    options = FormatOptions(cipher="aes-256-cbc", digest="md5", nosalt=True)
    artifact = OpenSSLArtifact(path, options)
    assert artifact.salt == b""
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT

    with pytest.raises(FormatError):
        OpenSSLArtifact(path, FormatOptions(cipher="aes-256-cbc", digest="md5"))


def test_salted_with_nosalt_flag(tmp_path: Path):
    path = make_openssl(tmp_path / "salted.enc")
    with pytest.raises(FormatError):
        OpenSSLArtifact(
            path,
            FormatOptions(cipher="aes-256-cbc", digest="sha256", nosalt=True),
        )


def test_missing_cipher_cannot_verify(tmp_path: Path):
    path = make_openssl(tmp_path / "cbc.enc")
    artifact = OpenSSLArtifact(path, FormatOptions())
    details = artifact.inspect()
    assert details["cipher"] is None
    with pytest.raises(UsageError):
        artifact.verifier(ValidationPolicy())
    with pytest.raises(UsageError):
        artifact.decrypt(b"hunter2", io.BytesIO())


def test_wrong_password_and_parameters(tmp_path: Path):
    encoded, options, _ = OPENSSL_FIXTURES["md5-cbc256"]
    path = tmp_path / "fixture.enc"
    path.write_bytes(base64.b64decode(encoded))
    artifact = OpenSSLArtifact(path, options)
    assert artifact.verifier(ValidationPolicy()).verify(b"wrong") == Outcome.REJECT
    with pytest.raises(DecryptionError):
        artifact.decrypt(b"wrong", io.BytesIO())

    wrong_digest = OpenSSLArtifact(path, FormatOptions(cipher="aes-256-cbc", digest="sha256"))
    assert wrong_digest.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.REJECT


def test_truncated_ciphertext(tmp_path: Path):
    path = make_openssl(tmp_path / "cbc.enc")
    data = path.read_bytes()[:-1]
    path.write_bytes(data)
    with pytest.raises(FormatError):
        OpenSSLArtifact(path, FormatOptions(cipher="aes-256-cbc", digest="sha256"))


@pytest.mark.parametrize("cipher", ["aes-128-cbc", "aes-192-cbc", "aes-256-cbc"])
@pytest.mark.parametrize("pbkdf2", [False, True])
def test_cbc_roundtrip_parameters(tmp_path: Path, cipher: str, pbkdf2: bool):
    plaintext = b"The quick brown fox jumps over the lazy dog.\n" * 2500  # ~112 KiB
    path = tmp_path / f"{cipher}-{pbkdf2}.enc"
    path.write_bytes(
        encrypt_bytes(
            plaintext,
            b"hunter2",
            cipher_name=cipher,
            digest="sha256",
            use_pbkdf2=pbkdf2,
            iterations=1000,
        )
    )
    options = FormatOptions(cipher=cipher, digest="sha256", pbkdf2=pbkdf2, iterations=1000)
    artifact = OpenSSLArtifact(path, options)
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") >= Outcome.PROBABLE
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == plaintext


def test_ecb_roundtrip(tmp_path: Path):
    path = tmp_path / "ecb.enc"
    path.write_bytes(
        encrypt_bytes(
            PLAINTEXT,
            b"hunter2",
            cipher_name="aes-256-ecb",
            digest="sha256",
        )
    )
    artifact = OpenSSLArtifact(path, FormatOptions(cipher="aes-256-ecb", digest="sha256"))
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") >= Outcome.PROBABLE
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


@pytest.mark.parametrize("mode", ["ctr", "cfb", "ofb"])
def test_stream_roundtrip(tmp_path: Path, mode: str):
    path = tmp_path / f"{mode}.enc"
    path.write_bytes(
        encrypt_bytes(
            PLAINTEXT,
            b"hunter2",
            cipher_name=f"aes-256-{mode}",
            digest="sha256",
        )
    )
    artifact = OpenSSLArtifact(path, FormatOptions(cipher=f"aes-256-{mode}", digest="sha256"))
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


def test_openssl_binary_interoperability(tmp_path: Path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is not installed")
    cases = [
        ("aes-256-cbc", "sha256", False, 10000),
        ("aes-128-cbc", "md5", False, 10000),
        ("aes-192-cbc", "sha256", True, 2000),
        ("aes-256-ctr", "sha256", False, 10000),
        ("aes-256-ecb", "sha256", False, 10000),
        ("aes-256-cfb", "sha256", False, 10000),
        ("aes-256-ofb", "sha256", False, 10000),
    ]
    for cipher, digest, pbkdf2, iterations in cases:
        path = tmp_path / f"{cipher}.enc"
        path.write_bytes(
            encrypt_bytes(
                PLAINTEXT,
                b"hunter2",
                cipher_name=cipher,
                digest=digest,
                use_pbkdf2=pbkdf2,
                iterations=iterations,
            )
        )
        command = [
            openssl,
            "enc",
            "-d",
            f"-{cipher}",
            "-md",
            digest,
            "-in",
            str(path),
            "-pass",
            "pass:hunter2",
        ]
        if pbkdf2:
            command.extend(["-pbkdf2", "-iter", str(iterations)])
        result = subprocess.run(command, capture_output=True, timeout=30)
        assert result.returncode == 0, (cipher, result.stderr)
        assert result.stdout == PLAINTEXT, cipher


def test_nopad_roundtrip_and_prefix(tmp_path: Path):
    plaintext = b"0123456789abcdef" * 2
    path = tmp_path / "nopad.enc"
    path.write_bytes(
        encrypt_bytes(
            plaintext,
            b"hunter2",
            cipher_name="aes-256-cbc",
            digest="sha256",
            nopad=True,
        )
    )
    options = FormatOptions(cipher="aes-256-cbc", digest="sha256", nopad=True)
    artifact = OpenSSLArtifact(path, options)
    with pytest.raises(UsageError):
        artifact.verifier(ValidationPolicy("strict"))
    verifier = artifact.verifier(ValidationPolicy("auto", b"0123456789abcdef"))
    assert verifier.verify(b"hunter2") == Outcome.CONFIRMED
    assert verifier.verify(b"wrong") == Outcome.REJECT
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == plaintext

    # Without a prefix there is no MAC or padding to verify; "any" is
    # meaningless for a padding-less block-mode file.
    with pytest.raises(UsageError):
        artifact.verifier(ValidationPolicy("any"))


def test_nopad_requires_aligned_input(tmp_path: Path):
    with pytest.raises(UsageError):
        encrypt_bytes(
            b"not aligned",
            b"hunter2",
            cipher_name="aes-256-cbc",
            digest="sha256",
            nopad=True,
        )


def test_nopad_openssl_interoperability(tmp_path: Path):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is not installed")
    plaintext = b"0123456789abcdef" * 4
    path = tmp_path / "nopad.enc"
    path.write_bytes(
        encrypt_bytes(
            plaintext,
            b"hunter2",
            cipher_name="aes-256-cbc",
            digest="sha256",
            nopad=True,
        )
    )
    result = subprocess.run(
        [
            openssl,
            "enc",
            "-d",
            "-aes-256-cbc",
            "-nopad",
            "-md",
            "sha256",
            "-in",
            str(path),
            "-pass",
            "pass:hunter2",
        ],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == plaintext


def test_nosalt_base64_requires_explicit_encoding(tmp_path: Path):
    raw = make_openssl(tmp_path / "nosalt.bin", cipher="aes-256-cbc", digest="md5", salted=False)
    encoded = tmp_path / "nosalt.b64"
    encoded.write_text(base64.encodebytes(raw.read_bytes()).decode("ascii"))
    options = FormatOptions(cipher="aes-256-cbc", digest="md5", nosalt=True, in_encoding="base64")
    artifact = OpenSSLArtifact(encoded, options)
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT

    # Auto must not reinterpret an ASCII-looking headerless ciphertext.
    with pytest.raises(FormatError):
        OpenSSLArtifact(
            encoded,
            FormatOptions(cipher="aes-256-cbc", digest="md5", nosalt=True),
        )


def test_short_known_prefix_is_rejected(tmp_path: Path):
    path = make_openssl(tmp_path / "cbc.enc")
    options = FormatOptions(cipher="aes-256-cbc", digest="sha256")
    artifact = OpenSSLArtifact(path, options)
    with pytest.raises(UsageError, match="at least"):
        artifact.verifier(ValidationPolicy("strict", b"T"))
    artifact_with_prefix = OpenSSLArtifact(path, options, policy=ValidationPolicy("auto", b"T"))
    with pytest.raises(UsageError, match="at least"):
        artifact_with_prefix.decrypt(b"hunter2", io.BytesIO())


@pytest.mark.parametrize("mode", ["cfb1", "cfb8"])
def test_cfb1_cfb8_openssl_interop(tmp_path: Path, mode: str):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is not installed")
    source = tmp_path / "plain.bin"
    source.write_bytes(PLAINTEXT)
    encrypted = tmp_path / f"{mode}.enc"
    completed = subprocess.run(
        [
            openssl,
            "enc",
            f"-aes-256-{mode}",
            "-pbkdf2",
            "-iter",
            "1000",
            "-md",
            "sha256",
            "-pass",
            "pass:hunter2",
            "-in",
            str(source),
            "-out",
            str(encrypted),
        ],
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    artifact = OpenSSLArtifact(
        encrypted,
        FormatOptions(
            cipher=f"aes-256-{mode}",
            digest="sha256",
            pbkdf2=True,
            iterations=1000,
        ),
    )
    verifier = artifact.verifier(ValidationPolicy("auto", PLAINTEXT[:8]))
    assert verifier.verify(b"hunter2") == Outcome.CONFIRMED
    assert verifier.verify(b"wrong") == Outcome.REJECT
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


@pytest.mark.parametrize("mode", ["cfb1", "cfb8"])
def test_raw_cfb1_cfb8_roundtrip(mode: str):
    import io as _io

    from aesbreaker.crypto import parse_cipher
    from aesbreaker.formats.raw import RawSpec, decrypt_stream

    key = bytes(range(32))
    iv = bytes(range(16))
    spec = RawSpec(
        cipher=parse_cipher(f"aes-256-{mode}"),
        key=key,
        iv=iv,
        padding="none",
    )
    # Use OpenSSL's own ciphertext shape: encrypt with the same primitive.
    from aesbreaker.crypto import aes_cfb1_cipher, aes_cfb_cipher

    if mode == "cfb1":
        ciphertext = aes_cfb1_cipher(key, iv).encrypt(PLAINTEXT)
    else:
        ciphertext = aes_cfb_cipher(key, iv, segment_size=8).encrypt(PLAINTEXT)
    output = _io.BytesIO()
    decrypt_stream(_io.BytesIO(ciphertext), output, spec)
    assert output.getvalue() == PLAINTEXT
