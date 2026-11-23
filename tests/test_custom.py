"""Tests for the explicit-spec custom AES format."""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES

from aesbreaker.crypto import (
    aes_cbc_encrypt,
    aes_ctr_cipher,
    aes_gcm_encrypt,
    pkcs7_pad,
)
from aesbreaker.errors import FormatError
from aesbreaker.formats.base import Outcome, ValidationPolicy
from aesbreaker.formats.custom import CustomArtifact
from aesbreaker.kdf import evp_bytes_to_key, pbkdf2

from .helpers import PLAINTEXT, json_output, run_cli

SALT = bytes(range(16))
IV = bytes(range(16, 32))
PREFIX = PLAINTEXT[:16]


def _write(path: Path, data: bytes | str) -> Path:
    if isinstance(data, str):
        path.write_text(data)
    else:
        path.write_bytes(data)
    return path


def _cbc_artifact(tmp_path: Path, *, iterations: int = 1000) -> CustomArtifact:
    key = pbkdf2(b"hunter2", SALT, iterations, 32, "sha256")
    ciphertext = aes_cbc_encrypt(key, IV, pkcs7_pad(PLAINTEXT))
    blob = SALT + IV + ciphertext
    _write(tmp_path / "blob.b64", base64.b64encode(blob))
    spec = {
        "version": 1,
        "cipher": "aes-256-cbc",
        "input_encoding": "base64",
        "ciphertext_offset": 32,
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": iterations,
            "salt_offset": 0,
            "salt_length": 16,
        },
        "iv": {"source": "embedded", "offset": 16, "length": 16},
        "padding": "pkcs7",
        "oracle": {"type": "known_prefix", "hex": PREFIX.hex()},
    }
    _write(tmp_path / "spec.json", json.dumps(spec))
    return CustomArtifact(tmp_path / "blob.b64", tmp_path / "spec.json")


def test_cbc_embedded_salt_iv_and_prefix(tmp_path: Path):
    artifact = _cbc_artifact(tmp_path)
    verifier = artifact.verifier(ValidationPolicy())
    assert verifier.verify(b"hunter2") == Outcome.CONFIRMED
    assert verifier.verify(b"wrong") == Outcome.REJECT
    output = io.BytesIO()
    report = artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT
    assert report.bytes_written == len(PLAINTEXT)
    assert "prefix" in report.verification


def test_evp_derived_iv(tmp_path: Path):
    key, iv = evp_bytes_to_key(b"hunter2", SALT, 16, 16, "md5")
    ciphertext = aes_cbc_encrypt(key, iv, pkcs7_pad(PLAINTEXT))
    _write(tmp_path / "evp.bin", SALT + ciphertext)
    spec = {
        "cipher": "aes-128-cbc",
        "input_encoding": "raw",
        "ciphertext_offset": 16,
        "kdf": {
            "type": "evp",
            "digest": "md5",
            "salt_offset": 0,
            "salt_length": 16,
        },
        "iv": {"source": "derived"},
        "padding": "pkcs7",
        "oracle": {"type": "known_prefix", "hex": PREFIX.hex()},
    }
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "evp.bin", tmp_path / "spec.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_ctr_known_prefix_little_endian(tmp_path: Path):
    key = pbkdf2(b"hunter2", b"", 1000, 16, "sha256")
    cipher = aes_ctr_cipher(key, IV, little_endian=True)
    ciphertext = cipher.encrypt(PLAINTEXT)
    _write(tmp_path / "ctr.bin", ciphertext)
    spec = {
        "cipher": "aes-128-ctr",
        "input_encoding": "raw",
        "ctr_little_endian": True,
        "kdf": {"type": "pbkdf2", "digest": "sha256", "iterations": 1000},
        "iv": {"source": "explicit", "hex": IV.hex()},
        "padding": "none",
        "oracle": {"type": "known_prefix", "hex": PREFIX.hex()},
    }
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "ctr.bin", tmp_path / "spec.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


def test_gcm_tag_from_payload_and_aad(tmp_path: Path):
    key = pbkdf2(b"hunter2", SALT, 1000, 32, "sha256")
    nonce = bytes(range(12))
    aad = b"custom-header"
    ciphertext, tag = aes_gcm_encrypt(key, nonce, PLAINTEXT, aad=aad)
    _write(tmp_path / "gcm.bin", nonce + ciphertext + tag)
    spec = {
        "cipher": "aes-256-gcm",
        "input_encoding": "raw",
        "ciphertext_offset": 12,
        "ciphertext_length": len(ciphertext),
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": SALT.hex(),
        },
        "iv": {"source": "embedded", "offset": 0, "length": 12},
        "padding": "none",
        "oracle": {
            "type": "gcm_tag",
            "tag_offset": 12 + len(ciphertext),
            "tag_length": 16,
            "aad_hex": aad.hex(),
        },
    }
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "gcm.bin", tmp_path / "spec.json")
    verifier = artifact.verifier(ValidationPolicy())
    assert verifier.verify(b"hunter2") == Outcome.CONFIRMED
    assert verifier.verify(b"wrong") == Outcome.REJECT
    output = io.BytesIO()
    report = artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT
    assert report.details["authenticated"] is True


def test_gcm_bad_tag_rejected(tmp_path: Path):
    key = pbkdf2(b"hunter2", SALT, 1000, 32, "sha256")
    nonce = bytes(range(12))
    ciphertext, tag = aes_gcm_encrypt(key, nonce, PLAINTEXT)
    bad_tag = bytes([tag[0] ^ 1]) + tag[1:]
    _write(tmp_path / "gcm.bin", nonce + ciphertext + bad_tag)
    spec = {
        "cipher": "aes-256-gcm",
        "input_encoding": "raw",
        "ciphertext_offset": 12,
        "ciphertext_length": len(ciphertext),
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": SALT.hex(),
        },
        "iv": {"source": "embedded", "offset": 0, "length": 12},
        "padding": "none",
        "oracle": {
            "type": "gcm_tag",
            "tag_offset": 12 + len(ciphertext),
            "tag_length": 16,
        },
    }
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "gcm.bin", tmp_path / "spec.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.REJECT


@pytest.mark.parametrize("mode", ["cbc", "ecb"])
def test_known_block(tmp_path: Path, mode: str):
    key = pbkdf2(b"hunter2", b"salt", 1000, 16, "sha256")
    padded = pkcs7_pad(PLAINTEXT)
    if mode == "cbc":
        ciphertext = aes_cbc_encrypt(key, IV, padded)
        iv_spec = {"source": "explicit", "hex": IV.hex()}
    else:
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(padded)
        iv_spec = None
    _write(tmp_path / "block.bin", ciphertext)
    spec = {
        "cipher": "aes-128-" + mode,
        "input_encoding": "raw",
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": b"salt".hex(),
        },
        "padding": "pkcs7",
        "oracle": {
            "type": "known_block",
            "offset": 16,
            "hex": PLAINTEXT[16:32].hex(),
        },
    }
    if iv_spec is not None:
        spec["iv"] = iv_spec
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "block.bin", tmp_path / "spec.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


def test_password_utf16le_encoding(tmp_path: Path):
    salt = b"salt"
    key = pbkdf2("hunter2".encode("utf-16-le"), salt, 1000, 16, "sha256")
    ciphertext = aes_cbc_encrypt(key, IV, pkcs7_pad(PLAINTEXT))
    _write(tmp_path / "utf16.bin", ciphertext)
    spec = {
        "cipher": "aes-128-cbc",
        "input_encoding": "raw",
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": salt.hex(),
            "password_encoding": "utf-16-le",
        },
        "iv": {"source": "explicit", "hex": IV.hex()},
        "padding": "pkcs7",
        "oracle": {"type": "known_prefix", "hex": PREFIX.hex()},
    }
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "utf16.bin", tmp_path / "spec.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_heuristic_requires_explicit_flag(tmp_path: Path):
    _cbc_artifact(tmp_path)
    document = json.loads((tmp_path / "spec.json").read_text())
    del document["oracle"]
    _write(tmp_path / "no_oracle.json", json.dumps(document))
    with pytest.raises(FormatError, match="oracle"):
        CustomArtifact(tmp_path / "blob.b64", tmp_path / "no_oracle.json")

    document["allow_heuristic"] = True
    _write(tmp_path / "heuristic.json", json.dumps(document))
    artifact = CustomArtifact(tmp_path / "blob.b64", tmp_path / "heuristic.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.PROBABLE
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(oracle={"type": "known_prefix", "hex": "00"}),
        lambda s: s.update(unknown_key=True),
        lambda s: s.update(version=2),
        lambda s: s["kdf"].update(salt_offset=1000),
        lambda s: s["iv"].update(length=8),
        lambda s: s.update(ctr_little_endian=True),
        lambda s: s.update(ciphertext_offset=10_000),
        lambda s: s["oracle"].update(aad_hex="00"),
    ],
)
def test_invalid_specs_are_rejected(tmp_path: Path, mutate):
    _cbc_artifact(tmp_path)
    document = json.loads((tmp_path / "spec.json").read_text())
    mutate(document)
    _write(tmp_path / "bad.json", json.dumps(document))
    with pytest.raises(FormatError):
        CustomArtifact(tmp_path / "blob.b64", tmp_path / "bad.json")


def test_gcm_requires_tag_not_plaintext_prefix(tmp_path: Path):
    spec = {
        "cipher": "aes-256-gcm",
        "input_encoding": "raw",
        "kdf": {"type": "pbkdf2", "digest": "sha256", "iterations": 1000},
        "iv": {"source": "explicit", "hex": "00" * 12},
        "padding": "none",
        "oracle": {"type": "known_prefix", "hex": PREFIX.hex()},
    }
    _write(tmp_path / "blob.bin", b"\x00" * 32)
    _write(tmp_path / "spec.json", json.dumps(spec))
    with pytest.raises(FormatError, match="gcm_tag"):
        CustomArtifact(tmp_path / "blob.bin", tmp_path / "spec.json")


def test_cli_custom_crack_inspect_and_decrypt(tmp_path: Path):
    artifact = _cbc_artifact(tmp_path)
    words = _write(tmp_path / "words.txt", b"wrong\nhunter2\n")
    expected = _write(tmp_path / "expected.bin", PLAINTEXT)

    output = tmp_path / "out.bin"
    completed = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(words),
        "-j",
        "1",
        "-q",
        "--no-status",
        "-o",
        str(output),
        "--overwrite",
    )
    assert completed.returncode == 0, completed.stderr
    assert output.read_bytes() == expected.read_bytes()
    assert b"confirmed" in completed.stdout

    completed = run_cli(
        "inspect",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "--json",
    )
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["format"] == "custom"
    assert payload["details"]["oracle"] == "known_prefix"

    decrypted = tmp_path / "dec.bin"
    completed = run_cli(
        "decrypt",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-p",
        "hunter2",
        "-o",
        str(decrypted),
        "--overwrite",
    )
    assert completed.returncode == 0, completed.stderr
    assert decrypted.read_bytes() == PLAINTEXT
    assert b"not independently authenticated" in completed.stdout
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_cli_custom_spec_errors_and_protection(tmp_path: Path):
    _cbc_artifact(tmp_path)
    completed = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "-w",
        str(_write(tmp_path / "words.txt", b"hunter2\n")),
        "-q",
    )
    assert completed.returncode == 2
    assert b"--spec" in completed.stderr

    completed = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "--known-prefix",
        "T",
        "-w",
        str(tmp_path / "words.txt"),
        "-q",
    )
    assert completed.returncode == 2

    original = (tmp_path / "spec.json").read_bytes()
    completed = run_cli(
        "inspect",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "--json-out",
        str(tmp_path / "spec.json"),
    )
    assert completed.returncode == 2
    assert (tmp_path / "spec.json").read_bytes() == original

    completed = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(tmp_path / "words.txt"),
        "--no-decrypt",
        "--json-out",
        str(tmp_path / "spec.json"),
        "-q",
    )
    assert completed.returncode == 2
    assert (tmp_path / "spec.json").read_bytes() == original

    completed = run_cli(
        "decrypt",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-p",
        "hunter2",
        "-o",
        str(tmp_path / "spec.json"),
        "--overwrite",
    )
    assert completed.returncode == 2
    assert (tmp_path / "spec.json").read_bytes() == original


def test_gcm_tag_offset_defaults_ciphertext_length(tmp_path: Path):
    key = pbkdf2(b"hunter2", SALT, 1000, 32, "sha256")
    nonce = bytes(range(12))
    ciphertext, tag = aes_gcm_encrypt(key, nonce, PLAINTEXT)
    _write(tmp_path / "gcm.bin", nonce + ciphertext + tag)
    spec = {
        "cipher": "aes-256-gcm",
        "input_encoding": "raw",
        "ciphertext_offset": 12,
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": SALT.hex(),
        },
        "iv": {"source": "embedded", "offset": 0, "length": 12},
        "padding": "none",
        "oracle": {
            "type": "gcm_tag",
            "tag_offset": 12 + len(ciphertext),
            "tag_length": 16,
        },
    }
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "gcm.bin", tmp_path / "spec.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_gcm_derived_nonce(tmp_path: Path):
    salt = b"nonce-salt"
    material = pbkdf2(b"hunter2", salt, 1000, 32 + 12, "sha256")
    key, nonce = material[:32], material[32:]
    ciphertext, tag = aes_gcm_encrypt(key, nonce, PLAINTEXT)
    _write(tmp_path / "gcm.bin", ciphertext)
    spec = {
        "cipher": "aes-256-gcm",
        "input_encoding": "raw",
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": salt.hex(),
        },
        "iv": {"source": "derived", "length": 12},
        "padding": "none",
        "oracle": {"type": "gcm_tag", "tag_hex": tag.hex()},
    }
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "gcm.bin", tmp_path / "spec.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_hex_input(tmp_path: Path):
    artifact = _cbc_artifact(tmp_path)
    blob = base64.b64decode((tmp_path / "blob.b64").read_bytes())
    _write(tmp_path / "blob.hex", blob.hex())
    document = json.loads((tmp_path / "spec.json").read_text())
    document["input_encoding"] = "hex"
    _write(tmp_path / "spec-hex.json", json.dumps(document))
    artifact = CustomArtifact(tmp_path / "blob.hex", tmp_path / "spec-hex.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_ecb_rejects_iv_and_tag_overlap(tmp_path: Path):
    _cbc_artifact(tmp_path)
    document = json.loads((tmp_path / "spec.json").read_text())
    document["cipher"] = "aes-128-ecb"
    _write(tmp_path / "bad-ecb.json", json.dumps(document))
    with pytest.raises(FormatError, match="ECB"):
        CustomArtifact(tmp_path / "blob.b64", tmp_path / "bad-ecb.json")

    gcm = {
        "cipher": "aes-256-gcm",
        "input_encoding": "raw",
        "ciphertext_offset": 12,
        "ciphertext_length": 32,
        "kdf": {"type": "pbkdf2", "digest": "sha256", "iterations": 1000},
        "iv": {"source": "embedded", "offset": 0, "length": 12},
        "padding": "none",
        "oracle": {"type": "gcm_tag", "tag_offset": 12, "tag_length": 16},
    }
    _write(tmp_path / "gcm.bin", b"\x00" * 64)
    _write(tmp_path / "gcm-overlap.json", json.dumps(gcm))
    with pytest.raises(FormatError, match="overlap"):
        CustomArtifact(tmp_path / "gcm.bin", tmp_path / "gcm-overlap.json")


def test_cli_custom_multiprocess(tmp_path: Path):
    _cbc_artifact(tmp_path)
    words = _write(tmp_path / "words.txt", b"wrong\nhunter2\n")
    output = tmp_path / "out.bin"
    completed = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(words),
        "-j",
        "2",
        "-q",
        "--no-status",
        "-o",
        str(output),
        "--overwrite",
    )
    assert completed.returncode == 0, completed.stderr
    assert output.read_bytes() == PLAINTEXT


@pytest.mark.parametrize(
    ("kdf_type", "digest", "extra"),
    [
        ("pbkdf2", "sha256", ["-pbkdf2", "-iter", "1000"]),
        ("evp", "md5", []),
    ],
)
def test_headerless_openssl_interop(tmp_path: Path, kdf_type: str, digest: str, extra: list[str]):
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is not installed")
    plain = _write(tmp_path / "plain.bin", PLAINTEXT)
    ciphertext = tmp_path / "openssl.enc"
    completed = subprocess.run(
        [
            openssl,
            "enc",
            "-aes-256-cbc",
            "-md",
            digest,
            *extra,
            "-S",
            "0011223344556677",
            "-in",
            str(plain),
            "-out",
            str(ciphertext),
            "-pass",
            "pass:hunter2",
        ],
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    spec = {
        "cipher": "aes-256-cbc",
        "input_encoding": "raw",
        "ciphertext_offset": 0,
        "kdf": {
            "type": kdf_type,
            "digest": digest,
            "salt_hex": "0011223344556677",
        },
        "iv": {"source": "derived"},
        "padding": "pkcs7",
        "oracle": {"type": "known_prefix", "hex": PREFIX.hex()},
    }
    if kdf_type == "pbkdf2":
        spec["kdf"]["iterations"] = 1000
    _write(tmp_path / "spec.json", json.dumps(spec))
    artifact = CustomArtifact(ciphertext, tmp_path / "spec.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


def test_checkpoint_resume_and_completion(tmp_path: Path):
    _cbc_artifact(tmp_path, iterations=500_000)
    words = _write(tmp_path / "checkpoint-words.txt", b"wrong\nhunter2\n")
    checkpoint = tmp_path / "progress.json"
    common_args = [
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(words),
        "--no-decrypt",
        "--json",
        "-j",
        "1",
        "-q",
        "--no-status",
    ]
    first = run_cli(
        *common_args,
        "--max-runtime",
        "0.01",
        "--checkpoint",
        str(checkpoint),
    )
    assert first.returncode == 124, first.stderr
    first_payload = json_output(first)
    assert first_payload["time_limit_reached"] is True
    assert first_payload["resumed_from"] == 0
    document = json.loads(checkpoint.read_text())
    assert document["attempts"] >= 1
    assert document["completed"] is False
    assert document["found"] is False

    second = run_cli(
        *common_args,
        "--resume",
        str(checkpoint),
    )
    assert second.returncode == 0, second.stderr
    second_payload = json_output(second)
    assert second_payload["found"] is True
    assert second_payload["password"]["text"] == "hunter2"
    assert second_payload["resumed_from"] == document["attempts"]
    assert second_payload["total_attempts"] >= document["attempts"] + 1
    completed = json.loads(checkpoint.read_text())
    assert completed["completed"] is True
    assert completed["found"] is True

    third = run_cli(*common_args, "--resume", str(checkpoint))
    assert third.returncode == 2
    assert b"already complete" in third.stderr


def test_checkpoint_mismatch_and_existing_file(tmp_path: Path):
    _cbc_artifact(tmp_path, iterations=500_000)
    words = _write(tmp_path / "checkpoint-words.txt", b"wrong\nhunter2\n")
    checkpoint = tmp_path / "progress.json"
    first = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(words),
        "--no-decrypt",
        "--json",
        "--max-runtime",
        "0.01",
        "--checkpoint",
        str(checkpoint),
        "-j",
        "1",
        "-q",
        "--no-status",
    )
    assert first.returncode == 124

    # An existing checkpoint is never clobbered without --resume/--overwrite.
    existing = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(words),
        "--no-decrypt",
        "--max-runtime",
        "0.01",
        "--checkpoint",
        str(checkpoint),
        "-q",
        "--no-status",
    )
    assert existing.returncode == 2
    assert b"already exists" in existing.stderr

    words.write_bytes(b"wrong\nhunter2\nextra\n")
    mismatch = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(words),
        "--no-decrypt",
        "--resume",
        str(checkpoint),
        "-q",
        "--no-status",
    )
    assert mismatch.returncode == 2
    assert b"does not match" in mismatch.stderr

    original = words.read_bytes()
    collision = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(words),
        "--no-decrypt",
        "--checkpoint",
        str(words),
        "-q",
        "--no-status",
    )
    assert collision.returncode == 2
    assert b"overwrite input" in collision.stderr
    assert words.read_bytes() == original


def test_max_runtime_without_checkpoint(tmp_path: Path):
    _cbc_artifact(tmp_path, iterations=500_000)
    words = _write(tmp_path / "runtime-words.txt", b"wrong\nhunter2\n")
    completed = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "-w",
        str(words),
        "--no-decrypt",
        "--json",
        "--max-runtime",
        "0.01",
        "-j",
        "1",
        "-q",
        "--no-status",
    )
    assert completed.returncode == 124
    payload = json_output(completed)
    assert payload["time_limit_reached"] is True
    assert payload["checkpoint"] is None
    assert payload["found"] is False


def test_checkpoint_rejected_with_dry_run(tmp_path: Path):
    _cbc_artifact(tmp_path, iterations=1000)
    completed = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "--mask",
        "?d",
        "--dry-run",
        "--max-runtime",
        "1",
        "-q",
    )
    assert completed.returncode == 2
    completed = run_cli(
        "crack",
        str(tmp_path / "blob.b64"),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "spec.json"),
        "--mask",
        "?d",
        "--dry-run",
        "--checkpoint",
        str(tmp_path / "progress.json"),
        "-q",
    )
    assert completed.returncode == 2


def test_aes192_and_truncated_gcm_tag(tmp_path: Path):
    key = pbkdf2(b"hunter2", SALT, 1000, 24, "sha256")
    ciphertext = aes_cbc_encrypt(key, IV, pkcs7_pad(PLAINTEXT))
    _write(tmp_path / "aes192.bin", ciphertext)
    spec = {
        "cipher": "aes-192-cbc",
        "input_encoding": "raw",
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": SALT.hex(),
        },
        "iv": {"source": "explicit", "hex": IV.hex()},
        "padding": "pkcs7",
        "oracle": {"type": "known_prefix", "hex": PREFIX.hex()},
    }
    _write(tmp_path / "aes192.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "aes192.bin", tmp_path / "aes192.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED

    gcm_key = pbkdf2(b"hunter2", SALT, 1000, 32, "sha256")
    nonce = bytes(range(12))
    gcm_ct, gcm_tag = aes_gcm_encrypt(gcm_key, nonce, PLAINTEXT)
    _write(tmp_path / "gcm8.bin", nonce + gcm_ct + gcm_tag[:8])
    gcm_spec = {
        "cipher": "aes-256-gcm",
        "input_encoding": "raw",
        "ciphertext_offset": 12,
        "ciphertext_length": len(gcm_ct),
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": SALT.hex(),
        },
        "iv": {"source": "embedded", "offset": 0, "length": 12},
        "padding": "none",
        "oracle": {
            "type": "gcm_tag",
            "tag_offset": 12 + len(gcm_ct),
            "tag_length": 8,
        },
    }
    _write(tmp_path / "gcm8.json", json.dumps(gcm_spec))
    gcm_artifact = CustomArtifact(tmp_path / "gcm8.bin", tmp_path / "gcm8.json")
    assert gcm_artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    output = io.BytesIO()
    gcm_artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == PLAINTEXT


def test_spec_with_utf8_bom(tmp_path: Path):
    artifact = _cbc_artifact(tmp_path)
    document = json.loads((tmp_path / "spec.json").read_text())
    _write(
        tmp_path / "bom.json",
        b"\xef\xbb\xbf" + json.dumps(document).encode("utf-8"),
    )
    artifact = CustomArtifact(tmp_path / "blob.b64", tmp_path / "bom.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_scrypt_and_hkdf_custom_kdfs(tmp_path: Path):
    import hashlib

    from aesbreaker.crypto import aes_ctr_cipher
    from aesbreaker.kdf import hkdf

    plain = b'{"kdf": "scrypt"}'
    material = hashlib.scrypt(b"hunter2", salt=SALT, n=1024, r=8, p=1, dklen=48)
    key, iv = material[:32], material[32:]
    _write(tmp_path / "scrypt.bin", aes_cbc_encrypt(key, iv, pkcs7_pad(plain)))
    spec = {
        "cipher": "aes-256-cbc",
        "input_encoding": "raw",
        "kdf": {
            "type": "scrypt",
            "n": 1024,
            "r": 8,
            "p": 1,
            "salt_hex": SALT.hex(),
        },
        "iv": {"source": "derived"},
        "padding": "pkcs7",
        "oracle": {"type": "known_prefix", "hex": plain[:8].hex()},
    }
    _write(tmp_path / "scrypt.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "scrypt.bin", tmp_path / "scrypt.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    out = io.BytesIO()
    artifact.decrypt(b"hunter2", out)
    assert out.getvalue() == plain

    info = b"custom-context"
    material = hkdf(b"hunter2", SALT, info, 32 + 16, "sha256")
    key, iv = material[:32], material[32:]
    _write(tmp_path / "hkdf.bin", aes_ctr_cipher(key, iv).encrypt(plain))
    spec = {
        "cipher": "aes-256-ctr",
        "input_encoding": "raw",
        "kdf": {
            "type": "hkdf",
            "digest": "sha256",
            "salt_hex": SALT.hex(),
            "info_hex": info.hex(),
        },
        "iv": {"source": "derived"},
        "padding": "none",
        "oracle": {"type": "known_prefix", "hex": plain[:8].hex()},
    }
    _write(tmp_path / "hkdf.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "hkdf.bin", tmp_path / "hkdf.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_custom_cfb_and_ofb_modes(tmp_path: Path):
    from aesbreaker.crypto import aes_cfb_cipher, aes_ofb_cipher

    plain = b'{"mode": "stream"}'
    for mode, encryptor in (
        ("cfb", aes_cfb_cipher),
        ("cfb8", lambda key, iv: aes_cfb_cipher(key, iv, segment_size=8)),
        ("ofb", aes_ofb_cipher),
    ):
        _write(tmp_path / f"{mode}.bin", encryptor(bytes(range(32)), IV).encrypt(plain))
        spec = {
            "cipher": f"aes-256-{mode}",
            "input_encoding": "raw",
            "kdf": {"type": "pbkdf2", "digest": "sha256", "iterations": 1000},
            "iv": {"source": "explicit", "hex": IV.hex()},
            "padding": "none",
            "oracle": {"type": "known_prefix", "hex": plain[:8].hex()},
        }
        _write(tmp_path / f"{mode}.json", json.dumps(spec))
        artifact = CustomArtifact(tmp_path / f"{mode}.bin", tmp_path / f"{mode}.json")
        # The key above is raw; ask the KDF for the actual key.
        actual_key = pbkdf2(b"hunter2", b"", 1000, 32, "sha256")
        _write(
            tmp_path / f"{mode}.bin",
            encryptor(actual_key, IV).encrypt(plain),
        )
        artifact = CustomArtifact(tmp_path / f"{mode}.bin", tmp_path / f"{mode}.json")
        assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_argon2_custom_kdf(tmp_path: Path):
    pytest.importorskip("argon2")
    from argon2.low_level import Type, hash_secret_raw

    plain = b'{"kdf": "argon2id"}'
    material = hash_secret_raw(
        secret=b"hunter2",
        salt=SALT,
        time_cost=2,
        memory_cost=1024,
        parallelism=1,
        hash_len=48,
        type=Type.ID,
    )
    key, iv = material[:32], material[32:]
    _write(tmp_path / "argon2.bin", aes_cbc_encrypt(key, iv, pkcs7_pad(plain)))
    spec = {
        "cipher": "aes-256-cbc",
        "input_encoding": "raw",
        "kdf": {
            "type": "argon2",
            "time_cost": 2,
            "memory_cost": 1024,
            "parallelism": 1,
            "salt_hex": SALT.hex(),
        },
        "iv": {"source": "derived"},
        "padding": "pkcs7",
        "oracle": {"type": "known_prefix", "hex": plain[:8].hex()},
    }
    _write(tmp_path / "argon2.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "argon2.bin", tmp_path / "argon2.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == plain


def test_custom_encrypt_writer_and_cli(tmp_path: Path):
    from aesbreaker.formats.custom import encrypt_document

    plain = b'{"hello": "writer"}'
    spec = {
        "cipher": "aes-256-cbc",
        "input_encoding": "raw",
        "ciphertext_offset": 32,
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_offset": 0,
            "salt_length": 16,
        },
        "iv": {"source": "embedded", "offset": 16, "length": 16},
        "padding": "pkcs7",
        "oracle": {"type": "known_prefix", "hex": b'{"hello"'.hex()},
    }
    blob = encrypt_document(spec, plain, b"hunter2")
    _write(tmp_path / "written.bin", blob)
    _write(tmp_path / "written.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "written.bin", tmp_path / "written.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == plain

    source = _write(tmp_path / "plain.bin", plain)
    encrypted = tmp_path / "cli.custom"
    completed = run_cli(
        "encrypt",
        str(source),
        "--format",
        "custom",
        "--spec",
        str(tmp_path / "written.json"),
        "-p",
        "hunter2",
        "-o",
        str(encrypted),
    )
    assert completed.returncode == 0, completed.stderr
    artifact = CustomArtifact(encrypted, tmp_path / "written.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED


def test_custom_encrypt_gcm_writer(tmp_path: Path):
    from aesbreaker.formats.custom import encrypt_document

    plain = b"gcm writer payload"
    spec = {
        "cipher": "aes-256-gcm",
        "input_encoding": "raw",
        "ciphertext_offset": 12,
        "kdf": {
            "type": "pbkdf2",
            "digest": "sha256",
            "iterations": 1000,
            "salt_hex": SALT.hex(),
        },
        "iv": {"source": "embedded", "offset": 0, "length": 12},
        "padding": "none",
        "oracle": {"type": "gcm_tag", "tag_offset": 12 + len(plain), "tag_length": 16},
    }
    blob = encrypt_document(spec, plain, b"hunter2")
    _write(tmp_path / "gcm.bin", blob)
    _write(tmp_path / "gcm.json", json.dumps(spec))
    artifact = CustomArtifact(tmp_path / "gcm.bin", tmp_path / "gcm.json")
    assert artifact.verifier(ValidationPolicy()).verify(b"hunter2") == Outcome.CONFIRMED
    output = io.BytesIO()
    artifact.decrypt(b"hunter2", output)
    assert output.getvalue() == plain
