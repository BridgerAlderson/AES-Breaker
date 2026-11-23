"""Deterministic mutation regression for container and spec parsers."""

from __future__ import annotations

import base64
import json
import random
from pathlib import Path

from aesbreaker.crypto import aes_cbc_encrypt, pkcs7_pad
from aesbreaker.errors import AesBreakerError
from aesbreaker.formats import detect_and_open
from aesbreaker.formats.custom import CustomArtifact
from aesbreaker.kdf import pbkdf2

from .helpers import PLAINTEXT, make_aescrypt, make_openssl, make_zip


def _mutate(data: bytes, rng: random.Random) -> bytes:
    mutated = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        action = rng.choice(("flip", "flip", "truncate", "append", "delete"))
        if action == "flip" and mutated:
            index = rng.randrange(len(mutated))
            mutated[index] ^= 1 << rng.randrange(8)
        elif action == "truncate" and mutated:
            mutated = mutated[: rng.randrange(len(mutated))]
        elif action == "append":
            mutated.extend(rng.randbytes(rng.randint(1, 8)))
        elif action == "delete" and len(mutated) > 1:
            index = rng.randrange(len(mutated))
            del mutated[index]
    return bytes(mutated)


def _exercise(path: Path, *, custom_spec: Path | None = None) -> None:
    try:
        if custom_spec is None:
            artifact = detect_and_open(path, "auto")
        else:
            artifact = CustomArtifact(path, custom_spec)
        artifact.inspect()
    except AesBreakerError:
        return


def test_container_parser_mutations_do_not_escape(tmp_path: Path):
    base = tmp_path / "base"
    base.mkdir()
    sources = {
        "aescrypt": make_aescrypt(base / "a.aes").read_bytes(),
        "openssl": make_openssl(base / "o.enc").read_bytes(),
        "zip": make_zip(base / "z.zip").read_bytes(),
    }
    rng = random.Random(0xA35)
    for name, data in sources.items():
        for index in range(100):
            target = tmp_path / f"{name}-{index}.bin"
            target.write_bytes(_mutate(data, rng))
            _exercise(target)


def test_custom_parser_and_spec_mutations_do_not_escape(tmp_path: Path):
    salt = bytes(range(16))
    iv = bytes(range(16, 32))
    key = pbkdf2(b"hunter2", salt, 1000, 32, "sha256")
    blob = salt + iv + aes_cbc_encrypt(key, iv, pkcs7_pad(PLAINTEXT))
    spec = {
        "cipher": "aes-256-cbc",
        "input_encoding": "base64",
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
        "oracle": {"type": "known_prefix", "hex": PLAINTEXT[:16].hex()},
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))

    rng = random.Random(0xC057)
    for index in range(100):
        target = tmp_path / f"custom-{index}.b64"
        target.write_bytes(base64.b64encode(_mutate(blob, rng)))
        _exercise(target, custom_spec=spec_path)

    for index in range(100):
        mutated = dict(spec)
        key_to_change = rng.choice(list(mutated))
        if key_to_change == "kdf":
            nested = dict(mutated["kdf"])
            nested_key = rng.choice(list(nested))
            nested[nested_key] = rng.choice([None, 0, -1, "bad", [], {}])
            mutated["kdf"] = nested
        elif key_to_change == "iv":
            mutated["iv"] = rng.choice([None, {}, {"source": "zero"}])
        elif key_to_change == "oracle":
            mutated["oracle"] = rng.choice([None, {}, {"type": "known_prefix", "hex": "00"}])
        else:
            mutated[key_to_change] = rng.choice([None, 0, -1, "bad", [], {}])
        target_spec = tmp_path / f"bad-spec-{index}.json"
        target_spec.write_text(json.dumps(mutated))
        _exercise(tmp_path / "custom-0.b64", custom_spec=target_spec)
