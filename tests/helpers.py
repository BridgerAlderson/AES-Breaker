"""Shared helpers for the test-suite."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from aesbreaker.formats.aescrypt import encrypt_bytes as aescrypt_encrypt_bytes  # noqa: E402
from aesbreaker.formats.openssl_enc import encrypt_bytes as openssl_encrypt_bytes  # noqa: E402
from aesbreaker.formats.zip_aes import build_zip_aes  # noqa: E402

PLAINTEXT = b"The quick brown fox jumps over the lazy dog.\nSecond line for padding.\n"


def make_aescrypt(
    path: Path,
    *,
    password: bytes = b"hunter2",
    data: bytes = PLAINTEXT,
) -> Path:
    path.write_bytes(aescrypt_encrypt_bytes(data, password, created_by="test"))
    return path


def make_openssl(
    path: Path,
    *,
    password: bytes = b"hunter2",
    cipher: str = "aes-256-cbc",
    digest: str = "sha256",
    pbkdf2: bool = False,
    iterations: int = 10000,
    salted: bool = True,
    data: bytes = PLAINTEXT,
) -> Path:
    path.write_bytes(
        openssl_encrypt_bytes(
            data,
            password,
            cipher_name=cipher,
            digest=digest,
            use_pbkdf2=pbkdf2,
            iterations=iterations,
            salted=salted,
        )
    )
    return path


def make_zip(
    path: Path,
    *,
    password: bytes = b"hunter2",
    data: bytes = PLAINTEXT,
    name: str = "secret.txt",
    strength: int = 3,
    compression: str = "deflate",
) -> Path:
    path.write_bytes(
        build_zip_aes(name, data, password, strength=strength, compression=compression)
    )
    return path


def run_cli(
    *arguments: str,
    input_bytes: Optional[bytes] = None,
    cwd: Path = REPO_ROOT,
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "aesbreaker", *arguments],
        input=input_bytes,
        capture_output=True,
        cwd=str(cwd),
        env=env,
        timeout=120,
    )


def json_output(completed: subprocess.CompletedProcess) -> dict:
    try:
        return json.loads(completed.stdout.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - diagnostic aid
        raise AssertionError(
            f"stdout is not JSON: {completed.stdout!r}\nstderr={completed.stderr!r}"
        ) from exc
