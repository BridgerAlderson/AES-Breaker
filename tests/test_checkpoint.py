"""Tests for progress checkpoint state and signatures."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from aesbreaker.checkpoint import (
    CHECKPOINT_VERSION,
    file_identity,
    load_checkpoint,
    make_signature,
    utc_now,
    write_checkpoint,
)
from aesbreaker.errors import FormatError, UsageError


def _state(**overrides) -> dict:
    state = {
        "created": utc_now(),
        "updated": utc_now(),
        "signature": "a" * 64,
        "attempts": 42,
        "weak_candidates": 3,
        "elapsed_seconds": 1.5,
        "completed": False,
        "found": False,
        "interrupted": True,
        "time_limit_reached": False,
        "exhausted": False,
        "errors": [],
        "resumed_from": 0,
        "input": "blob.aes",
        "format": "aescrypt",
        "plan": {"kind": "wordlist", "total": 100},
    }
    state.update(overrides)
    return state


def test_write_and_load_roundtrip(tmp_path: Path):
    path = tmp_path / "progress.json"
    write_checkpoint(path, _state())
    document = load_checkpoint(path)
    assert document["tool"] == "aesbreaker"
    assert document["checkpoint_version"] == CHECKPOINT_VERSION
    assert document["attempts"] == 42
    assert document["completed"] is False
    if os.name != "nt":
        # Windows reports the POSIX-like 0o666 view; it does not expose
        # chmod ownership bits. The file is still created through mkstemp.
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600


def test_signature_is_stable_and_sensitive():
    identity = {"input": "abc", "plan": {"total": 10}}
    first = make_signature(identity)
    assert first == make_signature({"plan": {"total": 10}, "input": "abc"})
    assert first != make_signature({"input": "abd", "plan": {"total": 10}})


def test_file_identity(tmp_path: Path):
    path = tmp_path / "words.txt"
    path.write_bytes(b"a\nb\n")
    identity = file_identity(path)
    assert identity["path"] == str(path.resolve())
    assert identity["size"] == 4
    assert identity["mtime_ns"] > 0
    assert file_identity("-") is None
    missing = file_identity(tmp_path / "absent")
    assert missing["missing"] is True


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(tool="other"),
        lambda d: d.update(checkpoint_version=99),
        lambda d: d.update(attempts=-1),
        lambda d: d.update(completed="no"),
        lambda d: d.update(found="no"),
        lambda d: d.update(signature="short"),
    ],
)
def test_invalid_checkpoint_documents(tmp_path: Path, mutate):
    path = tmp_path / "bad.json"
    document = {
        "tool": "aesbreaker",
        "version": "2.0.1",
        "checkpoint_version": CHECKPOINT_VERSION,
        **_state(),
    }
    mutate(document)
    path.write_text(json.dumps(document))
    with pytest.raises(FormatError):
        load_checkpoint(path)


def test_invalid_json_and_stdout_rejected(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(FormatError):
        load_checkpoint(path)
    with pytest.raises(UsageError):
        write_checkpoint("-", _state())
