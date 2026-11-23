"""Attack progress checkpoints.

A checkpoint stores a candidate-stream position, not a password.  It is bound
to a signature of the input, plan, verifier, and candidate source metadata so a
resume cannot silently continue against a different wordlist or cipher
parameters.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from . import __version__
from .errors import FormatError, UsageError
from .util import write_json

CHECKPOINT_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_signature(identity: dict) -> str:
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def file_identity(path: Optional[str | Path]) -> Optional[dict]:
    """Path plus cheap size/mtime identity for candidate-source files."""
    if path is None or str(path) == "-":
        return None
    resolved = Path(path).expanduser()
    try:
        stat = resolved.stat()
    except OSError:
        return {"path": str(resolved), "missing": True}
    return {
        "path": str(resolved.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def load_checkpoint(path: str | Path) -> dict:
    checkpoint_path = Path(path)
    try:
        raw = checkpoint_path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise FormatError(f"cannot read checkpoint {checkpoint_path}: {exc}") from None
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FormatError(f"checkpoint is not valid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise FormatError("checkpoint must be a JSON object")
    if document.get("tool") != "aesbreaker":
        raise FormatError("checkpoint was not written by AES-Breaker")
    if document.get("checkpoint_version") != CHECKPOINT_VERSION:
        raise FormatError(
            "unsupported checkpoint version "
            f"{document.get('checkpoint_version')!r}; expected {CHECKPOINT_VERSION}"
        )
    attempts = document.get("attempts")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
        raise FormatError("checkpoint has an invalid attempts position")
    if not isinstance(document.get("completed"), bool):
        raise FormatError("checkpoint has no valid completed flag")
    if not isinstance(document.get("found"), bool):
        raise FormatError("checkpoint has no valid found flag")
    signature = document.get("signature")
    if not isinstance(signature, str) or len(signature) != 64:
        raise FormatError("checkpoint has no valid signature")
    return document


def write_checkpoint(path: str | Path, state: dict) -> None:
    destination = str(path)
    if destination == "-":
        raise UsageError("checkpoint path cannot be '-'")
    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "checkpoint_version": CHECKPOINT_VERSION,
        **state,
    }
    write_json(destination, payload)
