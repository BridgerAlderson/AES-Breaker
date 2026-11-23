"""User-facing error types.

Every expected failure path raises one of these instead of leaking a raw
traceback.  ``exit_code`` is consumed by :mod:`aesbreaker.cli`.
"""

from __future__ import annotations


class AesBreakerError(Exception):
    """Base class for errors that should be reported without a traceback."""

    exit_code = 2

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message}\n  hint: {self.hint}"
        return self.message


class UsageError(AesBreakerError):
    """Invalid combination of options or arguments."""


class InputError(AesBreakerError):
    """An input file or value is missing, unreadable, or malformed."""


class FormatError(AesBreakerError):
    """The input is not a supported container, or its structure is invalid."""


class UnsupportedError(AesBreakerError):
    """The container is recognized but uses an unsupported feature."""


class OutputError(AesBreakerError):
    """The requested output cannot be written safely."""


class VerificationError(AesBreakerError):
    """A candidate password could not be verified."""

    exit_code = 3


class DecryptionError(AesBreakerError):
    """The password is known but the payload cannot be decrypted or checked."""

    exit_code = 3
