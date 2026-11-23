"""AES-Breaker: AES decryption and password recovery.

The package distinguishes what can and cannot be verified offline.  Authenticated containers (AES Crypt v1/v2/v3, WinZip AES) are confirmed
with their MAC; ``openssl enc`` output is unauthenticated by design and is
handled with a documented validation policy instead of guesswork.
"""

from __future__ import annotations

__version__ = "2.0.1"
__all__ = ["__version__"]
