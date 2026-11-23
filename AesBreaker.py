#!/usr/bin/env python3
"""Compatibility launcher for the AES-Breaker command line.

The legacy 1.x flags (--decrypt/--key/--blob) were built on unverifiable mode
guessing and have been removed.  Use ``aesbreaker --help`` or
``python -m aesbreaker --help`` for the current interface.
"""

from __future__ import annotations

import multiprocessing as mp
import sys

from aesbreaker.cli import main

if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
