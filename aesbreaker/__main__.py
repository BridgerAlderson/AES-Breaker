"""``python -m aesbreaker`` entry point."""

from __future__ import annotations

import multiprocessing as mp

from .cli import main

if __name__ == "__main__":
    mp.freeze_support()
    raise SystemExit(main())
