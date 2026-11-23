"""Parallel candidate verification engine.

Design invariants:

* workers never write output files, so terminating one cannot corrupt a
  decrypted artifact;
* a confirmed/probable hit sets a shared stop event and every worker checks it
  between candidates;
* the feeder thread uses bounded queues with timeouts so shutdown cannot
  deadlock;
* counts are flushed from workers periodically and again on exit, making the
  reported attempt count accurate except for candidates lost to a forced
  terminate after a crash.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import queue
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional, TextIO

from .candidates import AttackPlan
from .errors import UsageError
from .formats.base import Outcome, Verifier
from .util import (
    format_count,
    format_duration,
    format_percent,
    format_rate,
    is_tty,
)

MAX_WORKERS = 256
DEFAULT_BATCH_SIZE = 256
FLUSH_EVERY = 256


@dataclass(frozen=True)
class Hit:
    candidate: bytes
    outcome: Outcome


@dataclass
class AttackResult:
    found: Optional[bytes]
    outcome: Outcome
    attempts: int
    elapsed: float
    rate: float
    weak: int = 0
    interrupted: bool = False
    time_limit_reached: bool = False
    exhausted: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.found is not None


@dataclass
class AttackConfig:
    jobs: int = 0
    batch_size: int = DEFAULT_BATCH_SIZE
    status_interval: float = 2.0
    show_status: bool = True
    quiet: bool = False
    max_runtime: Optional[float] = None


class StatusPrinter:
    def __init__(
        self,
        stream: TextIO = sys.stderr,
        *,
        total: Optional[int],
        total_is_upper: bool,
        interval: float,
        enabled: bool,
    ) -> None:
        self.stream = stream
        self.total = total
        self.total_is_upper = total_is_upper
        self.interval = max(0.1, interval)
        self.enabled = enabled
        self._last = 0.0
        self._wrote = False
        self._tty = is_tty(stream)

    def maybe_update(
        self, attempts: int, elapsed: float, weak: int, *, force: bool = False
    ) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and now - self._last < self.interval:
            return
        self._last = now
        rate = attempts / elapsed if elapsed > 0 else 0.0
        if self.total is not None:
            percent = format_percent(attempts, self.total)
            total_text = f"{'<=' if self.total_is_upper else ''}{format_count(self.total)}"
            if rate > 0:
                remaining = max(0, self.total - attempts)
                eta = format_duration(remaining / rate)
            else:
                eta = "--:--:--"
            line = (
                f"[{format_duration(elapsed)}] {format_count(attempts)}/{total_text} "
                f"({percent}) {format_rate(rate)} ETA {eta}"
            )
            if self.total_is_upper:
                line += " (upper bound)"
        else:
            line = f"[{format_duration(elapsed)}] {format_count(attempts)} {format_rate(rate)}"
        if weak:
            line += f" weak={format_count(weak)}"
        if self._tty:
            self.stream.write("\r" + line)
        else:
            self.stream.write(line + "\n")
        self.stream.flush()
        self._wrote = True

    def finish(self) -> None:
        if self.enabled and self._tty and self._wrote:
            self.stream.write("\n")
            self.stream.flush()


def _worker(
    verifier: Verifier,
    task_queue,
    result_queue,
    stop_flag,
    attempts_counter,
    weak_counter,
) -> None:
    try:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    except (AttributeError, ValueError):
        pass

    local_attempts = 0
    local_weak = 0

    def flush() -> None:
        nonlocal local_attempts, local_weak
        if local_attempts:
            with attempts_counter.get_lock():
                attempts_counter.value += local_attempts
            local_attempts = 0
        if local_weak:
            with weak_counter.get_lock():
                weak_counter.value += local_weak
            local_weak = 0

    try:
        while not stop_flag.value:
            try:
                task = task_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if task is None:
                return
            for candidate in task:
                if stop_flag.value:
                    flush()
                    return
                outcome = verifier.verify(candidate)
                local_attempts += 1
                if outcome == Outcome.WEAK:
                    local_weak += 1
                if outcome >= Outcome.PROBABLE:
                    flush()
                    result_queue.put(("hit", Hit(candidate, outcome)))
                    stop_flag.value = 1
                    return
                if local_attempts >= FLUSH_EVERY:
                    flush()
            flush()
    except BaseException as exc:  # noqa: BLE001 - report worker failures
        flush()
        try:
            result_queue.put(("worker-error", f"{type(exc).__name__}: {exc}"))
        except Exception:
            pass
        stop_flag.value = 1
    finally:
        flush()


def _auto_jobs() -> int:
    return max(1, os.cpu_count() or 1)


def _resolve_jobs(jobs: int) -> int:
    if jobs <= 0:
        return _auto_jobs()
    if jobs > MAX_WORKERS:
        raise UsageError(f"--jobs is capped at {MAX_WORKERS}")
    return jobs


def _status_printer(plan: AttackPlan, config: AttackConfig, stream: TextIO) -> StatusPrinter:
    return StatusPrinter(
        stream,
        total=plan.summary.total,
        total_is_upper=plan.summary.total_is_upper,
        interval=config.status_interval,
        enabled=config.show_status and not config.quiet,
    )


def _run_serial(
    verifier: Verifier,
    plan: AttackPlan,
    config: AttackConfig,
    printer: StatusPrinter,
) -> AttackResult:
    start = time.monotonic()
    deadline = start + config.max_runtime if config.max_runtime is not None else None
    attempts = 0
    weak = 0
    interrupted = False
    time_limit_reached = False
    exhausted = False
    errors: list[str] = []
    found: Optional[bytes] = None
    outcome = Outcome.REJECT
    try:
        for candidate in plan.iter_candidates():
            if deadline is not None and time.monotonic() >= deadline:
                time_limit_reached = True
                break
            attempts += 1
            result = verifier.verify(candidate)
            if result == Outcome.WEAK:
                weak += 1
            if result >= Outcome.PROBABLE:
                found = candidate
                outcome = result
                break
            printer.maybe_update(attempts, time.monotonic() - start, weak)
        else:
            exhausted = True
    except KeyboardInterrupt:
        interrupted = True
    except Exception as exc:  # noqa: BLE001 - mirror worker error reporting
        errors.append(f"{type(exc).__name__}: {exc}")
    elapsed = time.monotonic() - start
    printer.maybe_update(attempts, elapsed, weak, force=True)
    return AttackResult(
        found=found,
        outcome=outcome,
        attempts=attempts,
        elapsed=elapsed,
        rate=attempts / elapsed if elapsed > 0 else 0.0,
        weak=weak,
        interrupted=interrupted,
        time_limit_reached=time_limit_reached,
        exhausted=exhausted,
        errors=errors,
    )


def _run_parallel(
    verifier: Verifier,
    plan: AttackPlan,
    config: AttackConfig,
    printer: StatusPrinter,
    jobs: int,
) -> AttackResult:
    context: Any
    forced = os.environ.get("AESBREAKER_MP_CONTEXT")
    if forced:
        if forced not in ("fork", "spawn", "forkserver"):
            raise UsageError("AESBREAKER_MP_CONTEXT must be fork, spawn, or forkserver")
        context = mp.get_context(forced)
    elif os.name == "posix" and sys.platform != "darwin":
        context = mp.get_context("fork")
    else:
        context = mp.get_context("spawn")

    task_queue = context.Queue(maxsize=max(2, jobs * 2))
    result_queue = context.Queue()
    # A RawValue flag is a plain shared-memory read in the hot loop; an
    # mp.Event would impose a lock acquisition on every candidate and can
    # dominate fast verifiers.
    stop_flag = context.RawValue("b", 0)
    attempts_counter = context.Value("Q", 0)
    weak_counter = context.Value("Q", 0)
    feed_done = threading.Event()
    errors: list[str] = []
    hits: list[Hit] = []
    interrupted = False
    time_limit_reached = False
    feeder_exhausted = False
    start = time.monotonic()
    run_deadline = start + config.max_runtime if config.max_runtime is not None else None

    workers = [
        context.Process(
            target=_worker,
            args=(
                verifier,
                task_queue,
                result_queue,
                stop_flag,
                attempts_counter,
                weak_counter,
            ),
            daemon=True,
        )
        for _ in range(jobs)
    ]
    for process in workers:
        process.start()

    def feeder() -> None:
        nonlocal feeder_exhausted, time_limit_reached
        batch: list[bytes] = []
        try:
            for candidate in plan.iter_candidates():
                if run_deadline is not None and time.monotonic() >= run_deadline:
                    time_limit_reached = True
                    stop_flag.value = 1
                    return
                if stop_flag.value:
                    return
                batch.append(candidate)
                if len(batch) >= config.batch_size:
                    if not _put_batch(batch):
                        return
                    batch = []
            if batch and not _put_batch(batch):
                return
            for _ in workers:
                while not stop_flag.value:
                    try:
                        task_queue.put(None, timeout=0.2)
                        break
                    except queue.Full:
                        if not any(process.is_alive() for process in workers):
                            return
            feeder_exhausted = True
            feed_done.set()
        except BaseException as exc:  # noqa: BLE001 - report feeder failures
            try:
                result_queue.put(("fatal", f"{type(exc).__name__}: {exc}"))
            except Exception:
                pass
            stop_flag.value = 1
        finally:
            feed_done.set()

    def _put_batch(batch: list[bytes]) -> bool:
        while not stop_flag.value:
            try:
                task_queue.put(batch, timeout=0.2)
                return True
            except queue.Full:
                if not any(process.is_alive() for process in workers):
                    return False
        return False

    feeder_thread = threading.Thread(target=feeder, name="aesbreaker-feeder", daemon=True)
    feeder_thread.start()

    def drain_messages() -> None:
        while True:
            try:
                kind, payload = result_queue.get_nowait()
            except queue.Empty:
                return
            if kind == "hit":
                hits.append(payload)
                stop_flag.value = 1
            elif kind in ("worker-error", "fatal"):
                errors.append(str(payload))
                stop_flag.value = 1

    try:
        while True:
            if (
                run_deadline is not None
                and time.monotonic() >= run_deadline
                and not stop_flag.value
            ):
                time_limit_reached = True
                stop_flag.value = 1
            try:
                kind, payload = result_queue.get(timeout=0.2)
                if kind == "hit":
                    hits.append(payload)
                    stop_flag.value = 1
                elif kind in ("worker-error", "fatal"):
                    errors.append(str(payload))
                    stop_flag.value = 1
            except queue.Empty:
                pass

            attempts_now = attempts_counter.value
            weak_now = weak_counter.value
            printer.maybe_update(attempts_now, time.monotonic() - start, weak_now)
            if not any(process.is_alive() for process in workers):
                break
            if stop_flag.value and feed_done.is_set():
                # Workers should exit within one candidate.  On a hit or a
                # worker failure a short grace period is enough; during a
                # normal run an expensive KDF may need longer.
                grace = 2.0 if (hits or errors) else 10.0
                deadline = time.monotonic() + grace
                while time.monotonic() < deadline and any(
                    process.is_alive() for process in workers
                ):
                    drain_messages()
                    time.sleep(0.05)
                break
    except KeyboardInterrupt:
        interrupted = True

    stop_flag.value = 1
    deadline = time.monotonic() + (2.0 if interrupted else 10.0)
    for process in workers:
        remaining = max(0.0, deadline - time.monotonic())
        process.join(timeout=remaining)
    for process in workers:
        if process.is_alive():
            process.terminate()
    for process in workers:
        process.join(timeout=2.0)

    drain_messages()
    feed_done.set()
    try:
        task_queue.close()
        task_queue.cancel_join_thread()
    except Exception:
        pass
    try:
        result_queue.close()
        result_queue.cancel_join_thread()
    except Exception:
        pass
    feeder_thread.join(timeout=1.0)

    for process in workers:
        if process.exitcode not in (0, None):
            errors.append(f"worker exited with code {process.exitcode}")

    attempts = int(attempts_counter.value)
    weak = int(weak_counter.value)
    elapsed = time.monotonic() - start
    printer.maybe_update(attempts, elapsed, weak, force=True)
    printer.finish()

    exhausted = (
        feeder_exhausted and not hits and not errors and not interrupted and not time_limit_reached
    )
    if hits:
        hits.sort(key=lambda hit: (-int(hit.outcome),))
        best = hits[0]
        return AttackResult(
            found=best.candidate,
            outcome=best.outcome,
            attempts=attempts,
            elapsed=elapsed,
            rate=attempts / elapsed if elapsed > 0 else 0.0,
            weak=weak,
            interrupted=interrupted,
            time_limit_reached=time_limit_reached,
            exhausted=exhausted,
            errors=errors,
        )
    return AttackResult(
        found=None,
        outcome=Outcome.REJECT,
        attempts=attempts,
        elapsed=elapsed,
        rate=attempts / elapsed if elapsed > 0 else 0.0,
        weak=weak,
        interrupted=interrupted,
        time_limit_reached=time_limit_reached,
        exhausted=exhausted,
        errors=errors,
    )


def run_attack(
    verifier: Verifier,
    plan: AttackPlan,
    config: AttackConfig,
    *,
    status_stream: TextIO = sys.stderr,
) -> AttackResult:
    if config.batch_size < 1:
        raise UsageError("--batch-size must be at least 1")
    if config.max_runtime is not None and config.max_runtime <= 0:
        raise UsageError("--max-runtime must be greater than zero")
    jobs = _resolve_jobs(config.jobs)
    printer = _status_printer(plan, config, status_stream)
    if jobs == 1:
        result = _run_serial(verifier, plan, config, printer)
        printer.finish()
        return result
    return _run_parallel(verifier, plan, config, printer, jobs)
