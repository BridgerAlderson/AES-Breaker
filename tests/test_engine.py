from __future__ import annotations

import io
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

from aesbreaker.candidates import PlanOptions, build_plan
from aesbreaker.engine import AttackConfig, run_attack
from aesbreaker.errors import UsageError
from aesbreaker.formats.base import Outcome, Verifier


@dataclass(frozen=True)
class EqualityVerifier(Verifier):
    target: bytes
    format_name = "test"

    def describe(self) -> dict:
        return {"format": "test"}

    def verify(self, password: bytes) -> Outcome:
        return Outcome.CONFIRMED if password == self.target else Outcome.REJECT


@dataclass(frozen=True)
class WeakVerifier(Verifier):
    target: bytes
    format_name = "test"

    def describe(self) -> dict:
        return {"format": "test"}

    def verify(self, password: bytes) -> Outcome:
        if password == self.target:
            return Outcome.CONFIRMED
        return Outcome.WEAK


@dataclass(frozen=True)
class ExplodingVerifier(Verifier):
    trigger: bytes
    format_name = "test"

    def describe(self) -> dict:
        return {"format": "test"}

    def verify(self, password: bytes) -> Outcome:
        if password == self.trigger:
            raise RuntimeError("verifier exploded")
        return Outcome.REJECT


@pytest.fixture()
def wordlist(tmp_path: Path) -> Path:
    path = tmp_path / "words.txt"
    path.write_bytes(b"\n".join(f"candidate-{index}".encode() for index in range(500)) + b"\n")
    return path


def test_serial_and_parallel_find(wordlist: Path):
    target = b"candidate-499"
    for jobs in (1, 2, 4):
        plan = build_plan(PlanOptions(wordlist=str(wordlist)))
        result = run_attack(
            EqualityVerifier(target), plan, AttackConfig(jobs=jobs, show_status=False)
        )
        assert result.found == target
        assert result.outcome == Outcome.CONFIRMED
        if jobs == 1:
            assert result.attempts == 500
        else:
            assert 1 <= result.attempts <= 500
        assert result.errors == []
        assert result.rate > 0


def test_not_found(wordlist: Path):
    for jobs in (1, 3):
        plan = build_plan(PlanOptions(wordlist=str(wordlist)))
        result = run_attack(
            EqualityVerifier(b"absent"),
            plan,
            AttackConfig(jobs=jobs, show_status=False),
        )
        assert result.found is None
        assert result.attempts == 500
        assert result.outcome == Outcome.REJECT


def test_early_stop_serial_is_exact(wordlist: Path):
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    result = run_attack(
        EqualityVerifier(b"candidate-5"),
        plan,
        AttackConfig(jobs=1, show_status=False),
    )
    assert result.found == b"candidate-5"
    assert result.attempts == 6


def test_weak_candidates_counted(wordlist: Path):
    for jobs in (1, 2):
        plan = build_plan(PlanOptions(wordlist=str(wordlist)))
        result = run_attack(
            WeakVerifier(b"absent"),
            plan,
            AttackConfig(jobs=jobs, show_status=False),
        )
        assert result.weak > 0
        assert result.found is None


def test_verifier_errors_are_reported(wordlist: Path):
    for jobs in (1, 2):
        plan = build_plan(PlanOptions(wordlist=str(wordlist)))
        result = run_attack(
            ExplodingVerifier(b"candidate-5"),
            plan,
            AttackConfig(jobs=jobs, show_status=False),
        )
        assert result.found is None
        assert any("verifier exploded" in error for error in result.errors)


def test_config_validation(wordlist: Path):
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    with pytest.raises(UsageError):
        run_attack(
            EqualityVerifier(b"x"),
            plan,
            AttackConfig(jobs=257, show_status=False),
        )
    with pytest.raises(UsageError):
        run_attack(
            EqualityVerifier(b"x"),
            plan,
            AttackConfig(jobs=2, batch_size=0, show_status=False),
        )


def test_status_output_is_rendered(wordlist: Path):
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    stream = io.StringIO()
    result = run_attack(
        EqualityVerifier(b"candidate-10"),
        plan,
        AttackConfig(jobs=1, show_status=True, status_interval=0.0001),
        status_stream=stream,
    )
    assert result.found == b"candidate-10"
    rendered = stream.getvalue()
    assert "candidates" in rendered or "candidate" in rendered or "ETA" in rendered


def test_parallel_with_mask():
    from aesbreaker.masks import parse_mask

    plan = build_plan(PlanOptions(mask=parse_mask("?l?l")))
    result = run_attack(
        EqualityVerifier(b"zz"),
        plan,
        AttackConfig(jobs=3, batch_size=16, show_status=False),
    )
    assert result.found == b"zz"
    assert 1 <= result.attempts <= 676


@dataclass(frozen=True)
class SlowVerifier(Verifier):
    delay: float
    format_name = "test"

    def describe(self) -> dict:
        return {"format": "test"}

    def verify(self, password: bytes) -> Outcome:
        time.sleep(self.delay)
        return Outcome.REJECT


def test_time_limit_stops_serial_and_parallel(wordlist: Path):
    for jobs in (1, 2):
        plan = build_plan(PlanOptions(wordlist=str(wordlist)))
        result = run_attack(
            SlowVerifier(0.01),
            plan,
            AttackConfig(
                jobs=jobs,
                show_status=False,
                max_runtime=0.15,
            ),
        )
        assert result.found is None
        assert result.time_limit_reached is True
        assert result.interrupted is False
        assert result.exhausted is False
        assert 0 < result.attempts < 500


def test_time_limit_must_be_positive(wordlist: Path):
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    with pytest.raises(UsageError):
        run_attack(
            EqualityVerifier(b"absent"),
            plan,
            AttackConfig(show_status=False, max_runtime=0),
        )


def test_skipped_plan_starts_at_expected_candidate(wordlist: Path):
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    skipped = plan.skipped(498)
    assert skipped.summary.total == 2
    assert skipped.summary.details["resumed_from"] == 498
    result = run_attack(
        EqualityVerifier(b"candidate-499"),
        skipped,
        AttackConfig(jobs=1, show_status=False),
    )
    assert result.found == b"candidate-499"
    assert result.attempts == 2
    assert result.exhausted is False


def test_skipped_plan_validation(wordlist: Path):
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    with pytest.raises(UsageError):
        plan.skipped(-1)
    assert plan.skipped(0) is plan


def test_exhausted_flag(wordlist: Path):
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    result = run_attack(
        EqualityVerifier(b"absent"),
        plan,
        AttackConfig(jobs=1, show_status=False),
    )
    assert result.exhausted is True


def test_spawn_context_finds_password(wordlist: Path, monkeypatch):
    monkeypatch.setenv("AESBREAKER_MP_CONTEXT", "spawn")
    plan = build_plan(PlanOptions(wordlist=str(wordlist)))
    result = run_attack(
        EqualityVerifier(b"candidate-499"),
        plan,
        AttackConfig(jobs=2, show_status=False),
    )
    assert result.found == b"candidate-499"
