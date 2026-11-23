"""``aesbreaker crack``: password recovery against an encrypted container."""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from .. import __version__
from ..candidates import AttackPlan, build_plan
from ..checkpoint import (
    file_identity,
    load_checkpoint,
    make_signature,
    utc_now,
    write_checkpoint,
)
from ..engine import AttackConfig, AttackResult, run_attack
from ..errors import AesBreakerError, OutputError, UsageError
from ..formats.base import Outcome
from ..util import (
    check_output_path,
    escape_control,
    format_count,
    format_duration,
    format_rate,
    parse_size,
    sha256_file,
    write_json,
)
from . import common


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="encrypted container to attack")
    group = parser.add_argument_group("candidate sources")
    group.add_argument("-w", "--wordlist", metavar="FILE", help="wordlist file ('-' for stdin)")
    group.add_argument("--stdin", action="store_true", help="read candidates from stdin")
    group.add_argument("--combinator", metavar="FILE", help="second wordlist to combine")
    group.add_argument(
        "--separator",
        default="",
        help="separator inserted between combinator words (default: empty)",
    )
    group.add_argument("--dedupe", action="store_true", help="skip duplicate candidates")
    group.add_argument(
        "--dedupe-limit",
        type=common.positive_int,
        default=5_000_000,
        metavar="N",
        help="maximum unique candidates tracked for --dedupe",
    )
    group.add_argument("--no-count", action="store_true", help="skip wordlist line counting")
    group.add_argument(
        "--combinator-max",
        type=common.positive_int,
        default=5_000_000,
        metavar="N",
        help="refuse a second combinator wordlist above this many words",
    )
    group.add_argument(
        "--include-empty",
        action="store_true",
        help="include empty lines from the wordlist as candidates",
    )

    common.rules_arguments(parser)
    common.mask_arguments(parser)
    common.add_format_arguments(parser)
    common.add_policy_arguments(parser)

    group = parser.add_argument_group("performance")
    group.add_argument(
        "-j",
        "--jobs",
        type=common.nonnegative_int,
        default=0,
        metavar="N",
        help="worker processes (0 = CPU count; 1 = in-process serial)",
    )
    group.add_argument(
        "--batch-size",
        type=common.positive_int,
        default=256,
        metavar="N",
        help="candidates per worker task (default: 256)",
    )
    group.add_argument(
        "--status-interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="progress update interval (default: 2.0)",
    )
    group.add_argument("--no-status", action="store_true", help="disable progress output")
    group.add_argument("-q", "--quiet", action="store_true", help="suppress informational output")
    group.add_argument(
        "--max-runtime",
        type=common.positive_float,
        metavar="SECONDS",
        help="stop after this many seconds (exit 124; use --checkpoint to resume)",
    )
    group.add_argument(
        "--checkpoint",
        metavar="FILE",
        help="save attack progress to FILE on stop or completion",
    )
    group.add_argument(
        "--resume",
        metavar="FILE",
        help="resume a previous --checkpoint FILE",
    )

    common.add_output_arguments(parser)
    group = parser.add_argument_group("result")
    group.add_argument(
        "--no-decrypt", action="store_true", help="recover the password but do not decrypt"
    )
    group.add_argument("--password-out", metavar="FILE", help="write the recovered password bytes")
    group.add_argument(
        "--max-extract-size",
        type=parse_size,
        default=parse_size("8G"),
        metavar="SIZE",
        help="ZIP extraction output limit (default: 8G; 0 = unlimited)",
    )
    group.add_argument("--dry-run", action="store_true", help="show the attack plan and exit")
    group.add_argument(
        "--benchmark",
        nargs="?",
        const=100,
        type=common.positive_int,
        metavar="N",
        help="measure verification throughput with N candidates and exit",
    )
    group.add_argument("--json", action="store_true", help="write the final result as JSON")
    group.add_argument("--json-out", metavar="FILE", help="also write the JSON result to FILE")


def _checkpoint_identity(args, artifact, verifier, plan, policy) -> dict:
    """Everything that must be identical for a checkpoint to be resumable."""
    return {
        "tool": "aesbreaker",
        "version": __version__,
        "input": {
            "path": str(Path(common.input_display(args, artifact)).resolve()),
            "sha256": sha256_file(common.input_display(args, artifact)),
        },
        "format": artifact.format_name,
        "format_options": asdict(common.format_options_from_args(args)),
        "policy": {
            "mode": policy.mode,
            "known_prefix": (policy.known_prefix.hex() if policy.has_prefix else None),
        },
        "verifier": verifier.describe(),
        "plan": plan.summary.as_dict(),
        "wordlist": file_identity(args.wordlist),
        "combinator": file_identity(args.combinator),
        "rules": [file_identity(path) for path in (args.rules or [])],
        "rule_presets": list(args.rules_preset or []),
        "inline_rules": list(args.rule or []),
        "spec": file_identity(args.spec),
        "entry": args.entry,
    }


def _checkpoint_path_guard(
    checkpoint_path: str,
    args,
    protected_inputs: tuple[str, ...],
    primary_output: Optional[str],
) -> None:
    if not checkpoint_path or checkpoint_path == "-":
        raise UsageError("checkpoint path must be a file, not '-'")
    try:
        resolved = Path(checkpoint_path).expanduser().resolve()
    except OSError as exc:
        raise UsageError(f"invalid checkpoint path: {exc}") from None
    if resolved.exists() and resolved.is_dir():
        raise UsageError(f"checkpoint path is a directory: {checkpoint_path}")
    for value in protected_inputs:
        if not value or value == "-" or value == args.resume:
            continue
        try:
            if Path(value).expanduser().resolve() == resolved:
                raise UsageError(
                    f"checkpoint would overwrite input {value}",
                    hint="choose a different checkpoint path",
                )
        except OSError:
            continue
    for label, output_value in (
        ("--json-out", args.json_out),
        ("--password-out", args.password_out),
        ("primary output", primary_output),
    ):
        if not output_value or output_value == "-":
            continue
        try:
            if Path(output_value).expanduser().resolve() == resolved:
                raise UsageError(
                    f"checkpoint path conflicts with {label}",
                    hint="choose a different checkpoint path",
                )
        except OSError:
            continue
    if args.resume is None and resolved.exists() and not args.overwrite:
        raise UsageError(
            f"checkpoint already exists: {checkpoint_path}",
            hint="use --resume to continue it or --overwrite to replace it",
        )


def _prepare_checkpoint(
    args,
    artifact,
    verifier,
    plan: AttackPlan,
    policy,
    protected_inputs: tuple[str, ...],
    primary_output: Optional[str],
) -> tuple[Optional[str], Optional[str], int, Optional[dict]]:
    checkpoint_path = args.checkpoint or args.resume
    if not checkpoint_path:
        return None, None, 0, None
    _checkpoint_path_guard(checkpoint_path, args, protected_inputs, primary_output)
    signature = make_signature(_checkpoint_identity(args, artifact, verifier, plan, policy))
    previous = None
    skip = 0
    if args.resume:
        previous = load_checkpoint(args.resume)
        if previous.get("signature") != signature:
            raise UsageError(
                "checkpoint does not match this attack",
                hint=(
                    "resume with the same input, wordlist, rules, cipher "
                    "parameters, and AES-Breaker version"
                ),
            )
        if previous.get("completed"):
            raise UsageError("checkpoint is already complete; nothing to resume")
        skip = int(previous["attempts"])
        if plan.summary.total is not None and skip >= plan.summary.total:
            raise UsageError("checkpoint is at the end of the candidate plan; nothing to resume")
    return checkpoint_path, signature, skip, previous


def _checkpoint_state(
    args,
    artifact,
    plan: AttackPlan,
    signature: str,
    skip: int,
    previous: Optional[dict],
    result: AttackResult,
) -> dict:
    previous = previous or {}
    total = plan.summary.total
    attempts = skip + result.attempts
    if total is not None:
        attempts = min(attempts, total)
    completed = bool(result.found is not None or (result.exhausted and not result.errors))
    if result.interrupted or result.time_limit_reached or result.errors:
        completed = False
    if result.found is not None:
        completed = True
    return {
        "created": previous.get("created") or utc_now(),
        "updated": utc_now(),
        "signature": signature,
        "attempts": attempts,
        "weak_candidates": int(previous.get("weak_candidates", 0)) + result.weak,
        "elapsed_seconds": round(float(previous.get("elapsed_seconds", 0.0)) + result.elapsed, 6),
        "completed": completed,
        "found": result.found is not None,
        "interrupted": result.interrupted,
        "time_limit_reached": result.time_limit_reached,
        "exhausted": result.exhausted,
        "errors": list(result.errors),
        "resumed_from": skip,
        "input": common.input_display(args, artifact),
        "format": artifact.format_name,
        "plan": plan.summary.as_dict(),
    }


def _base_payload(args, artifact, verifier, plan) -> dict:
    return {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "crack",
        "input": common.input_display(args, artifact),
        "format": artifact.format_name,
        "format_display": artifact.display_name,
        "verification": verifier.verification_label(),
        "attack": plan.summary.as_dict(),
        "found": False,
        "password": None,
        "confidence": None,
        "output": None,
        "attempts": 0,
        "weak_candidates": 0,
        "elapsed_seconds": 0.0,
        "rate_per_second": 0.0,
        "interrupted": False,
        "errors": [],
        "warnings": list(plan.warnings),
    }


def _emit_json(args, payload: dict) -> None:
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)


def _print_header(artifact, verifier, plan, args, *, resumed_from: int = 0) -> None:
    if args.quiet:
        return
    print(f"Input: {common.input_display(args, artifact)}", file=sys.stderr)
    print(f"Format: {artifact.display_name}", file=sys.stderr)
    if resumed_from:
        print(
            f"Resumed from candidate {format_count(resumed_from)}",
            file=sys.stderr,
        )
    print(common.describe_plan(plan.summary), file=sys.stderr)
    print(f"Verification: {verifier.verification_label()}", file=sys.stderr)
    if args.jobs == 0:
        print("Workers: auto", file=sys.stderr)
    else:
        print(f"Workers: {args.jobs}", file=sys.stderr)
    for warning in plan.warnings:
        print(f"Warning: {warning}", file=sys.stderr)


def _print_verifier_summary(verifier) -> None:
    for key, value in verifier.describe().items():
        print(f"{key}: {value}")


def _run_benchmark(args, artifact, verifier, plan, payload: dict) -> int:
    if args.benchmark is None:
        raise AssertionError("benchmark requested without a count")
    count = args.benchmark
    start = time.perf_counter()
    tested = 0
    candidates = plan.iter_candidates()
    try:
        while tested < count:
            candidate = next(candidates)
            verifier.verify(candidate)
            tested += 1
    except StopIteration:
        pass
    elapsed = time.perf_counter() - start
    if tested == 0:
        raise UsageError("the attack plan produced no candidates to benchmark")
    rate = tested / elapsed if elapsed > 0 else 0.0
    payload.update(
        {
            "benchmark": {
                "candidates": tested,
                "elapsed_seconds": round(elapsed, 6),
                "rate_per_second": round(rate, 3),
            }
        }
    )
    if plan.summary.total is not None and rate > 0:
        payload["benchmark"]["keyspace_eta_seconds"] = round(plan.summary.total / rate, 3)
    _emit_json(args, payload)
    if args.json:
        return 0
    print(f"Benchmark: verified {format_count(tested)} candidates in {format_duration(elapsed)}")
    print(f"Rate: {format_rate(rate)}")
    if plan.summary.total is not None:
        eta = plan.summary.total / rate if rate > 0 else None
        print(
            f"Keyspace: {format_count(plan.summary.total)} candidates, "
            f"estimated time at this rate: {format_duration(eta)}"
        )
    return 0


def _early_output_check(args, artifact) -> None:
    if args.no_decrypt:
        if args.out:
            raise UsageError("--out has no effect with --no-decrypt")
        return
    output = common.output_path_from_args(args, artifact)
    common.ensure_output_is_not_input(output, artifact)
    if artifact.output_kind == "directory":
        if output == "-":
            raise UsageError("ZIP extraction requires a directory output, not '-'")
        path = Path(output)
        if path.exists() and not path.is_dir():
            raise OutputError(f"output path is not a directory: {path}")
    else:
        if output != "-":
            check_output_path(output, overwrite=args.overwrite)


def _decrypt_found(args, artifact, password: bytes) -> tuple[str | None, dict, list[str]]:
    output = common.output_path_from_args(args, artifact)
    common.ensure_output_is_not_input(output, artifact)
    if artifact.output_kind == "directory":
        max_bytes = None if args.max_extract_size == 0 else args.max_extract_size
        report = artifact.extract(
            password,
            output,
            overwrite=args.overwrite,
            max_output_bytes=max_bytes,
        )
        details = dict(report.details)
        return output, details, list(details.get("errors") or [])
    with common.output_sink(output, overwrite=args.overwrite) as handle:
        report = artifact.decrypt(password, handle)
    return output, {"bytes_written": report.bytes_written, **report.details}, []


def _human_result(
    args,
    payload: dict,
    *,
    stream,
    artifact,
    verifier,
    plan,
    message: str | None = None,
) -> None:
    if args.json:
        return
    found = payload.get("found")
    if not found:
        print(
            f"Password not found after {format_count(payload['attempts'])} attempts "
            f"({format_duration(payload['elapsed_seconds'])}, "
            f"{format_rate(payload['rate_per_second'])}).",
            file=stream,
        )
        if payload.get("interrupted"):
            print("Interrupted by user.", file=stream)
        if payload.get("weak_candidates"):
            print(
                f"Padding-only matches rejected: {format_count(payload['weak_candidates'])} "
                "(use --policy any to inspect them).",
                file=stream,
            )
        if artifact.format_name == "openssl":
            print(
                "OpenSSL enc does not store its cipher or KDF parameters; verify "
                "--openssl-cipher, --openssl-digest, --openssl-pbkdf2, and "
                "--openssl-iterations before concluding the password is absent.",
                file=stream,
            )
        return

    password_json = payload.get("password") or {}
    display = password_json.get("display", "")
    confidence = payload.get("confidence")
    if confidence == "confirmed":
        print(f"Password recovered: {display}", file=stream)
    else:
        print(f"Candidate password (not cryptographically confirmed): {display}", file=stream)
    print(f"Password hex: {password_json.get('hex', '')}", file=stream)
    print(f"Confidence: {confidence}", file=stream)
    print(f"Verification: {payload.get('verification')}", file=stream)
    print(
        f"Attempts: {format_count(payload['attempts'])} "
        f"({format_duration(payload['elapsed_seconds'])}, "
        f"{format_rate(payload['rate_per_second'])})",
        file=stream,
    )
    if payload.get("output"):
        print(f"Output: {payload['output']}", file=stream)
    extraction = payload.get("extraction")
    if extraction:
        extracted = extraction.get("extracted_count", 0)
        print(f"Extracted entries: {format_count(extracted)}", file=stream)
        for entry in extraction.get("entries", []):
            status = entry.get("status")
            if status not in ("extracted", "directory"):
                name = escape_control(str(entry.get("name", "")))
                print(f"  {name}: {status}", file=stream)
        for error in extraction.get("errors", []):
            print(f"  error: {escape_control(error)}", file=stream)
    if message:
        print(message, file=stream)


def run(args: argparse.Namespace) -> int:
    requested = common.normalize_format(args.format or "auto")
    if requested == "custom":
        return _run(args)
    with common.decoded_input(args):
        return _run(args)


def _run(args: argparse.Namespace) -> int:
    if args.benchmark is not None and args.dry_run:
        raise UsageError("--benchmark and --dry-run are mutually exclusive")
    if args.status_interval <= 0:
        raise UsageError("--status-interval must be greater than zero")
    if args.batch_size > 100_000:
        raise UsageError("--batch-size is capped at 100000")
    if (args.checkpoint or args.resume) and (args.dry_run or args.benchmark is not None):
        raise UsageError("--checkpoint/--resume cannot be used with --dry-run or --benchmark")
    if args.max_runtime is not None and (args.dry_run or args.benchmark is not None):
        raise UsageError("--max-runtime cannot be used with --dry-run or --benchmark")

    policy = common.policy_from_args(args)
    artifact = common.open_artifact_from_args(args, policy)
    common.attach_input_origin(args, artifact)
    common.validate_format_options(artifact, args)
    verifier = artifact.verifier(policy)

    if not args.dry_run and args.benchmark is None:
        _early_output_check(args, artifact)
    primary_output = (
        None
        if args.no_decrypt or args.dry_run or args.benchmark is not None
        else common.output_path_from_args(args, artifact)
    )
    protected_inputs = [str(artifact.path)]
    if args.wordlist and args.wordlist != "-":
        protected_inputs.append(args.wordlist)
    if args.combinator:
        protected_inputs.append(args.combinator)
    protected_inputs.extend(args.rules or [])
    if args.spec:
        protected_inputs.append(args.spec)
    if args.resume:
        protected_inputs.append(args.resume)
    if getattr(args, "_input_original", None):
        protected_inputs.append(args._input_original)
    common.validate_side_outputs(
        args,
        inputs=tuple(protected_inputs),
        primary=primary_output,
    )
    plan = build_plan(common.build_plan_options_from_args(args))
    payload = _base_payload(args, artifact, verifier, plan)
    checkpoint_path, checkpoint_signature, resumed_from, previous_checkpoint = _prepare_checkpoint(
        args,
        artifact,
        verifier,
        plan,
        policy,
        tuple(protected_inputs),
        primary_output,
    )
    attack_plan = plan.skipped(resumed_from) if resumed_from else plan
    payload["resumed_from"] = resumed_from
    payload["checkpoint"] = checkpoint_path
    if resumed_from:
        payload["remaining_attack"] = attack_plan.summary.as_dict()

    if args.dry_run:
        payload["dry_run"] = True
        payload["verifier"] = verifier.describe()
        payload["policy"] = {
            "mode": policy.mode,
            "known_prefix": policy.known_prefix.hex() if policy.has_prefix else None,
        }
        if args.json:
            _emit_json(args, payload)
        else:
            print(f"Input: {artifact.path}")
            print(f"Format: {artifact.display_name}")
            print(common.describe_plan(plan.summary))
            print("Verifier:")
            _print_verifier_summary(verifier)
            for warning in plan.warnings:
                print(f"Warning: {warning}")
        return 0

    if args.benchmark is not None:
        return _run_benchmark(args, artifact, verifier, plan, payload)

    _print_header(artifact, verifier, attack_plan, args, resumed_from=resumed_from)
    config = AttackConfig(
        jobs=args.jobs,
        batch_size=args.batch_size,
        status_interval=args.status_interval,
        show_status=not args.no_status,
        quiet=args.quiet,
        max_runtime=args.max_runtime,
    )
    result: AttackResult = run_attack(verifier, attack_plan, config)
    total_attempts = resumed_from + result.attempts

    checkpoint_error = None
    checkpoint_completed = False
    if checkpoint_path:
        assert checkpoint_signature is not None
        state = _checkpoint_state(
            args,
            artifact,
            plan,
            checkpoint_signature,
            resumed_from,
            previous_checkpoint,
            result,
        )
        checkpoint_completed = bool(state["completed"])
        try:
            write_checkpoint(checkpoint_path, state)
        except AesBreakerError as exc:
            checkpoint_error = str(exc)
    payload.update(
        {
            "attempts": result.attempts,
            "total_attempts": total_attempts,
            "weak_candidates": result.weak,
            "elapsed_seconds": round(result.elapsed, 6),
            "rate_per_second": round(result.rate, 3),
            "interrupted": result.interrupted,
            "time_limit_reached": result.time_limit_reached,
            "exhausted": result.exhausted,
            "completed": checkpoint_completed or bool(result.found),
            "errors": list(result.errors),
            "warnings": list(plan.warnings),
        }
    )
    if checkpoint_error:
        payload["checkpoint_error"] = checkpoint_error
        payload["warnings"].append(f"checkpoint write failed: {checkpoint_error}")
    if result.found is None:
        if result.errors:
            for error in result.errors:
                print(f"Error: {error}", file=sys.stderr)
            _emit_json(args, payload)
            return 3
        _emit_json(args, payload)
        _human_result(
            args,
            payload,
            stream=sys.stderr if args.json else sys.stdout,
            artifact=artifact,
            verifier=verifier,
            plan=plan,
        )
        if checkpoint_error:
            print(f"Checkpoint error: {checkpoint_error}", file=sys.stderr)
            return 3
        if result.time_limit_reached:
            if checkpoint_path:
                print(
                    f"Time limit reached; checkpoint saved to {checkpoint_path}",
                    file=sys.stderr,
                )
            else:
                print("Time limit reached.", file=sys.stderr)
            return 124
        if result.interrupted:
            if checkpoint_path:
                print(
                    f"Interrupted; checkpoint saved to {checkpoint_path}",
                    file=sys.stderr,
                )
            return 130
        return 1

    if checkpoint_error:
        print(f"Checkpoint error: {checkpoint_error}", file=sys.stderr)
    password = result.found
    confidence = "confirmed" if result.outcome == Outcome.CONFIRMED else "probable"
    payload["found"] = True
    payload["password"] = common.password_json(password)
    payload["confidence"] = confidence
    common.write_password_output(args, password)

    if not args.quiet:
        print(
            f"Hit at attempt {format_count(result.attempts)} "
            f"({format_duration(result.elapsed)}, {format_rate(result.rate)})",
            file=sys.stderr,
        )

    decryption_error: str | None = None
    extraction_errors: list[str] = []
    if not args.no_decrypt:
        try:
            output, details, extraction_errors = _decrypt_found(args, artifact, password)
            payload["output"] = output
            payload["decryption"] = details
            if artifact.output_kind == "directory":
                payload["extraction"] = details
            if extraction_errors:
                payload["errors"].extend(extraction_errors)
        except AesBreakerError as exc:
            decryption_error = str(exc)
            payload["errors"].append(decryption_error)

    _emit_json(args, payload)
    human_stream = (
        sys.stderr
        if args.json
        or args.password_out == "-"
        or (not args.no_decrypt and payload.get("output") == "-")
        else sys.stdout
    )
    if decryption_error:
        _human_result(
            args,
            payload,
            stream=human_stream,
            artifact=artifact,
            verifier=verifier,
            plan=plan,
        )
        print(f"Decryption failed: {decryption_error}", file=sys.stderr)
        return 3
    if not args.no_decrypt:
        notes = []
        if confidence == "probable":
            notes.append(
                "The password is a heuristic match; OpenSSL enc has no MAC. "
                "Inspect the output before relying on it."
            )
        if payload.get("errors"):
            notes.append("Some operations reported errors; see above.")
        _human_result(
            args,
            payload,
            stream=human_stream,
            artifact=artifact,
            verifier=verifier,
            plan=plan,
            message=" ".join(notes) if notes else None,
        )
    elif args.no_decrypt:
        note = (
            "The password is a heuristic match and was not confirmed by a MAC."
            if confidence == "probable"
            else None
        )
        _human_result(
            args,
            payload,
            stream=human_stream,
            artifact=artifact,
            verifier=verifier,
            plan=plan,
            message=note,
        )
    return 3 if extraction_errors else 0
