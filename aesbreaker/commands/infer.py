"""``aesbreaker infer``: rank raw AES mode/IV interpretations without guessing.

This is the rigorous replacement for the legacy "try every mode and call the
most printable result a success" behaviour.  A configuration is reported as
``confirmed`` only when a GCM tag verifies or a supplied known plaintext
prefix matches exactly.  File magic and printable-text checks produce
``probable`` results; a bare valid PKCS#7 padding is ``weak`` and hidden by
default.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from Crypto.Cipher import AES

from .. import __version__
from ..crypto import (
    AES_BLOCK_SIZE,
    aes_cfb_cipher,
    aes_ctr_cipher,
    aes_ecb_decrypt_block,
    aes_gcm_decrypt,
    aes_ofb_cipher,
    pkcs7_unpad,
    pkcs7_valid_last_block,
    xor_bytes,
)
from ..errors import DecryptionError, InputError, OutputError, UsageError
from ..formats.base import MIN_CONFIRM_PREFIX
from ..signatures import assess_plaintext
from ..util import (
    atomic_writer,
    check_output_path,
    format_hex,
    parse_hex_data,
    preview_bytes,
    read_encoded_data,
    read_file,
    write_json,
)
from . import common

VERDICT_ORDER = {"confirmed": 0, "probable": 1, "weak": 2}


@dataclass
class InferResult:
    cipher: str
    mode: str
    key_bits: int
    iv_source: str
    verdict: str
    detail: str
    probe: bytes
    iv: bytes = b""
    ciphertext: bytes = b""
    padding: str = "pkcs7"
    little_endian: bool = False
    gcm_nonce: bytes = b""
    gcm_tag: bytes = b""
    aad: bytes = b""
    output: Optional[str] = None

    def decrypt(self, key: bytes) -> bytes:
        if self.mode == "gcm":
            return aes_gcm_decrypt(
                key,
                self.gcm_nonce,
                self.ciphertext,
                self.gcm_tag,
                aad=self.aad,
            )
        if self.mode == "ecb":
            plain = AES.new(key, AES.MODE_ECB).decrypt(self.ciphertext)
        elif self.mode == "cbc":
            plain = AES.new(key, AES.MODE_CBC, iv=self.iv).decrypt(self.ciphertext)
        elif self.mode == "ctr":
            plain = aes_ctr_cipher(key, self.iv, little_endian=self.little_endian).decrypt(
                self.ciphertext
            )
        elif self.mode == "cfb":
            plain = aes_cfb_cipher(key, self.iv).decrypt(self.ciphertext)
        elif self.mode == "ofb":
            plain = aes_ofb_cipher(key, self.iv).decrypt(self.ciphertext)
        else:  # pragma: no cover - mode table is closed
            raise AssertionError(f"unknown mode {self.mode}")
        if self.padding == "pkcs7" and self.mode in ("cbc", "ecb"):
            plain = pkcs7_unpad(plain)
        return plain

    def as_dict(self) -> dict:
        return {
            "cipher": self.cipher,
            "mode": self.mode,
            "key_bits": self.key_bits,
            "iv_source": self.iv_source,
            "verdict": self.verdict,
            "detail": self.detail,
            "preview": preview_bytes(self.probe),
            "probe_hex": self.probe[:64].hex(),
            "output": self.output,
        }


def configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input", help="ciphertext file ('-' for stdin)")
    parser.add_argument("--key", metavar="HEX", help="AES key as hex")
    parser.add_argument("--key-file", metavar="FILE", help="raw AES key bytes")
    parser.add_argument("--iv", metavar="HEX", help="explicit 16-byte IV/counter")
    parser.add_argument("--gcm-nonce", metavar="HEX", help="explicit GCM nonce")
    parser.add_argument("--gcm-tag", metavar="HEX", help="explicit GCM tag")
    parser.add_argument("--aad", metavar="HEX", help="GCM additional authenticated data")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--known-prefix", metavar="TEXT", help="known plaintext prefix (UTF-8)")
    group.add_argument("--known-prefix-hex", metavar="HEX", help="known plaintext prefix as hex")
    parser.add_argument(
        "--padding",
        choices=("pkcs7", "none"),
        default="pkcs7",
        help="block-mode padding assumption (default: pkcs7)",
    )
    parser.add_argument(
        "--in-encoding",
        choices=("auto", "raw", "hex", "base64"),
        default="auto",
        help="ciphertext encoding (default: auto)",
    )
    parser.add_argument("--out-dir", metavar="DIR", help="write candidate plaintexts to DIR")
    parser.add_argument("--overwrite", action="store_true", help="replace existing candidate files")
    parser.add_argument("--show-weak", action="store_true", help="include padding-only results")
    parser.add_argument("--json", action="store_true", help="write the result as JSON")
    parser.add_argument("--json-out", metavar="FILE", help="also write the JSON result to FILE")


def _key(args) -> bytes:
    if (args.key is None) == (args.key_file is None):
        raise UsageError("supply exactly one of --key or --key-file")
    key = parse_hex_data(args.key, what="key") if args.key is not None else read_file(args.key_file)
    if len(key) not in (16, 24, 32):
        raise UsageError("AES key must be 16, 24, or 32 bytes")
    return key


def _prefix(args) -> bytes:
    if args.known_prefix is not None:
        return args.known_prefix.encode("utf-8")
    if args.known_prefix_hex is not None:
        return parse_hex_data(args.known_prefix_hex, what="known prefix")
    return b""


def _block_result(
    key: bytes,
    mode: str,
    iv: bytes,
    iv_source: str,
    ciphertext: bytes,
    padding: str,
    prefix: bytes,
) -> Optional[InferResult]:
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE:
        return None
    if mode == "cbc":
        if len(ciphertext) >= 2 * AES_BLOCK_SIZE:
            previous = ciphertext[-2 * AES_BLOCK_SIZE : -AES_BLOCK_SIZE]
        else:
            previous = iv
        last_plain = xor_bytes(aes_ecb_decrypt_block(key, ciphertext[-AES_BLOCK_SIZE:]), previous)
    else:
        last_plain = aes_ecb_decrypt_block(key, ciphertext[-AES_BLOCK_SIZE:])
    if padding == "pkcs7" and not pkcs7_valid_last_block(last_plain):
        return None

    probe_limit = max(64, len(prefix))
    full = len(ciphertext) <= probe_limit
    take = (
        len(ciphertext)
        if full
        else ((probe_limit + AES_BLOCK_SIZE - 1) // AES_BLOCK_SIZE) * AES_BLOCK_SIZE
    )
    take = min(take, len(ciphertext))
    if mode == "cbc":
        probe = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext[:take])
    else:
        probe = AES.new(key, AES.MODE_ECB).decrypt(ciphertext[:take])
    if full and padding == "pkcs7":
        try:
            probe = pkcs7_unpad(probe)
        except DecryptionError:
            return None
    if prefix:
        if len(probe) < len(prefix):
            return None
        if probe[: len(prefix)] != prefix:
            return None

    plausibility = assess_plaintext(probe)
    if prefix:
        if len(prefix) < MIN_CONFIRM_PREFIX:
            verdict = "probable"
            detail = (
                f"{len(prefix)}-byte prefix matched; below the "
                f"{MIN_CONFIRM_PREFIX}-byte confirmation threshold"
            )
        else:
            verdict, detail = "confirmed", "known plaintext prefix matched"
    elif plausibility.is_magic:
        verdict, detail = "probable", f"{plausibility.magic} magic"
    elif plausibility.is_text:
        verdict, detail = "probable", plausibility.detail
    else:
        verdict = "weak"
        detail = "valid PKCS#7 padding only" if padding == "pkcs7" else "no evidence"
    bits = len(key) * 8
    return InferResult(
        cipher=f"aes-{bits}-{mode}",
        mode=mode,
        key_bits=bits,
        iv_source=iv_source,
        verdict=verdict,
        detail=detail,
        probe=probe,
        iv=iv,
        ciphertext=ciphertext,
        padding=padding if mode in ("cbc", "ecb") else "none",
    )


def _stream_result(
    key: bytes,
    mode: str,
    iv: bytes,
    iv_source: str,
    ciphertext: bytes,
    prefix: bytes,
    *,
    little_endian: bool = False,
) -> Optional[InferResult]:
    if not ciphertext:
        return None
    take = min(len(ciphertext), max(64, len(prefix)))
    if mode == "ctr":
        probe = aes_ctr_cipher(key, iv, little_endian=little_endian).decrypt(ciphertext[:take])
    elif mode == "cfb":
        probe = aes_cfb_cipher(key, iv).decrypt(ciphertext[:take])
    elif mode == "ofb":
        probe = aes_ofb_cipher(key, iv).decrypt(ciphertext[:take])
    else:  # pragma: no cover
        raise AssertionError(mode)
    if prefix:
        if len(probe) < len(prefix) or probe[: len(prefix)] != prefix:
            return None
    plausibility = assess_plaintext(probe)
    if prefix:
        if len(prefix) < MIN_CONFIRM_PREFIX:
            verdict = "probable"
            detail = (
                f"{len(prefix)}-byte prefix matched; below the "
                f"{MIN_CONFIRM_PREFIX}-byte confirmation threshold"
            )
        else:
            verdict, detail = "confirmed", "known plaintext prefix matched"
    elif plausibility.is_magic:
        verdict, detail = "probable", f"{plausibility.magic} magic"
    elif plausibility.is_text:
        verdict, detail = "probable", plausibility.detail
    else:
        verdict, detail = "weak", "no padding or MAC in this mode"
    bits = len(key) * 8
    return InferResult(
        cipher=f"aes-{bits}-{mode}",
        mode=mode,
        key_bits=bits,
        iv_source=iv_source,
        verdict=verdict,
        detail=detail,
        probe=probe,
        iv=iv,
        ciphertext=ciphertext,
        padding="none",
        little_endian=little_endian,
    )


def _gcm_result(
    key: bytes,
    data: bytes,
    aad: bytes,
    explicit_nonce: bytes,
    explicit_tag: bytes,
) -> Optional[InferResult]:
    if explicit_nonce or explicit_tag:
        if not explicit_nonce or not explicit_tag:
            raise UsageError("--gcm-nonce and --gcm-tag must be supplied together")
        nonce = explicit_nonce
        tag = explicit_tag
        ciphertext = data
        source = "explicit"
    else:
        trial = None
        for nonce_length in (12, 16):
            if len(data) < nonce_length + 16:
                continue
            nonce = data[:nonce_length]
            tag = data[-16:]
            candidate_ct = data[nonce_length:-16]
            try:
                aes_gcm_decrypt(key, nonce, candidate_ct, tag, aad=aad)
            except DecryptionError:
                continue
            trial = (nonce, tag, candidate_ct, f"nonce-{nonce_length}")
            break
        if trial is None:
            return None
        nonce, tag, ciphertext, source = trial
    plain = aes_gcm_decrypt(key, nonce, ciphertext, tag, aad=aad)
    bit_length = len(key) * 8
    return InferResult(
        cipher=f"aes-{bit_length}-gcm",
        mode="gcm",
        key_bits=bit_length,
        iv_source=source,
        verdict="confirmed",
        detail="GCM tag verified (256-bit authentication)",
        probe=plain[:64],
        gcm_nonce=nonce,
        gcm_tag=tag,
        ciphertext=ciphertext,
        padding="none",
        aad=aad,
    )


def _candidate_inputs(data: bytes, iv: Optional[bytes]):
    sources = []
    if iv is not None:
        if len(iv) != AES_BLOCK_SIZE:
            raise UsageError("--iv must be exactly 16 bytes")
        sources.append(("explicit", iv, data))
    sources.append(("zero", bytes(AES_BLOCK_SIZE), data))
    if len(data) > AES_BLOCK_SIZE:
        sources.append(("embedded", data[:AES_BLOCK_SIZE], data[AES_BLOCK_SIZE:]))
    return sources


def _write_outputs(
    results: list[InferResult],
    key: bytes,
    out_dir: str,
    overwrite: bool,
) -> list[dict]:
    directory = Path(out_dir)
    if directory.exists() and not directory.is_dir():
        raise OutputError(f"output path is not a directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, object]] = []
    for result in results:
        suffix = "_le" if result.little_endian else ""
        name = f"infer_{result.mode}_{result.iv_source}_{result.key_bits}{suffix}.bin"
        target = directory / name
        try:
            check_output_path(target, overwrite=overwrite)
            plaintext = result.decrypt(key)
        except (DecryptionError, OutputError, InputError) as exc:
            written.append({"file": str(target), "error": str(exc)})
            continue
        with atomic_writer(target, overwrite=overwrite) as handle:
            handle.write(plaintext)
        result.output = str(target)
        written.append({"file": str(target), "bytes": len(plaintext)})
    return written


def run(args: argparse.Namespace) -> int:
    key = _key(args)
    prefix = _prefix(args)
    if args.input == "-":
        data = sys.stdin.buffer.read()
    else:
        data = read_encoded_data(args.input, args.in_encoding, what="ciphertext")
    if not data:
        raise InputError("input ciphertext is empty")
    common.validate_side_outputs(
        args,
        inputs=(args.input if args.input != "-" else None, args.key_file),
    )
    iv = parse_hex_data(args.iv, what="IV") if args.iv is not None else None
    aad = parse_hex_data(args.aad, what="AAD") if args.aad else b""
    explicit_nonce = parse_hex_data(args.gcm_nonce, what="GCM nonce") if args.gcm_nonce else b""
    explicit_tag = parse_hex_data(args.gcm_tag, what="GCM tag") if args.gcm_tag else b""

    results: list[InferResult] = []

    gcm = _gcm_result(key, data, aad, explicit_nonce, explicit_tag)
    if gcm is not None:
        results.append(gcm)

    ecb = _block_result(key, "ecb", b"", "none", data, args.padding, prefix)
    if ecb is not None:
        results.append(ecb)
    for iv_source, mode_iv, ciphertext in _candidate_inputs(data, iv):
        result = _block_result(key, "cbc", mode_iv, iv_source, ciphertext, args.padding, prefix)
        if result is not None:
            results.append(result)
        for mode in ("cfb", "ofb"):
            result = _stream_result(key, mode, mode_iv, iv_source, ciphertext, prefix)
            if result is not None:
                results.append(result)
        for little_endian in (False, True):
            result = _stream_result(
                key,
                "ctr",
                mode_iv,
                iv_source + ("-le" if little_endian else "-be"),
                ciphertext,
                prefix,
                little_endian=little_endian,
            )
            if result is not None:
                results.append(result)

    results.sort(
        key=lambda item: (
            VERDICT_ORDER[item.verdict],
            item.mode,
            item.iv_source,
            item.key_bits,
        )
    )
    weak_count = sum(1 for result in results if result.verdict == "weak")
    visible = [result for result in results if result.verdict != "weak" or args.show_weak]
    outputs = []
    if args.out_dir and visible:
        outputs = _write_outputs(visible, key, args.out_dir, args.overwrite)

    payload = {
        "tool": "aesbreaker",
        "version": __version__,
        "command": "infer",
        "input": args.input,
        "key_bits": len(key) * 8,
        "known_prefix": prefix.hex() if prefix else None,
        "results": [result.as_dict() for result in visible],
        "weak_count": weak_count,
        "outputs": outputs,
        "errors": [],
    }
    if args.json_out:
        write_json(args.json_out, payload)
    if args.json:
        write_json(None, payload)
        return 0 if any(result.verdict != "weak" for result in visible) else 1

    print(f"Key: AES-{len(key) * 8} ({len(key)} bytes)")
    print(f"Input: {len(data)} bytes")
    if prefix:
        print(f"Known prefix: {format_hex(prefix)}")
    if not visible:
        print("No confirmed or probable candidates.")
        if weak_count:
            print(f"Hidden padding-only matches: {weak_count} (use --show-weak).")
        return 1
    for result in visible:
        if result.verdict == "confirmed":
            marker = "CONFIRMED"
        elif result.verdict == "probable":
            marker = "PROBABLE "
        else:
            marker = "WEAK     "
        print(f"{marker}  {result.cipher:<16}  iv={result.iv_source:<12}  {result.detail}")
        print(f"           {preview_bytes(result.probe)}")
        if result.output:
            print(f"           output: {result.output}")
    if weak_count and not args.show_weak:
        print(f"Hidden padding-only matches: {weak_count} (use --show-weak).")
    for output in outputs:
        if "error" in output:
            print(f"Could not write {output['file']}: {output['error']}", file=sys.stderr)
    return 0 if any(result.verdict != "weak" for result in visible) else 1
