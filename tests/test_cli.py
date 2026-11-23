from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from aesbreaker import cli
from aesbreaker.commands import common
from aesbreaker.commands import selftest as selftest_command
from aesbreaker.crypto import (
    aes_cbc_encrypt,
    aes_ctr_cipher,
    aes_gcm_encrypt,
    pkcs7_pad,
)
from aesbreaker.errors import UsageError

from .helpers import (
    PLAINTEXT,
    json_output,
    make_aescrypt,
    make_openssl,
    make_zip,
    run_cli,
)


def test_version():
    completed = run_cli("--version")
    assert completed.returncode == 0
    assert b"aesbreaker 2.0.0" in completed.stdout


def test_crack_aescrypt_wordlist(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    wordlist = tmp_path / "words.txt"
    wordlist.write_bytes(b"wrong\nhunter2\n")
    output = tmp_path / "plain.txt"
    completed = run_cli(
        "crack",
        str(container),
        "-w",
        str(wordlist),
        "-j",
        "1",
        "--no-status",
        "-o",
        str(output),
        "--overwrite",
    )
    assert completed.returncode == 0, completed.stderr
    assert output.read_bytes() == PLAINTEXT
    assert b"Password recovered: hunter2" in completed.stdout
    assert b"HMAC-SHA256" in completed.stdout


def test_crack_json_and_password_output(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    wordlist = tmp_path / "words.txt"
    wordlist.write_bytes(b"wrong\nhunter2\n")
    password_file = tmp_path / "password.bin"
    completed = run_cli(
        "crack",
        str(container),
        "-w",
        str(wordlist),
        "--no-decrypt",
        "--password-out",
        str(password_file),
        "--json",
        "-q",
    )
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["found"] is True
    assert payload["password"]["text"] == "hunter2"
    assert payload["password"]["hex"] == b"hunter2".hex()
    assert password_file.read_bytes() == b"hunter2"
    # stdout must contain only JSON.
    assert completed.stdout.startswith(b"{")


def test_crack_not_found_exit_code(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    wordlist = tmp_path / "words.txt"
    wordlist.write_bytes(b"wrong\nalso-wrong\n")
    completed = run_cli(
        "crack", str(container), "-w", str(wordlist), "-j", "1", "--no-status", "-q"
    )
    assert completed.returncode == 1
    assert b"Password not found" in completed.stdout


def test_crack_rules(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes", password=b"Hunter1")
    wordlist = tmp_path / "words.txt"
    wordlist.write_bytes(b"hunter\n")
    completed = run_cli(
        "crack",
        str(container),
        "-w",
        str(wordlist),
        "--rule",
        "c$1",
        "--no-decrypt",
        "--json",
        "-q",
        "--no-status",
    )
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["password"]["text"] == "Hunter1"


def test_crack_mask_and_stdin(tmp_path: Path):
    container = make_openssl(
        tmp_path / "secret.enc",
        password=b"a1",
        cipher="aes-256-cbc",
        digest="sha256",
    )
    completed = run_cli(
        "crack",
        str(container),
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-256-cbc",
        "--openssl-digest",
        "sha256",
        "--mask",
        "?l?d",
        "-j",
        "2",
        "--no-decrypt",
        "--json",
        "-q",
        "--no-status",
    )
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["password"]["text"] == "a1"
    assert payload["confidence"] == "probable"

    completed = run_cli(
        "crack",
        str(container),
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-256-cbc",
        "--openssl-digest",
        "sha256",
        "--stdin",
        "--no-decrypt",
        "--json",
        "-q",
        "--no-status",
        input_bytes=b"nope\na1\n",
    )
    assert completed.returncode == 0, completed.stderr
    assert json_output(completed)["password"]["text"] == "a1"


def test_crack_dry_run_and_benchmark(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    completed = run_cli("crack", str(container), "--mask", "?d?d", "--dry-run", "--json")
    assert completed.returncode == 0
    payload = json_output(completed)
    assert payload["dry_run"] is True
    assert payload["attack"]["total"] == 100

    completed = run_cli("crack", str(container), "--mask", "?d", "--benchmark", "2", "-q")
    assert completed.returncode == 0, completed.stderr
    assert b"Benchmark" in completed.stdout


def test_crack_existing_output_fails_before_attack(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    wordlist = tmp_path / "words.txt"
    wordlist.write_bytes(b"hunter2\n")
    output = tmp_path / "existing.txt"
    output.write_text("do not clobber")
    completed = run_cli("crack", str(container), "-w", str(wordlist), "-o", str(output), "-q")
    assert completed.returncode == 2
    assert b"already exists" in completed.stderr
    assert output.read_text() == "do not clobber"


def test_decrypt_aescrypt_and_wrong_password(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    output = tmp_path / "plain.txt"
    completed = run_cli("decrypt", str(container), "-p", "hunter2", "-o", str(output))
    assert completed.returncode == 0, completed.stderr
    assert output.read_bytes() == PLAINTEXT

    bad_output = tmp_path / "bad.txt"
    completed = run_cli("decrypt", str(container), "-p", "wrong", "-o", str(bad_output))
    assert completed.returncode == 3
    assert not bad_output.exists()


def test_decrypt_zip_and_openssl(tmp_path: Path):
    archive = make_zip(tmp_path / "secret.zip")
    out_dir = tmp_path / "zip-out"
    completed = run_cli("decrypt", str(archive), "-p", "hunter2", "-o", str(out_dir))
    assert completed.returncode == 0, completed.stderr
    assert (out_dir / "secret.txt").read_bytes() == PLAINTEXT

    openssl = make_openssl(tmp_path / "secret.enc", cipher="aes-256-cbc", digest="md5")
    output = tmp_path / "openssl-out.bin"
    completed = run_cli(
        "decrypt",
        str(openssl),
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-256-cbc",
        "--openssl-digest",
        "md5",
        "-p",
        "hunter2",
        "-o",
        str(output),
    )
    assert completed.returncode == 0, completed.stderr
    assert output.read_bytes() == PLAINTEXT


def test_decrypt_raw_cbc_and_gcm(tmp_path: Path):
    key = bytes(range(16))
    iv = bytes(range(16))
    ciphertext = aes_cbc_encrypt(key, iv, pkcs7_pad(PLAINTEXT))
    hex_file = tmp_path / "cipher.hex"
    hex_file.write_text(ciphertext.hex())
    output = tmp_path / "plain.bin"
    completed = run_cli(
        "decrypt",
        str(hex_file),
        "--format",
        "raw",
        "--cipher",
        "aes-128-cbc",
        "--key",
        key.hex(),
        "--iv",
        iv.hex(),
        "--in-encoding",
        "hex",
        "-o",
        str(output),
    )
    assert completed.returncode == 0, completed.stderr
    assert output.read_bytes() == PLAINTEXT

    gcm_key = bytes(range(32))
    nonce = bytes(range(1, 13))
    gcm_ciphertext, tag = aes_gcm_encrypt(gcm_key, nonce, PLAINTEXT)
    gcm_file = tmp_path / "gcm.bin"
    gcm_file.write_bytes(gcm_ciphertext)
    gcm_out = tmp_path / "gcm.plain"
    completed = run_cli(
        "decrypt",
        str(gcm_file),
        "--format",
        "raw",
        "--cipher",
        "aes-256-gcm",
        "--key",
        gcm_key.hex(),
        "--nonce",
        nonce.hex(),
        "--tag",
        tag.hex(),
        "-o",
        str(gcm_out),
    )
    assert completed.returncode == 0, completed.stderr
    assert gcm_out.read_bytes() == PLAINTEXT

    completed = run_cli(
        "decrypt",
        str(gcm_file),
        "--format",
        "raw",
        "--cipher",
        "aes-256-gcm",
        "--key",
        gcm_key.hex(),
        "--nonce",
        nonce.hex(),
        "--tag",
        "00" * 16,
        "-o",
        str(tmp_path / "bad"),
    )
    assert completed.returncode == 3


def test_decrypt_to_stdout_is_binary_clean(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    completed = run_cli("decrypt", str(container), "-p", "hunter2", "-o", "-")
    assert completed.returncode == 0
    assert completed.stdout == PLAINTEXT
    assert b"Format:" in completed.stderr


def test_inspect_and_analyze_json(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    completed = run_cli("inspect", str(container), "--json")
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["format"] == "aescrypt"
    assert payload["details"]["version"] == 2
    assert payload["sha256"]

    duplicate_data = b"ABCD" * 64
    completed = run_cli("analyze", str(container), "--json", "--limit", "1M")
    assert completed.returncode == 0
    analyzed = json_output(completed)
    assert analyzed["entropy_bits_per_byte"] > 0
    assert analyzed["is_container"] is True
    assert analyzed["ecb_suspected"] is False

    ecb_file = tmp_path / "ecb.bin"
    ecb_file.write_bytes(duplicate_data)
    completed = run_cli("analyze", str(ecb_file), "--json")
    payload = json_output(completed)
    assert payload["ecb_suspected"] is True


def test_derive_json():
    completed = run_cli(
        "derive",
        "--kdf",
        "evp",
        "--password",
        "password",
        "--salt",
        "3132333435363738",
        "--digest",
        "md5",
        "--key-length",
        "32",
        "--iv-length",
        "16",
        "--json",
    )
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["key"].startswith("bbb0ddff1b944b3c")
    assert payload["iv"].startswith("fa1dd9ab")


def test_encrypt_all_formats(tmp_path: Path):
    plain = tmp_path / "plain.txt"
    plain.write_bytes(PLAINTEXT)

    # AES Crypt
    aescrypt = tmp_path / "out.aes"
    completed = run_cli(
        "encrypt", str(plain), "-p", "secret", "--format", "aescrypt", "-o", str(aescrypt)
    )
    assert completed.returncode == 0, completed.stderr
    decrypted = tmp_path / "aescrypt.dec"
    completed = run_cli("decrypt", str(aescrypt), "-p", "secret", "-o", str(decrypted))
    assert completed.returncode == 0, completed.stderr
    assert decrypted.read_bytes() == PLAINTEXT

    # OpenSSL
    openssl = tmp_path / "out.enc"
    completed = run_cli(
        "encrypt",
        str(plain),
        "-p",
        "secret",
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-192-cbc",
        "--openssl-digest",
        "sha256",
        "-o",
        str(openssl),
    )
    assert completed.returncode == 0, completed.stderr
    decrypted = tmp_path / "openssl.dec"
    completed = run_cli(
        "decrypt",
        str(openssl),
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-192-cbc",
        "--openssl-digest",
        "sha256",
        "-p",
        "secret",
        "-o",
        str(decrypted),
    )
    assert completed.returncode == 0, completed.stderr
    assert decrypted.read_bytes() == PLAINTEXT

    # ZIP
    archive = tmp_path / "out.zip"
    completed = run_cli(
        "encrypt",
        str(plain),
        "-p",
        "secret",
        "--format",
        "zip-aes",
        "--zip-strength",
        "128",
        "-o",
        str(archive),
    )
    assert completed.returncode == 0, completed.stderr
    out_dir = tmp_path / "zip-dec"
    completed = run_cli("decrypt", str(archive), "-p", "secret", "-o", str(out_dir))
    assert completed.returncode == 0, completed.stderr
    assert (out_dir / "plain.txt").read_bytes() == PLAINTEXT


def test_cribdrag_and_recover_iv(tmp_path: Path):
    key = bytes(range(32))
    iv = bytes(range(16))
    first_plain = b"The secret message is hidden in plain sight. "
    second_plain = b"Attack at dawn, bring all the supplies you can."
    first = aes_ctr_cipher(key, iv).encrypt(first_plain)
    second = aes_ctr_cipher(key, iv).encrypt(second_plain)
    first_path = tmp_path / "first.bin"
    second_path = tmp_path / "second.bin"
    first_path.write_bytes(first)
    second_path.write_bytes(second)
    completed = run_cli(
        "cribdrag",
        str(first_path),
        str(second_path),
        "--crib",
        "secret message",
        "--json",
    )
    assert completed.returncode == 0, completed.stderr
    results = json_output(completed)["results"]
    assert any(result["offset"] == 4 for result in results)

    cbc_pt = b"A" * 16 + b"B" * 16
    cbc_ct = aes_cbc_encrypt(bytes(range(16)), iv, cbc_pt)
    cipher_path = tmp_path / "cbc.bin"
    cipher_path.write_bytes(cbc_ct)
    completed = run_cli(
        "recover-iv",
        str(cipher_path),
        "--key",
        bytes(range(16)).hex(),
        "--mode",
        "cbc",
        "--plaintext-block",
        ("A" * 16).encode().hex(),
        "--json",
    )
    assert completed.returncode == 0, completed.stderr
    assert json_output(completed)["recovered"] == iv.hex()


def test_infer_gcm_and_prefix(tmp_path: Path):
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"PNG-like infer payload that is long enough. " * 3
    ciphertext, tag = aes_gcm_encrypt(key, nonce, plaintext)
    path = tmp_path / "gcm.bin"
    path.write_bytes(nonce + ciphertext + tag)
    completed = run_cli("infer", str(path), "--key", key.hex(), "--json")
    assert completed.returncode == 0, completed.stderr
    results = json_output(completed)["results"]
    assert any(result["verdict"] == "confirmed" and result["mode"] == "gcm" for result in results)

    cbc_iv = bytes(range(16))
    cbc_ct = aes_cbc_encrypt(key, cbc_iv, pkcs7_pad(plaintext))
    embedded = tmp_path / "embedded.bin"
    embedded.write_bytes(cbc_iv + cbc_ct)
    out_dir = tmp_path / "infer-out"
    completed = run_cli(
        "infer",
        str(embedded),
        "--key",
        key.hex(),
        "--known-prefix",
        "PNG-like infer",
        "--out-dir",
        str(out_dir),
        "--json",
    )
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["results"][0]["verdict"] == "confirmed"
    assert any(result["output"] for result in payload["results"])

    # A short prefix is evidence, but not 8 bytes of evidence.
    completed = run_cli(
        "infer",
        str(embedded),
        "--key",
        key.hex(),
        "--known-prefix",
        "PNG",
        "--json",
    )
    assert completed.returncode == 0
    short_payload = json_output(completed)
    assert short_payload["results"]
    assert all(result["verdict"] != "confirmed" for result in short_payload["results"])


def test_selftest_command():
    completed = run_cli("selftest", "--no-process", "--json")
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["failed"] == 0


def test_encrypt_rejects_mismatched_options(tmp_path: Path):
    plain = tmp_path / "plain.txt"
    plain.write_bytes(PLAINTEXT)
    completed = run_cli(
        "encrypt",
        str(plain),
        "-p",
        "secret",
        "--format",
        "aescrypt",
        "--openssl-pbkdf2",
        "-o",
        str(tmp_path / "out.aes"),
    )
    assert completed.returncode == 2
    assert b"OpenSSL options" in completed.stderr


def test_side_outputs_cannot_clobber_inputs(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    original = container.read_bytes()
    completed = run_cli("inspect", str(container), "--json-out", str(container), "--no-hash")
    assert completed.returncode == 2
    assert container.read_bytes() == original

    completed = run_cli(
        "crack",
        str(container),
        "-w",
        str(tmp_path / "words.txt"),
        "--no-decrypt",
        "--password-out",
        str(container),
    )
    # The wordlist check may happen first, but no output is written.
    assert container.read_bytes() == original

    plain = tmp_path / "plain.txt"
    plain.write_bytes(PLAINTEXT)
    ciphertext = tmp_path / "out.aes"
    completed = run_cli(
        "encrypt",
        str(plain),
        "-p",
        "secret",
        "-o",
        str(ciphertext),
        "--json-out",
        str(ciphertext),
    )
    assert completed.returncode == 2
    assert not ciphertext.exists()


def test_stdout_alias_collisions_are_rejected(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    completed = run_cli("inspect", str(container), "--json", "--json-out", "-")
    assert completed.returncode == 2
    assert completed.stdout == b""

    completed = run_cli("decrypt", str(container), "-p", "hunter2", "-o", "-", "--json-out", "-")
    assert completed.returncode == 2
    assert completed.stdout == b""


def test_gcm_forged_tag_leaks_no_stdout(tmp_path: Path):
    key = bytes(range(32))
    nonce = bytes(range(1, 13))
    ciphertext, _tag = aes_gcm_encrypt(key, nonce, PLAINTEXT)
    path = tmp_path / "gcm.bin"
    path.write_bytes(ciphertext)
    completed = run_cli(
        "decrypt",
        str(path),
        "--format",
        "raw",
        "--cipher",
        "aes-256-gcm",
        "--key",
        key.hex(),
        "--nonce",
        nonce.hex(),
        "--tag",
        "00" * 16,
        "-o",
        "-",
    )
    assert completed.returncode == 3
    assert completed.stdout == b""


def test_benchmark_writes_json_out_without_json(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    target = tmp_path / "bench.json"
    completed = run_cli(
        "crack",
        str(container),
        "--mask",
        "?d",
        "--benchmark",
        "1",
        "--json-out",
        str(target),
        "-q",
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(target.read_text())
    assert payload["benchmark"]["candidates"] == 1


def test_analyze_limit_bounds_the_sample(tmp_path: Path):
    path = tmp_path / "large.bin"
    path.write_bytes(b"A" * 512 + b"\x00" * 100_000)
    completed = run_cli("analyze", str(path), "--limit", "1K", "--no-hash", "--json")
    assert completed.returncode == 0, completed.stderr
    payload = json_output(completed)
    assert payload["analyzed_bytes"] == 1024
    assert payload["size"] == len(path.read_bytes())
    assert payload["sampled"] is True


def test_crack_rejects_short_known_prefix(tmp_path: Path):
    container = make_openssl(tmp_path / "secret.enc")
    wordlist = tmp_path / "words.txt"
    wordlist.write_bytes(b"hunter2\n")
    completed = run_cli(
        "crack",
        str(container),
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-256-cbc",
        "--openssl-digest",
        "sha256",
        "--known-prefix",
        "T",
        "-w",
        str(wordlist),
        "--no-decrypt",
        "-q",
    )
    assert completed.returncode == 2
    assert b"at least" in completed.stderr


def test_derive_option_validation():
    completed = run_cli("derive", "--kdf", "evp", "--password", "x", "--iterations", "2")
    assert completed.returncode == 2
    completed = run_cli("derive", "--kdf", "evp", "--password", "x", "--length", "16")
    assert completed.returncode == 2
    completed = run_cli("derive", "--kdf", "pbkdf2", "--password", "x", "--info", "aa")
    assert completed.returncode == 2


def test_encrypt_rejects_nopad_for_stream_cipher(tmp_path: Path):
    plain = tmp_path / "plain.txt"
    plain.write_bytes(PLAINTEXT)
    completed = run_cli(
        "encrypt",
        str(plain),
        "-p",
        "secret",
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-256-ctr",
        "--openssl-nopad",
        "-o",
        str(tmp_path / "out.enc"),
    )
    assert completed.returncode == 2


def test_empty_nosalt_nopad_openssl_file(tmp_path: Path):
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    completed = run_cli(
        "inspect",
        str(empty),
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-256-cbc",
        "--openssl-digest",
        "sha256",
        "--openssl-nosalt",
        "--openssl-nopad",
        "--json",
    )
    assert completed.returncode == 0, completed.stderr
    assert json_output(completed)["details"]["ciphertext_bytes"] == 0

    output = tmp_path / "empty.out"
    completed = run_cli(
        "decrypt",
        str(empty),
        "--format",
        "openssl-enc",
        "--openssl-cipher",
        "aes-256-cbc",
        "--openssl-digest",
        "sha256",
        "--openssl-nosalt",
        "--openssl-nopad",
        "-p",
        "x",
        "-o",
        str(output),
    )
    assert completed.returncode == 0, completed.stderr
    assert output.read_bytes() == b""


def test_partial_zip_extraction_exits_three(tmp_path: Path):
    import shutil
    import subprocess

    from aesbreaker.formats.zip_aes import parse_zip

    sevenzip = shutil.which("7z") or shutil.which("7za") or shutil.which("7zr")
    if not sevenzip:
        pytest.skip("7z is not installed")
    (tmp_path / "a.txt").write_bytes(b"first\n")
    (tmp_path / "b.txt").write_bytes(b"second\n")
    archive = tmp_path / "multi.zip"
    result = subprocess.run(
        [
            sevenzip,
            "a",
            "-tzip",
            "-mem=AES256",
            "-phunter2",
            str(archive),
            "a.txt",
            "b.txt",
        ],
        cwd=str(tmp_path),
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0
    directory = parse_zip(archive)
    target = directory.entries[1]
    data = bytearray(archive.read_bytes())
    data[target.ciphertext_offset] ^= 0x80
    archive.write_bytes(bytes(data))

    out_dir = tmp_path / "out"
    completed = run_cli("decrypt", str(archive), "-p", "hunter2", "-o", str(out_dir))
    assert completed.returncode == 3
    assert (out_dir / "a.txt").read_bytes() == b"first\n"
    assert not (out_dir / "b.txt").exists()


def test_raw_hex_stdin_and_stdout(tmp_path: Path):
    key = bytes(range(16))
    iv = bytes(range(16))
    ciphertext = aes_cbc_encrypt(key, iv, pkcs7_pad(PLAINTEXT))
    completed = run_cli(
        "decrypt",
        "-",
        "--format",
        "raw",
        "--cipher",
        "aes-128-cbc",
        "--key",
        key.hex(),
        "--iv",
        iv.hex(),
        "--in-encoding",
        "hex",
        "-o",
        "-",
        input_bytes=ciphertext.hex().encode(),
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == PLAINTEXT


def test_wordlist_is_protected_from_output_paths(tmp_path: Path):
    container = make_aescrypt(tmp_path / "secret.aes")
    wordlist = tmp_path / "words.txt"
    wordlist.write_bytes(b"wrong\nhunter2\n")
    original = wordlist.read_bytes()

    completed = run_cli(
        "crack",
        str(container),
        "-w",
        str(wordlist),
        "--json-out",
        str(wordlist),
        "--no-decrypt",
        "-q",
    )
    assert completed.returncode == 2
    assert wordlist.read_bytes() == original

    completed = run_cli(
        "crack",
        str(container),
        "-w",
        str(wordlist),
        "-o",
        str(wordlist),
        "--overwrite",
        "-q",
    )
    assert completed.returncode == 2
    assert wordlist.read_bytes() == original


def test_cli_interrupt_and_broken_pipe(monkeypatch, capsys):
    def interrupt(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(selftest_command, "run", interrupt)
    assert cli.main(["selftest"]) == 130
    assert "interrupted" in capsys.readouterr().err

    def broken_pipe(args):
        raise BrokenPipeError

    monkeypatch.setattr(selftest_command, "run", broken_pipe)
    assert cli.main(["selftest"]) == 0


def test_password_prompt_and_mismatch(monkeypatch):
    args = SimpleNamespace(
        password=None,
        password_hex=None,
        password_file=None,
    )

    class TTY:
        def isatty(self):
            return True

    monkeypatch.setattr(common.sys, "stdin", TTY())
    monkeypatch.setattr(common.getpass, "getpass", lambda prompt: "secret")
    assert common.resolve_password(args) == b"secret"

    answers = iter(["first", "second"])
    monkeypatch.setattr(common.getpass, "getpass", lambda prompt: next(answers))
    with pytest.raises(UsageError, match="do not match"):
        common.resolve_password(args, confirm=True)


def test_auto_base64_aes_and_zip(tmp_path: Path):
    from .helpers import make_aescrypt, make_zip

    aes = make_aescrypt(tmp_path / "backup.aes")
    encoded = tmp_path / "backup.aes.b64"
    encoded.write_text(base64.b64encode(aes.read_bytes()).decode())
    words = tmp_path / "words.txt"
    words.write_bytes(b"wrong\nhunter2\n")
    completed = run_cli(
        "crack",
        str(encoded),
        "--format",
        "aescrypt",
        "-w",
        str(words),
        "-q",
        "--no-status",
        "--overwrite",
    )
    assert completed.returncode == 0, completed.stderr
    recovered = tmp_path / "backup.dec"
    assert recovered.read_bytes() == PLAINTEXT

    inspection = run_cli(
        "inspect",
        str(encoded),
        "--format",
        "aescrypt",
        "--json",
        "--no-hash",
    )
    assert inspection.returncode == 0, inspection.stderr
    assert json_output(inspection)["input"] == str(encoded)

    zip_path = make_zip(tmp_path / "archive.zip")
    zip_b64 = tmp_path / "archive.zip.b64"
    zip_b64.write_text(base64.b64encode(zip_path.read_bytes()).decode())
    out_dir = tmp_path / "extracted"
    completed = run_cli(
        "decrypt",
        str(zip_b64),
        "--format",
        "zip-aes",
        "-p",
        "hunter2",
        "-o",
        str(out_dir),
    )
    assert completed.returncode == 0, completed.stderr
    assert (out_dir / "secret.txt").read_bytes() == PLAINTEXT


def test_auto_base64_does_not_touch_raw_mode(tmp_path: Path):
    from aesbreaker.crypto import aes_cbc_encrypt, pkcs7_pad

    key = bytes(range(16))
    iv = bytes(range(16))
    ciphertext = aes_cbc_encrypt(key, iv, pkcs7_pad(PLAINTEXT))
    encoded = tmp_path / "raw.b64"
    encoded.write_text(base64.b64encode(ciphertext).decode())
    completed = run_cli(
        "decrypt",
        str(encoded),
        "--format",
        "raw",
        "--cipher",
        "aes-128-cbc",
        "--key",
        key.hex(),
        "--iv",
        iv.hex(),
        "--in-encoding",
        "base64",
        "-o",
        "-",
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == PLAINTEXT
