from __future__ import annotations

import gzip
import io
import os
import threading
from pathlib import Path

import pytest

from aesbreaker.errors import InputError, OutputError
from aesbreaker.util import (
    atomic_writer,
    b64_decode,
    count_wordlist,
    count_wordlist_lines,
    decode_data_arg,
    escape_control,
    format_duration,
    iter_wordlist_lines,
    open_wordlist,
    parse_hex_data,
    parse_size,
    read_encoded_data,
    safe_zip_target,
    sha256_file,
    strip_line_ending,
)


def test_parse_hex_variants():
    assert parse_hex_data("00:11:22") == b"\x00\x11\x22"
    assert parse_hex_data("0x00-11 22") == b"\x00\x11\x22"
    assert parse_hex_data("") == b""
    with pytest.raises(InputError):
        parse_hex_data("abc")
    with pytest.raises(InputError):
        parse_hex_data("zz")


def test_base64_decode():
    assert b64_decode("aGVsbG8=") == b"hello"
    assert b64_decode("aGVs\nbG8=") == b"hello"
    assert b64_decode("aGVsbG8") == b"hello"
    with pytest.raises(InputError):
        b64_decode("!!!!")


def test_decode_data_arg(tmp_path: Path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"\x00\x01")
    assert decode_data_arg(str(path)) == b"\x00\x01"
    assert decode_data_arg("hex:0001") == b"\x00\x01"
    assert decode_data_arg("base64:AAE=") == b"\x00\x01"
    assert decode_data_arg("0001") == b"\x00\x01"
    with pytest.raises(InputError):
        decode_data_arg("does-not-exist-and-is-not-hex")


def test_parse_size():
    assert parse_size("0") == 0
    assert parse_size("512") == 512
    assert parse_size("1K") == 1024
    assert parse_size("2MiB") == 2 * 1024**2
    assert parse_size("1G") == 1024**3
    with pytest.raises(ValueError):
        parse_size("12XB")


def test_format_duration():
    assert format_duration(0) == "00:00:00"
    assert format_duration(61) == "00:01:01"
    assert format_duration(None) == "--:--:--"


def test_line_handling_preserves_spaces():
    assert strip_line_ending(b"pass \r\n") == b"pass "
    assert strip_line_ending(b"pass\n") == b"pass"
    assert strip_line_ending(b"pass") == b"pass"
    assert strip_line_ending(b"pass\r") == b"pass"

    stream = io.BytesIO(b"one \r\n\r\ntwo\nthree")
    assert list(iter_wordlist_lines(stream)) == [b"one ", b"two", b"three"]
    stream.seek(0)
    assert count_wordlist_lines(stream) == 3
    stream.seek(0)
    assert count_wordlist_lines(stream, skip_empty=False) == 4


def test_count_wordlist_compressed(tmp_path: Path):
    plain = tmp_path / "words.txt"
    plain.write_bytes(b"one\n\ntwo\r\nthree")
    compressed = tmp_path / "words.txt.gz"
    with gzip.open(compressed, "wb") as handle:
        handle.write(plain.read_bytes())
    assert count_wordlist(str(plain)) == 3
    assert count_wordlist(str(compressed)) == 3
    with gzip.open(compressed, "rb") as handle:
        assert list(iter_wordlist_lines(handle)) == [b"one", b"two", b"three"]


def test_atomic_writer_semantics(tmp_path: Path):
    target = tmp_path / "out.bin"
    target.write_bytes(b"old")
    with pytest.raises(OutputError):
        with atomic_writer(target) as handle:
            handle.write(b"new")
    assert target.read_bytes() == b"old"

    with atomic_writer(target, overwrite=True) as handle:
        handle.write(b"new")
    assert target.read_bytes() == b"new"

    failing = tmp_path / "failing.bin"
    with pytest.raises(RuntimeError):
        with atomic_writer(failing) as handle:
            handle.write(b"partial")
            raise RuntimeError("boom")
    assert not failing.exists()
    assert not list(tmp_path.glob(".failing.bin.*"))


def test_safe_zip_target_rejects_traversal(tmp_path: Path):
    base = tmp_path / "extract"
    base.mkdir()
    assert safe_zip_target(base, "dir/file.txt") == base / "dir" / "file.txt"
    for name in (
        "../evil",
        "/etc/passwd",
        "C:\\evil",
        "a/../../evil",
        "",
        "a\x00b",
        "dir/CON.txt",
    ):
        with pytest.raises(OutputError):
            safe_zip_target(base, name)


def test_safe_zip_target_rejects_symlink_component(tmp_path: Path):
    base = tmp_path / "extract"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = base / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available")
    with pytest.raises(OutputError):
        safe_zip_target(base, "link/file.txt")


def test_read_encoded_data(tmp_path: Path):
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"\x00\xff")
    assert read_encoded_data(raw, "raw") == b"\x00\xff"
    assert read_encoded_data(raw, "auto") == b"\x00\xff"

    hex_file = tmp_path / "cipher.hex"
    hex_file.write_text("00 ff 10\n")
    assert read_encoded_data(hex_file, "hex") == b"\x00\xff\x10"
    assert read_encoded_data(hex_file, "auto") == b"\x00\xff\x10"

    b64_file = tmp_path / "cipher.b64"
    b64_file.write_text("AP8Q\n")
    assert read_encoded_data(b64_file, "base64") == b"\x00\xff\x10"
    assert read_encoded_data(b64_file, "auto") == b"\x00\xff\x10"

    with pytest.raises(InputError):
        read_encoded_data(raw, "nonsense")


def test_sha256_file(tmp_path: Path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abc")
    assert sha256_file(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_escape_control():
    assert escape_control("plain text") == "plain text"
    assert escape_control("a\x1b[31mred") == "a\\x1b[31mred"
    assert escape_control("line\nnext") == "line\\x0anext"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not available")
def test_open_wordlist_fifo(tmp_path: Path):
    fifo = tmp_path / "wordlist.fifo"
    os.mkfifo(fifo)

    def writer():
        with open(fifo, "wb") as handle:
            handle.write(b"alpha\n\nbeta\n")

    thread = threading.Thread(target=writer, daemon=True)
    thread.start()
    with open_wordlist(str(fifo)) as stream:
        lines = list(stream)
    thread.join(timeout=5)
    assert lines == [b"alpha\n", b"\n", b"beta\n"]
