# AES-Breaker

[![CI](https://github.com/BridgerAlderson/AES-Breaker/actions/workflows/ci.yml/badge.svg)](https://github.com/BridgerAlderson/AES-Breaker/actions/workflows/ci.yml)

AES decryption, password recovery, and cryptanalysis for AES file containers.

Each supported container is parsed byte-for-byte and every password candidate
is tested with the strongest check the format provides. Results are labelled
`confirmed`, `probable`, or `weak` instead of being selected by a readability
score.

```text
$ aesbreaker crack backup.zip.aes -w rockyou.txt
Password recovered: hunter2
Password hex: 68756e74657232
Confidence: confirmed
Verification: HMAC-SHA256 (256-bit)
Attempts: 1,248 (00:00:06, 208/s)
Output: backup.zip
```

## What it supports

| Container | Crypto | Password check | Confidence |
|---|---|---|---|
| **AES Crypt v1/v2/v3** | AES-256-CBC, random internal key; v1/v2 use 8192-round SHA-256 ACKDF over the UTF-16LE password, v3 uses PBKDF2-HMAC-SHA512 over the UTF-8 password; HMAC-SHA256 | 256-bit HMAC over the encrypted IV/key (v3 also covers the version byte) | confirmed |
| **OpenSSL `enc`** | AES-128/192/256 in CBC, ECB, CFB1/CFB8/CFB128, OFB, or CTR; `EVP_BytesToKey` or PBKDF2; MD5/SHA-1/SHA-2 digests; salted or `-nosalt`; optional `-nopad` | format has **no MAC**; PKCS#7 padding is only ~1/256 evidence | confirmed only with an exact known plaintext prefix; otherwise probable/weak |
| **WinZip AES** (AE-1/AE-2) | AES-128/192/256-CTR, PBKDF2-HMAC-SHA1/1000, 10-byte HMAC-SHA1 auth code | 2-byte verifier prefilter then HMAC auth code | confirmed |
| **Custom (JSON spec)** | AES-128/192/256 CBC/ECB/CTR/CFB1/CFB8/CFB128/OFB/GCM; PBKDF2, `EVP_BytesToKey`, scrypt, HKDF, or optional Argon2id; explicit, embedded, zero, or derived IV; PKCS#7 or none | spec-defined: known prefix ≥8 bytes, known 16-byte block, or GCM tag | confirmed with an oracle; `probable`/`weak` only with `allow_heuristic` |

Additional commands cover raw AES with explicit parameters, ECB detection,
statistical analysis, key derivation, CTR nonce-reuse crib dragging, IV /
keystream recovery, and a built-in self-test.

## Install

Requirements: Python 3.9+, [pycryptodome].

```bash
pip install .
# development
pip install -e '.[dev]'
```

From a checkout without installing:

```bash
python -m aesbreaker --help
```

After installation the `aesbreaker` command and the compatibility launcher
`python AesBreaker.py` are available.

## Password handling

`-p/--password` and `--password-hex` are convenient, but command-line arguments
are visible in the process list and shell history. Prefer the interactive
prompt (omit the password option) or a permission-restricted file:

```bash
aesbreaker decrypt backup.aes --password-file ~/.secrets/backup.pass -o backup.tar
```

Notes:

- `--password-file` reads the first line and removes its line ending. Protect
  the file with mode 0600.
- `--json` and `--json-out` include the recovered password. `--json-out` files
  are created atomically with mode 0600, but stdout/terminal logs may be
  captured elsewhere.
- Passwords and derived keys necessarily exist in process memory while the
  command runs; Python cannot guarantee secure erasure of every copy.
- For non-UTF-8 passwords use `--password-hex` or a binary `--password-file`.

## Quick start

### AES Crypt / pyAesCrypt

v1, v2, and v3 containers are auto-detected. v2 is written by default for
pyAesCrypt compatibility; `--aescrypt-version 3` writes the modern
PBKDF2-HMAC-SHA512 format.

```bash
aesbreaker crack secret.txt.aes -w wordlists/rockyou.txt
# base64-encoded AES/OpenSSL/ZIP containers are auto-decoded
aesbreaker crack backup.aes.b64 -w wordlists/rockyou.txt
aesbreaker crack secret.txt.aes -w words.txt --rules rules/leet.rule
aesbreaker crack secret.txt.aes --mask '?u?l?l?l?l?d?d?d'
aesbreaker crack secret.txt.aes -w words.txt --mask-append '?d?d'
aesbreaker crack secret.txt.aes -w first.txt --combinator second.txt

aesbreaker decrypt secret.txt.aes -p hunter2 -o secret.txt
aesbreaker inspect secret.txt.aes

# Modern AES Crypt v3 output (PBKDF2-HMAC-SHA512)
aesbreaker encrypt secret.txt -p hunter2 --aescrypt-version 3 \
  --aescrypt-iterations 600000 -o secret.txt.aes
```

### OpenSSL `enc`

The cipher and KDF parameters are not stored in the file, so they must be
supplied explicitly; guessing them produces false results.

```bash
# Old-style OpenSSL 1.1 file: EVP_BytesToKey + MD5
aesbreaker crack document.enc \
  --format openssl-enc --openssl-cipher aes-256-cbc --openssl-digest md5 \
  -w words.txt

# OpenSSL 3 PBKDF2 file
aesbreaker crack document.enc \
  --format openssl-enc --openssl-cipher aes-256-cbc --openssl-digest sha256 \
  --openssl-pbkdf2 --openssl-iterations 10000 \
  -w words.txt --known-prefix '{"version":'

# -nosalt file
aesbreaker decrypt document.enc --format openssl-enc --openssl-cipher aes-256-cbc \
  --openssl-digest md5 --openssl-nosalt -p hunter2 -o document.txt

# Unpadded CBC produced with: openssl enc -aes-256-cbc -nopad ...
aesbreaker decrypt document.enc --format openssl-enc --openssl-cipher aes-256-cbc \
  --openssl-digest sha256 --openssl-nopad -p hunter2 -o document.txt
```

Stream modes (CTR/CFB/OFB) have no padding and no MAC. Cracking them therefore
requires an exact plaintext prefix:

```bash
aesbreaker crack stream.enc \
  --format openssl-enc --openssl-cipher aes-256-ctr --openssl-digest sha256 \
  --known-prefix-hex 89504e470d0a1a0a -w words.txt
```

A `-nopad` CBC/ECB file has no padding either. Without a known prefix, a
candidate can only be labelled probable from text/magic heuristics;
`--policy any` is rejected for such files because there is no padding to test.

### Custom / headerless AES with a JSON spec

When the blob is not a recognized container but the scheme is known, use
`--format custom --spec spec.json`. The spec names one cipher, one KDF, one IV
source, and a verification oracle.

Example: `salt ‖ IV ‖ ciphertext`, base64-encoded, PBKDF2-HMAC-SHA256, known
JSON prefix.

```json
{
  "version": 1,
  "cipher": "aes-256-cbc",
  "input_encoding": "base64",
  "ciphertext_offset": 32,
  "kdf": {
    "type": "pbkdf2",
    "digest": "sha256",
    "iterations": 200000,
    "salt_offset": 0,
    "salt_length": 16
  },
  "iv": {"source": "embedded", "offset": 16, "length": 16},
  "padding": "pkcs7",
  "oracle": {"type": "known_prefix", "hex": "7b2276657273696f6e223a"}
}
```

```bash
aesbreaker inspect blob.b64 --format custom --spec spec.json
aesbreaker crack blob.b64 --format custom --spec spec.json -w words.txt
aesbreaker decrypt blob.b64 --format custom --spec spec.json -p hunter2 -o plain.bin
aesbreaker encrypt plain.bin --format custom --spec spec.json -p hunter2 -o blob.custom
```

For writing, the same spec defines cipher/KDF/IV/padding and offsets. Embedded
salt/IV bytes are generated randomly at their declared offsets; the ciphertext
goes at `ciphertext_offset`; for GCM the oracle must provide
`tag_offset`/`tag_length`. The writer emits raw bytes, so `input_encoding` and a
plaintext-prefix oracle are ignored.

Supported:

- **Ciphers:** AES-128/192/256 CBC, ECB, CTR, CFB1/CFB8/CFB128, OFB, GCM.
- **KDFs:** PBKDF2 (digest + iterations + salt), OpenSSL-style
  `EVP_BytesToKey`, scrypt, HKDF, and Argon2id (optional `argon2` extra).
- **IV/nonce:** `explicit`, `embedded` (offset/length), `zero`, or `derived`
  from the KDF output after the key. ECB takes no IV.
- **Input:** `raw`, `hex`, or `base64`, with `ciphertext_offset` and optional
  `ciphertext_length` into the decoded payload.
- **Oracles:**
  - `known_prefix`: exact plaintext at offset 0, at least 8 bytes → confirmed;
  - `known_block`: one full 16-byte plaintext block at a block-aligned offset,
    CBC/ECB only → confirmed;
  - `gcm_tag`: 8–16-byte GCM tag, optionally read from the payload with
    `tag_offset`/`tag_length`, plus optional `aad_hex` → confirmed.
- **Password encoding:** `raw` (default), `utf-8`, `utf-16-le`, `utf-16-be`.

GCM requires a tag; a plaintext prefix is not accepted as a substitute. If
there is no oracle at all, the spec must set `"allow_heuristic": true`; such a
crack can only return `probable` (text/magic) or `weak` (padding), never
`confirmed`. An incorrect spec produces no hit; modes and IVs are not changed silently.

The version-1 schema is published at
[docs/custom-spec.schema.json](docs/custom-spec.schema.json), with a runnable
template at [examples/custom-spec.json](examples/custom-spec.json). Argon2
requires `pip install 'aesbreaker[argon2]'`; scrypt limits `N*r` to 1 GiB of
memory.

### WinZip AES

```bash
aesbreaker crack archive.zip -w words.txt -j 8
aesbreaker crack archive.zip -w words.txt --entry 'secret/report.pdf'
aesbreaker decrypt archive.zip -p hunter2 -o extracted/
```

ZipCrypto entries are recognized but not attacked: they are not AES.

Extraction reports each entry. A partial extraction (for example one entry
using a different password, unsupported compression, or exceeding
`--max-extract-size`) still extracts the readable entries, lists the failures,
and exits 3.

### Raw AES with explicit parameters

```bash
# CBC with PKCS#7
aesbreaker decrypt ciphertext.bin --format raw --cipher aes-256-cbc \
  --key 000102...1f --iv 101112...1f -o plaintext.bin

# CTR; --iv is the initial counter
aesbreaker decrypt ciphertext.bin --format raw --cipher aes-128-ctr \
  --key 000102...0f --iv 101112...1f -o plaintext.bin

# GCM: the tag is always verified
aesbreaker decrypt ciphertext.bin --format raw --cipher aes-256-gcm \
  --key 000102...1f --nonce 000102030405060708090a0b \
  --tag aabbcc... -o plaintext.bin
```

Keys must be exactly 16, 24, or 32 bytes. AES-Breaker never silently pads or
truncates a key. Use `aesbreaker derive` if you need to reproduce a KDF.

### Inspect, analyze, infer, derive

```bash
aesbreaker inspect archive.zip
aesbreaker inspect suspicious.enc --openssl-cipher aes-256-cbc --openssl-digest md5
aesbreaker analyze unknown.bin
aesbreaker analyze unknown.bin --json

# Recover IV / keystream from a known plaintext block
aesbreaker recover-iv cipher.bin --key 000102...0f --mode cbc \
  --plaintext-block 00112233445566778899aabbccddeeff

# Two CTR/OFB ciphertexts under the same key+nonce
aesbreaker cribdrag first.bin second.bin --crib 'the secret is'

# Rank raw mode/IV interpretations with explicit confidence
aesbreaker infer mystery.bin --key 000102...1f --known-prefix 'PK' --out-dir candidates/

# Reproduce EVP_BytesToKey exactly as openssl does
aesbreaker derive --kdf evp --password hunter2 --salt 0011223344556677 \
  --digest md5 --key-length 32 --iv-length 16

# PBKDF2 with key+IV split
aesbreaker derive --kdf pbkdf2 --password hunter2 --salt 0011223344556677 \
  --digest sha256 --iterations 10000 --length 48 --iv-length 16
```

### Create test containers

```bash
aesbreaker encrypt plain.txt -p hunter2 --format aescrypt -o test.aes
aesbreaker encrypt plain.txt -p hunter2 --format openssl-enc \
  --openssl-cipher aes-256-cbc --openssl-digest sha256 -o test.enc
aesbreaker encrypt plain.txt -p hunter2 --format zip-aes \
  --zip-strength 256 --zip-compression deflate -o test.zip
```

Generated files are verified against the real pyAesCrypt, OpenSSL, and 7-Zip
implementations by the test-suite and by `aesbreaker selftest`.

## Attack modes

### Wordlists

- Read in binary; candidates are raw bytes.
- Only one line terminator (`\n` or `\r\n`) is removed. **Spaces are preserved.**
- Blank lines are skipped unless `--include-empty` is used.
- `.gz`, `.bz2`, and `.xz` wordlists are detected automatically.
- `-w -` or `--stdin` reads candidates from stdin.
- A base64-encoded AES Crypt, WinZip AES, or OpenSSL `Salted__` container is
  detected and decoded automatically; use `--in-encoding base64` for raw AES.
- `--no-count` skips the preliminary line count (no percentage/ETA).

Candidates are bytes. AES Crypt v1/v2 hashes the password as UTF-16LE and
requires valid UTF-8; AES Crypt v3 hashes the UTF-8 password bytes. ZIP AES and
OpenSSL `enc` use the candidate bytes directly. Different ZIP/OpenSSL implementations disagree on
the encoding of non-ASCII passwords, so use `--password-hex` when byte-exact
input matters.

### Rules

Rule files contain one rule per line; blank lines and `#` comments are ignored.
Each rule is an independent transformation of the base word. Multiple rules can
be combined with repeated `--rule` / `--rules` options or a preset.

Built-in presets: `common` (42 rules), `leet` (19), `digits` (110), `years` (61).

| Syntax | Meaning |
|---|---|
| `:` | no-op |
| `l` `u` | ASCII lower / upper case |
| `c` `C` | capitalize / invert-capitalize |
| `t` | toggle case everywhere |
| `TN` | toggle case at index N |
| `r` `d` `f` | reverse / duplicate / reflect |
| `{` `}` | rotate left / right |
| `$X` `^X` | append / prepend X |
| `[` `]` `DN` `xNM` | delete first / last / at N; extract N,M |
| `iNX` `sXY` `@X` | insert, replace all, purge all |
| `pN` `zN` `ZN` `q` | repeat word, repeat edge byte, duplicate every byte |
| `k` `K` | swap first / last two bytes |
| `<N` `>N` `_N` | reject length ≥ N / > N / ≠ N |
| `!X` `(X` `)X` | reject if contains X / unless contains X / unless starts with X |

Character arguments accept `\xNN`, `\\`, `\n`, `\r`, and `\t`.

```bash
aesbreaker crack file.aes -w words.txt --rules rules/common.rule
aesbreaker crack file.aes -w words.txt --rules-preset leet
aesbreaker crack file.aes -w words.txt --rule 'c$1' --rule 'sa@se3'
```

### Masks

| Placeholder | Characters |
|---|---|
| `?l` / `?u` | a-z / A-Z |
| `?d` | 0-9 |
| `?s` | ASCII punctuation |
| `?a` | all 95 printable ASCII (includes space) |
| `?h` / `?H` | hex lower / upper |
| `?1`..`?4` | custom charset (`-1`..`-4`) |
| `??` | literal `?` |

```bash
# 8 characters: uppercase, 6 lowercase letters, 2 digits
aesbreaker crack file.aes --mask '?u?l?l?l?l?l?l?d?d'

# Custom charset
aesbreaker crack file.aes -1 '?l?d' --mask '?1?1?1?1'

# Increment keeps the leftmost mask positions: ?u?l, then ?u?l?l, ...
aesbreaker crack file.aes --mask '?u?l?l?l' --increment-min 2

# Character-set brute force
aesbreaker crack file.aes --charset 'abc123' --min-length 1 --max-length 6
```

### Hybrids and combinator

```bash
# word + two digits
aesbreaker crack file.aes -w words.txt --mask-append '?d?d'

# two digits + word
aesbreaker crack file.aes -w words.txt --mask-prepend '?d?d'

# word1+word2
aesbreaker crack file.aes -w first.txt --combinator second.txt --separator '-'
```

The second combinator wordlist is loaded into memory; use `--combinator-max`
to enforce a limit.

### Deduplication

`--dedupe` removes candidates by 128-bit BLAKE2b digest. It stops tracking after
`--dedupe-limit` unique candidates (default 5,000,000) and reports that the
total is an upper bound.

## Long attacks: checkpoints and time limits

Long PBKDF2/AES Crypt attacks can be stopped and resumed without re-testing
the whole keyspace:

```bash
aesbreaker crack backup.aes -w rockyou.txt \
  --checkpoint backup.progress.json --max-runtime 3600

# exit 124 after the time limit; resume later
aesbreaker crack backup.aes -w rockyou.txt --resume backup.progress.json
```

- `--max-runtime SECONDS` stops gracefully and exits **124**.
- `--checkpoint FILE` writes progress on time limit, Ctrl-C, exhaustion, or a
  hit.
- `--resume FILE` loads a compatible checkpoint and starts after the saved
  candidate position.
- A checkpoint is bound to a signature of the input, wordlist, rules, mask,
  cipher parameters, spec, and AES-Breaker version. Resuming with a changed
  wordlist or scheme is rejected.
- Checkpoints contain no password; they store candidate position, counters,
  timestamps, and plan metadata.
- A completed checkpoint cannot be resumed. An existing checkpoint is not
  overwritten without `--resume` or `--overwrite`.
- The checkpoint path cannot collide with an input, wordlist, rules/spec file,
  or the plaintext/JSON/password output.
- Progress is saved when the attack stops or completes, not continuously. A
  `SIGKILL` or power loss does not update the file; use `--max-runtime` or
  Ctrl-C for a clean checkpoint.

Full checkpoint format and resume rules: [docs/checkpointing.md](docs/checkpointing.md).

## Verification and confidence

AES-Breaker reports exactly what it knows:

- **confirmed** — a 256-bit HMAC (AES Crypt), a WinZip AES auth code, a GCM tag,
  or an exact known plaintext prefix of at least 8 bytes matched. Shorter
  prefixes are rejected by `crack`/`decrypt` because a 1-byte prefix is
  matched by 1/256 of random wrong keys; `infer` labels a short-prefix match
  as probable.
- **probable** — OpenSSL PKCS#7 padding is valid and the decrypted probe looks
  like text or a known file signature; with `-nopad`, only the text/magic
  heuristic exists. This is strong for long text but is not cryptographic
  proof.
- **weak** — a padding-valid OpenSSL candidate with no additional evidence, or
  a padding-less `-nopad` probe with no text/magic evidence. Weak matches are
  counted and hidden by default; `--policy any` turns the first padding-valid
  one into a probable result.

OpenSSL `--policy` values:

| Policy | Accepts |
|---|---|
| `auto` (default) | known prefix, strong file magic, or printable text after valid padding |
| `magic` | known prefix or strong file magic only |
| `text` | known prefix or printable text only |
| `strict` | known prefix only |
| `any` | first valid PKCS#7 padding; unconfirmed, never reported as confirmed (rejected for `-nopad`) |

For binary plaintext with no magic and no known prefix, use
`--known-prefix`/`--known-prefix-hex` for certainty or inspect the candidate
output manually. Prefix confirmation is exact for the bytes supplied; a
prefix shorter than one 16-byte block can be satisfied by more than one
mode/counter interpretation (for example CFB and CTR share
`AES(key, IV)` for the first block). Extend the prefix past one block to
disambiguate.

GCM in raw mode is always authenticated: a forged tag is rejected and no
plaintext is reported.

### A format-level caveat: AES Crypt `fs16`

AES Crypt v1/v2 does not cover the one-byte plaintext-length remainder
(`fs16`) with either HMAC. An attacker with write access can change the
recovered plaintext length by up to 15 bytes. The decrypted report shows
`fs16_authenticated: false` and whether the padding convention is consistent.
AES Crypt v3 uses authenticated PKCS#7 padding and is not affected; this is a
property of the legacy format, not of this implementation.

## Performance

Password recovery is bounded by the format's KDF, not by AES throughput.
Approximate measurements on an Intel i5-1235U (12 threads) with Python 3.14:

| Workload | Per process | 4 workers |
|---|---:|---:|
| AES Crypt v1/v2 (8192 SHA-256 rounds) | ~198/s | ~413/s |
| WinZip AES-256 (PBKDF2-SHA1/1000) | ~1,019/s | ~3,823/s |
| OpenSSL EVP_BytesToKey-MD5 CBC | ~60,700/s | ~123,000/s |
| OpenSSL PBKDF2-HMAC-MD5/5000 | ~283/s | — |

Tuning:

- `-j N` sets worker processes (default: CPU count; `1` = in-process serial).
- `--batch-size` default 256; larger batches reduce IPC overhead for fast
  verifiers.
- `--status-interval` controls progress updates.
- `--benchmark N` measures your actual machine/KDF before a long attack.
- `--dry-run` prints the keyspace and plan without cracking.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | success / password found / command completed |
| 1 | password not found, `infer`/`cribdrag` produced no candidates, or `selftest` failed |
| 2 | usage, input, format, or output error |
| 3 | verification/decryption failure, partial ZIP extraction error, or internal runtime failure |
| 124 | `--max-runtime` limit reached (checkpoint saved if `--checkpoint` was set) |
| 130 | interrupted (Ctrl-C) |

## JSON output

`--json` writes a single JSON object to stdout and keeps status lines on stderr.
`--json-out FILE` additionally writes it to a file (`-` is not accepted; use
`--json` for stdout).

```json
{
  "tool": "aesbreaker",
  "version": "2.0.0",
  "command": "crack",
  "input": "backup.zip.aes",
  "format": "aescrypt",
  "format_display": "AES Crypt",
  "verification": "HMAC-SHA256 (256-bit)",
  "found": true,
  "password": {
    "hex": "68756e74657232",
    "text": "hunter2",
    "display": "hunter2",
    "valid_utf8": true
  },
  "confidence": "confirmed",
  "attempts": 1248,
  "elapsed_seconds": 6.0,
  "rate_per_second": 208.0,
  "output": "backup.zip",
  "errors": []
}
```

## Self-test

```bash
aesbreaker selftest
aesbreaker selftest --json
aesbreaker selftest --no-process   # skip the multiprocessing check
```

The self-test embeds fixtures produced by the real pyAesCrypt, OpenSSL,
7-Zip, and AES Crypt (Rust reference) implementations, plus NIST AES
known-answer vectors. It also performs cross-checks against those tools when
they are installed. A clean install must report zero failures.

## Development

```bash
pip install -e '.[dev]'
pytest -q
ruff check aesbreaker tests
aesbreaker selftest
```

External tools used by optional interoperability tests: `openssl`, `7z`, and
the `pyAesCrypt` Python package. Tests skip cleanly when a tool is absent.

Project layout:

```text
aesbreaker/
  crypto.py          AES primitives and strict padding/counter handling
  kdf.py             EVP_BytesToKey, PBKDF2, AES Crypt stretching, HKDF
  formats/           byte-level container parsers and verifiers
    custom.py        explicit JSON-spec raw AES verifier
  checkpoint.py      signed attack progress state
  candidates.py      wordlist / rules / mask / combinator planning
  rules.py           hashcat-style rule engine
  masks.py           mask parsing and enumeration
  engine.py          multiprocessing verification engine
  commands/          one module per CLI command (incl. selftest.py)
docs/formats.md      wire-format notes and references
docs/checkpointing.md  checkpoint/resume state format
docs/custom-spec.schema.json
examples/            runnable custom spec template
completions/         bash/zsh completion
rules/               example rule files
tests/               unit, integration, and CLI tests
```

## Limitations

- This tool attacks **password-derived keys**; it does not break AES itself.
- No GPU acceleration. Throughput is dominated by PBKDF2/SHA-256 stretching.
- Supported formats are AES Crypt v1/v2/v3, OpenSSL `enc`, WinZip AES, and the
  explicit `--format custom` spec. 7-Zip native archives, RAR, KDBX, and
  similar formats are not implemented.
- ZipCrypto is legacy encryption, not AES, and is intentionally unsupported.
- The OpenSSL cipher, digest, PBKDF2 flag, and iteration count are not stored in
  the file. Nothing can recover them from the ciphertext alone.
- OpenSSL padding-valid candidates are probabilistic; use a known prefix when
  certainty matters.
- ZIP extraction has an 8 GiB default output limit (`--max-extract-size 0`
  disables it), refuses path traversal and symlink entries, and escapes control
  characters in terminal output. Like any path-based extractor it cannot
  protect against a local attacker who can modify the destination directory
  concurrently.
- The combinator's second wordlist is held in memory.
- A custom writer uses the same layout fields as the verifier. It does not
  invent a header or a salt/IV placement: set `ciphertext_offset` and
  embedded salt/IV offsets explicitly, and ensure ranges do not overlap.
- Base64-encoded AES Crypt, WinZip AES, and OpenSSL `Salted__` inputs are
  auto-detected and decoded; raw AES still uses its explicit `--in-encoding`.

## License

MIT. See [LICENSE](LICENSE).

[aescrypt format]: https://www.aescrypt.com/aes_file_format.html
[pycryptodome]: https://www.pycryptodome.org/
[WinZip AES]: https://www.winzip.com/en/support/aes-encryption/
