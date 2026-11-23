# Format notes

This document records the exact wire formats, key derivation, and verification
rules implemented by AES-Breaker. It is the reference for the parsers in
`aesbreaker/formats/`.

## AES Crypt v1/v2/v3

All three versions start with ASCII `AES` and use AES-256-CBC with a random
internal key. They differ in header, KDF, session HMAC, and payload trailer.

### Layout

Common prefix:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 3 | ASCII `AES` |
| 3 | 1 | version `0x01`, `0x02`, or `0x03` |
| 4 | 1 | reserved, `0x00` |

Then:

| Version | Header after the prefix | Trailer after ciphertext |
|---|---|---|
| v1 | `iv1` 16, `c_iv_key` 48, `hmac1` 32 | `fs16` 1, `hmac0` 32 |
| v2 | extensions, then same 96-byte session header | `fs16` 1, `hmac0` 32 |
| v3 | extensions, `iterations` 4 (BE), then same 96-byte session header | `hmac0` 32 |

Extensions are a sequence of `uint16be length` + bytes, terminated by a
zero-length entry (v2/v3 only). pyAesCrypt writes `CREATED_BY\0pyAesCrypt
<version>` and a 128-byte container extension.

`c_iv_key = AES-256-CBC(K, iv1)` over `iv0 ‖ intKey`; `hmac0 =
HMAC-SHA256(intKey, ciphertext)`.

### Key derivation

v1/v2 use ACKDF, not PBKDF2. With `P` = the password encoded as UTF-16LE:

```text
D = iv1 ‖ 0x00 * 16
repeat 8192 times:
    D = SHA-256(D ‖ P)
K = D
```

Candidates that are not valid UTF-8 are rejected; AES Crypt v1/v2 cannot have
been produced from them.

v3 uses PBKDF2-HMAC-SHA512 over the UTF-8 password bytes:

```text
K = PBKDF2-HMAC-SHA512(password_utf8, salt=iv1, iterations, 32)
```

The iteration count is stored in the v3 header and bounded to 1..5,000,000
before any password-dependent work.

### Verification and decryption

```text
K = derive(password, version)
session_data = c_iv_key + (b"\x03" if version == 3 else b"")
if not constant_time_equal(HMAC-SHA256(K, session_data), hmac1):
    reject
iv_key = AES-256-CBC-decrypt(K, iv1, c_iv_key)
iv0, intKey = iv_key[:16], iv_key[16:48]
if not constant_time_equal(HMAC-SHA256(intKey, ciphertext), hmac0):
    corrupt
plaintext = AES-256-CBC-decrypt(intKey, iv0, ciphertext)
```

For v1/v2, truncate the final block using `fs16` (0 means 16). For v3, remove
authenticated PKCS#7 padding.

`hmac1` is the password oracle used by the cracking engine. It covers only 48
bytes plus the v3 version byte, so candidate verification does not touch the
payload. The payload MAC is verified before any plaintext is written.

v1/v2 do **not** authenticate `fs16`; a modified `fs16` can change the
reported plaintext length by up to 15 bytes while both HMACs verify. The
decrypt report includes `fs16_authenticated: false` and
`padding_consistent: true/false`. v3 authenticates the PKCS#7 padding inside
the ciphertext.

References: <https://www.aescrypt.com/aes_file_format.html>,
<https://github.com/marcobellaccini/pyAesCrypt>,
<https://github.com/Slurp9187/aescrypt-rs>.

## OpenSSL `enc`

### Layout

Salted file:

```text
"Salted__" (8 bytes: 53 61 6c 74 65 64 5f 5f)
salt (8 bytes)
ciphertext
```

With `-nosalt`, the header is omitted and the salt is empty. With `-a`, the
whole structure is base64 encoded; AES-Breaker accepts raw or base64 input.

### Key derivation

The cipher and KDF parameters are **not stored in the file.**

Legacy EVP (the default before OpenSSL 3, still used by `-md` without
`-pbkdf2`):

```text
D[-1] = empty
D[i]  = HASH(D[i-1] ‖ password ‖ salt)
key   = (D[0] ‖ D[1] ‖ ...)[:key_len]
iv    = (D[0] ‖ D[1] ‖ ...)[key_len:key_len+iv_len]
```

PBKDF2 (`-pbkdf2`):

```text
key ‖ iv = PBKDF2-HMAC(digest, password, salt, iterations, key_len + iv_len)
```

Digests: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512. OpenSSL 3 defaults to
SHA-256; OpenSSL 1.1 defaults to MD5. AES-Breaker defaults to SHA-256 and
requires the cipher to be supplied.

### Modes and counters

| Mode | Key lengths | IV | Padding |
|---|---|---|---|
| CBC | 16/24/32 | 16 | PKCS#7, or none with `-nopad` |
| ECB | 16/24/32 | none | PKCS#7, or none with `-nopad` |
| CTR | 16/24/32 | 16 | none |
| CFB128 | 16/24/32 | 16 | none |
| CFB8 | 16/24/32 | 16 | none |
| CFB1 | 16/24/32 | 16 | none (bit-oriented; slow) |
| OFB | 16/24/32 | 16 | none |

CTR uses the derived IV as a full 128-bit big-endian counter:

```text
keystream[i] = AES-encrypt(key, (int.from_bytes(iv, "big") + i) mod 2^128)
```

### Verification

`openssl enc` has no MAC or AEAD tag. AES-Breaker therefore performs:

1. a cheap decryption of the final block and strict PKCS#7 validation;
2. if a known plaintext prefix was supplied, exact comparison;
3. otherwise, a probe of the first 64 bytes scored for strong file magic or
   printable UTF-8 text.

A random wrong key passes the padding check with probability
`sum(256^-k for k=1..16) ≈ 1/256`. It also has to look like text or match a
known signature to be reported as probable. This is why `--policy strict`
requires a prefix and why a bare padding match is labelled `weak`, not found.

For CTR/CFB1/CFB8/CFB128/OFB there is no padding at all, so cracking is refused unless a
known prefix is supplied. A prefix must be at least 8 bytes before
`crack`/`decrypt` will treat it as confirmation; shorter values are rejected
because a one-byte prefix is satisfied by 1/256 of random wrong keys.

With `-nopad`, the padding check is skipped. Without a prefix the only evidence
is the text/magic heuristic; `--policy any` is intentionally not allowed to
turn a padding-less candidate into a hit.

## WinZip AES (AE-1 / AE-2)

### ZIP structures used

- End of central directory (`PK\x05\x06`), including Zip64 locator/record when
  the classic fields are saturated.
- Central directory entries (`PK\x01\x02`) with filename, extra fields, sizes,
  flags, and local-header offset.
- Local file headers (`PK\x03\x04`) whose name/extra lengths locate the entry
  data.
- Prepended self-extractor stubs: if the recorded central-directory offset does
  not point at `PK\x01\x02`, the actual directory is found from the EOCD
  position and the delta is applied to local offsets.

WinZip AES entries use compression method `99` and the extra field `0x9901`:

| Field | Size |
|---|---:|
| header id `0x9901` | 2 |
| data size `7` | 2 |
| AES version (1 or 2) | 2 |
| vendor `AE` | 2 |
| strength (1/2/3) | 1 |
| actual compression method | 2 |

Strength maps to AES-128 (8-byte salt), AES-192 (12-byte salt), or AES-256
(16-byte salt).

### Entry data

```text
salt (8/12/16)
password verification value (2)
ciphertext (compressed plaintext, AES-CTR)
authentication code (10 bytes, HMAC-SHA1 truncated)
```

### Key derivation

```text
material = PBKDF2-HMAC-SHA1(password, salt, 1000, 2*key_len + 2)
key       = material[:key_len]
auth_key  = material[key_len:2*key_len]
pwd_verify= material[2*key_len:]
```

The 2-byte verification value is only a prefilter (1/65536). The 10-byte
auth code is the actual proof:

```text
HMAC-SHA1(auth_key, ciphertext)[:10] == auth_code
```

### CTR

WinZip AES uses a 16-byte little-endian counter starting at 1:

```text
keystream[i] = AES-encrypt(key, (i + 1).to_bytes(16, "little"))
```

### AE-1 vs AE-2

Both use the same cryptography. AE-2 sets the CRC field to zero and relies on
the auth code. AE-1 may carry a CRC-32; AES-Breaker verifies it when it is
non-zero. Extraction supports stored (0), deflate (8), and bzip2 (12)
compression methods; LZMA (14) and zstd (93) are reported as unsupported.

### Extraction safety

- Member names are normalized; absolute paths, drive letters, `..`, NUL bytes,
  and reserved Windows device names are rejected.
- Existing symlink components and symlink entries are refused.
- Files are written through temporary files and atomically replaced.
- The default total output limit is 8 GiB (`--max-extract-size 0` disables it).

## Custom / headerless AES (JSON spec)

The `custom` format is not a container format: it is an explicit description of
one password-based AES scheme. AES-Breaker does not guess a missing field.
Parameters are taken from a JSON file passed with `--spec`; the input blob can
be raw, hex, or base64. The version-1 JSON Schema is
[`docs/custom-spec.schema.json`](custom-spec.schema.json); a runnable template
is [`examples/custom-spec.json`](../examples/custom-spec.json).

### Writing a custom blob

`aesbreaker encrypt --format custom --spec spec.json` uses the same schema.
Embedded salt/IV fields are generated randomly at their offsets; explicit,
zero, and derived IVs follow the spec. The ciphertext starts at
`ciphertext_offset`; gaps are zero-filled. GCM requires
`oracle.tag_offset`/`tag_length` so the generated tag can be placed. The writer
does not use `input_encoding` or a plaintext-prefix oracle, and it rejects
overlapping ranges.

### Schema, version 1

```json
{
  "version": 1,
  "cipher": "aes-256-cbc",
  "input_encoding": "base64",
  "ciphertext_offset": 32,
  "ciphertext_length": null,
  "ctr_little_endian": false,
  "kdf": {
    "type": "pbkdf2",
    "digest": "sha256",
    "iterations": 200000,
    "salt_hex": "00112233445566778899aabbccddeeff",
    "password_encoding": "raw"
  },
  "iv": {"source": "embedded", "offset": 16, "length": 16},
  "padding": "pkcs7",
  "oracle": {"type": "known_prefix", "hex": "7b2276657273696f6e223a"},
  "allow_heuristic": false
}
```

Unknown keys are rejected, so a typo cannot silently change the scheme.

### Fields

| Field | Meaning |
|---|---|
| `cipher` | `aes-128/192/256-{cbc,ecb,ctr,cfb,cfb1,cfb8,ofb,gcm}` |
| `input_encoding` | `raw`, `hex`, or `base64` (default `base64`) |
| `ciphertext_offset` | Byte offset of ciphertext in the decoded payload (default 0) |
| `ciphertext_length` | Optional ciphertext length; default: rest of payload |
| `ctr_little_endian` | CTR only; `false` = OpenSSL-style big-endian 128-bit counter |
| `kdf.type` | `pbkdf2`, `evp`, `scrypt`, `hkdf`, or `argon2` |
| `kdf.digest` | `md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512` |
| `kdf.iterations` | PBKDF2 only; required/positive; default 10000 |
| `kdf.n`/`r`/`p` | scrypt only; N must be a power of two and `128*N*r <= 1 GiB` |
| `kdf.info_hex` | HKDF info bytes (optional) |
| `kdf.time_cost`/`memory_cost`/`parallelism` | Argon2id parameters (defaults 3/65536/4) |
| `kdf.salt_hex` | Salt bytes; mutually exclusive with `salt_offset`/`salt_length` |
| `kdf.salt_offset`/`salt_length` | Read the salt from the decoded payload |
| `kdf.password_encoding` | `raw` (default), `utf-8`, `utf-16-le`, `utf-16-be` |
| `iv.source` | `explicit`, `embedded`, `zero`, or `derived` |
| `iv.hex` | Explicit IV/nonce |
| `iv.offset`/`iv.length` | Embedded IV/nonce in the decoded payload |
| `padding` | `pkcs7` for CBC/ECB; `none` for stream/GCM modes |
| `oracle` | Required real checker; see below |
| `allow_heuristic` | Permit no-oracle text/magic checking; false by default |

Offsets are always into the **decoded** payload, not into the base64 text.

### Key derivation and IV

PBKDF2, scrypt, HKDF, and Argon2id derive `key_len` bytes, plus the IV length
when `iv.source` is `derived`; the key is the first `key_len` bytes and the IV
is the remainder. `EVP_BytesToKey` is called with the key and IV lengths in the
same way and uses one iteration. For `explicit`, `zero`, and `embedded`, the
KDF output is only the key.

scrypt uses `hashlib.scrypt(password, salt, n, r, p, dklen)`; HKDF uses
RFC 5869 with the password as IKM; Argon2id uses `argon2.low_level`
(optional dependency). HKDF is not a password-hardening KDF; use PBKDF2,
scrypt, or Argon2 for password-derived keys.

CBC, CTR, CFB, and OFB use a 16-byte IV. GCM uses a nonce of 1–64 bytes (12 by default
for `derived`/`zero`); `explicit`/`embedded` lengths come from the supplied
value. ECB rejects `iv` entirely.

### Oracles and confidence

| `oracle.type` | Fields | Applies to | Result |
|---|---|---|---|
| `known_prefix` | `hex` (≥8 bytes) | CBC/ECB/CTR/CFB/OFB | exact prefix match = confirmed |
| `known_block` | `hex` (exactly 16 bytes), `offset` (multiple of 16) | CBC/ECB | exact block match = confirmed |
| `gcm_tag` | `tag_hex`, or `tag_offset`/`tag_length` (8–16 bytes); optional `aad_hex` | GCM | tag verification = confirmed |

The prefix is at plaintext offset 0. The known block is at a fixed plaintext
offset; for CBC, verifying block *N* needs only `C_N`, `C_{N-1}`, and the key,
so it is cheap even for large files. GCM is tag-only; a plaintext prefix is
rejected as a GCM oracle because it would be weaker than the format provides.

With no oracle and `allow_heuristic: true`, CBC/ECB additionally require valid
PKCS#7 padding and text/magic evidence; CTR only text/magic. Such candidates
are `probable` at best, and padding-only candidates are `weak`. A spec with no
oracle and `allow_heuristic: false` is rejected.

### Ciphertext and tag offsets

For GCM, the tag can be appended (other fields omitted for brevity):

```json
{
  "cipher": "aes-256-gcm",
  "input_encoding": "raw",
  "ciphertext_offset": 12,
  "ciphertext_length": 128,
  "iv": {"source": "embedded", "offset": 0, "length": 12},
  "oracle": {"type": "gcm_tag", "tag_offset": 140, "tag_length": 16}
}
```

If `ciphertext_length` is omitted and `tag_offset` is given,
ciphertext length defaults to `tag_offset - ciphertext_offset`. The tag range
must not overlap the ciphertext range.

## Raw AES

Raw decryption requires every parameter explicitly:

- key: exactly 16/24/32 bytes, via `--key`, `--key-text`, or `--key-file`;
- CBC/CFB/OFB/CTR: 16-byte IV (the initial counter for CTR);
- GCM: nonce, tag, optional AAD;
- padding: `pkcs7` or `none`, never guessed.

GCM tags are verified with `decrypt_and_verify`; a failed tag produces no
reported plaintext. CTR supports full-width big-endian (OpenSSL style) and
little-endian (WinZip style) counters.

A known-plaintext prefix only proves the bytes it covers. A prefix shorter
than one AES block cannot distinguish CFB from CTR, nor CTR's two counter
endiannesses, because all of them use `AES(key, IV)` for the first block.
`infer` reports every interpretation that satisfies the prefix and ranks them;
use a prefix of at least 17 bytes when the distinction matters.

## References

- AES Crypt file format: <https://www.aescrypt.com/aes_file_format.html>
- pyAesCrypt: <https://github.com/marcobellaccini/pyAesCrypt>
- OpenSSL `enc` and `EVP_BytesToKey`
- WinZip AES encryption specification
- APPNOTE.TXT (ZIP file format)
- NIST SP 800-38A (block cipher modes), NIST GCM test vectors
- RFC 5869 (HKDF), RFC 6070 (PBKDF2-HMAC-SHA1)
