# AES-Breaker | Dictionary Attack & Decryption Tool for AES Encrypted Data

AES-Breaker is a fast, multi-threaded AES decryption and bruteforce tool. It supports **direct text decryption** with automatic mode detection (GCM, CTR, CFB, CBC, ECB) and **file/blob dictionary attacks** for pyAesCrypt encrypted data. Designed for lab and recovery scenarios: recover lost passwords for files you own or for legally authorized engagements.

## Features

**Text Decryption Mode (NEW)**
- Direct AES decryption with `--decrypt` and `--key`
- Auto-detection of AES modes (GCM, CTR, CFB, CBC, ECB)
- Readability scoring for best result selection
- Dictionary attack support for encrypted text

**File/Blob Mode**
- Streaming wordlist reader (no need to load huge lists into memory)
- Multi-threaded worker pool for faster attempts
- Thread-safe atomic file handling to avoid corrupted/zero-byte outputs
- ZIP format validation and automatic extraction (`--zip`)
- Configurable progress reporting (`-v` and `--report-every`)

## Requirements

- Python 3.8+
- pyAesCrypt
- pycryptodome

```bash
pip install pyAesCrypt pycryptodome
```

## Usage
<img width="1789" height="672" alt="image" src="https://github.com/user-attachments/assets/6be49b21-f2fa-4105-8e0c-8a093e444e51" />

### Text Decryption Mode

**Direct decryption with known key:**
```bash
python3 AesBreaker.py --decrypt '<BASE64_ENCRYPTED_TEXT>' --key '<DECRYPTION_KEY>'
```

**Dictionary attack on encrypted text:**
```bash
python3 AesBreaker.py --decrypt '<BASE64_ENCRYPTED_TEXT>' --wordlist /path/to/wordlist.txt
```

### File Decryption Mode

**Basic file decryption:**
```bash
python3 AesBreaker.py -w /path/to/wordlist.txt encrypted_file.aes
```

**ZIP file decryption with extraction:**
```bash
python3 AesBreaker.py -w /path/to/wordlist.txt --zip encrypted_file.zip.aes
```

**Blob decryption:**
```bash
python3 AesBreaker.py -w /usr/share/wordlists/rockyou.txt --blob <DATA-BLOB>
```

## Options

| Option | Description |
|--------|-------------|
| `--decrypt`, `-d` | Encrypted text (Base64) for direct AES decryption |
| `--key`, `-k` | Decryption key for `--decrypt` mode |
| `-w`, `--wordlist` | Password wordlist file |
| `-t`, `--threads` | Number of worker processes (default: CPU count) |
| `-v`, `--verbose` | Increase verbosity (`-v` for progress, `-vv` for all attempts) |
| `--zip` | Validate and extract ZIP after decryption |
| `--blob` | Input is Base64-encoded data blob |
| `-o`, `--output-dir` | Output directory (default: `./decrypted`) |
| `--report-every` | Report progress every N attempts (default: 200) |
| `--temp-dir` | Directory for temp files |

## Examples

### Text Decryption with Key
```bash
python3 AesBreaker.py --decrypt 'encrypted-string' --key 'decrypt-key'
```

Output:
```
[*] Key: decrypt-key
[*] Encrypted Data (Base64): encrypted-string
[*] Encrypted Data Length: 11 bytes

--- ATTEMPT 1: AES GCM ---
[-] AES GCM failed: GCM (no tag)

--- ATTEMPT 2: AES CTR (Zero Counter) ---
[+] CTR Output: decrypted-string

==================================================
[BEST] Best result: AES CTR (Zero Counter) (CTR) - Score: 1.00
[BEST] Decrypted text: decrypted-string

[SUCCESS] Decryption completed!
```

### File Mode
```bash
python3 AesBreaker.py -w /usr/share/wordlists/rockyou.txt --zip data.zip.aes -v
```
### Blob Mode
```bash
python3 AesBreaker.py -w /usr/share/wordlists/rockyou.txt --blob <DATA-BLOB> -v
```
<img width="1907" height="472" alt="image" src="https://github.com/user-attachments/assets/92f72fc8-7b6a-463c-a114-6089af7739bf" />

### Double Verbose Mode
```bash
python3 AesBreaker.py -w /usr/share/wordlists/rockyou.txt --blob <DATA-BLOB> -vv
```
<img width="1899" height="884" alt="image" src="https://github.com/user-attachments/assets/421ae324-68b8-49b4-8289-c14b85dfbb16" />

## Supported AES Modes (Text Decryption)

| Mode | Description |
|------|-------------|
| GCM | Galois/Counter Mode (with tag verification) |
| CTR | Counter Mode (zero nonce) |
| CFB | Cipher Feedback Mode (zero IV) |
| CBC | Cipher Block Chaining (zero IV / embedded IV) |
| ECB | Electronic Codebook Mode |

## License

For educational and authorized use only.
