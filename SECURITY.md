# Security policy

## Supported versions

Only the current 2.0.x line receives security fixes.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could affect users.
Use GitHub's private vulnerability reporting on the repository Security tab.
If that is unavailable, open a minimal public issue asking for a private
channel; do not include exploit details. Include:

- affected version and command;
- a minimal reproducer or malformed file if safe to share;
- impact and whether plaintext, key material, or output files are exposed.

You will receive an acknowledgement and a remediation timeline. Please allow
time for a fix before public disclosure.

## Scope notes

- AES-Breaker is an offline password-recovery tool. It does not attack AES
  itself.
- OpenSSL `enc` has no MAC; results without a known prefix are explicitly
  probabilistic.
- AES Crypt v1/v2 `fs16` and the ciphertext length are not authenticated by the
  legacy format; v3 PKCS#7 is authenticated.
- `-p/--password` and `--password-hex` are visible in process arguments; prefer
  the prompt or `--password-file`.
