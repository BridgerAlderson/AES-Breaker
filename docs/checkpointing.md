# Checkpoints and time limits

A checkpoint is a JSON state file for a long `crack` run. It records a
deterministic candidate-stream position and enough identity metadata to reject
an incompatible resume.

## Usage

```bash
# Stop after one hour, saving state.
aesbreaker crack backup.aes -w rockyou.txt \
  --checkpoint backup.progress.json --max-runtime 3600

# Continue from the saved position.
aesbreaker crack backup.aes -w rockyou.txt --resume backup.progress.json
```

If both `--checkpoint` and `--resume` are supplied, the resume file is read and
the checkpoint file is updated.

## State format, version 1

```json
{
  "tool": "aesbreaker",
  "version": "2.0.0",
  "checkpoint_version": 1,
  "created": "2026-11-23T09:15:02+00:00",
  "updated": "2026-11-23T10:15:02+00:00",
  "signature": "...64 hex characters...",
  "attempts": 124800,
  "weak_candidates": 12,
  "elapsed_seconds": 3600.4,
  "completed": false,
  "found": false,
  "interrupted": false,
  "time_limit_reached": true,
  "exhausted": false,
  "errors": [],
  "resumed_from": 0,
  "input": "backup.aes",
  "format": "aescrypt",
  "plan": { "kind": "wordlist", "total": 14344392 }
}
```

The file never contains a password. It is written atomically; on POSIX the
mode is 0600, while Windows inherits the destination directory ACL.

## Resume rules

The resume position is applied **after** rules, hybrid masks, and
deduplication, so the same candidate stream is reproduced. The signature covers:

- container path and SHA-256;
- format and format-specific options;
- verifier description (cipher, KDF, entry, custom spec);
- candidate plan summary (wordlist path/count, mask, rules count, dedupe);
- wordlist/combinator/rules/spec file size and mtime;
- inline rules and rule preset names;
- policy and known prefix;
- AES-Breaker version.

Any change is rejected with exit code 2 before verification starts.

## Completion and exit codes

| Situation | Checkpoint `completed` | Exit |
|---|---|---:|
| Password found | true | 0 (or 3 for a partial extraction error) |
| Candidate plan exhausted | true | 1 |
| `--max-runtime` reached | false | 124 |
| Ctrl-C | false | 130 |
| Verifier/worker error | false | 3 |
| Incompatible or completed resume | unchanged | 2 |

A completed checkpoint cannot be resumed. An existing checkpoint is not
overwritten unless `--resume` targets it or `--overwrite` is supplied.

## Limits

- Progress is flushed when the attack stops or completes, not on a timer.
  `SIGKILL`, a crash, or power loss does not update the checkpoint. Use
  `--max-runtime` or Ctrl-C for a clean save.
- Candidate-source identity uses size and `mtime_ns` for large wordlists. If a
  file is modified while preserving both, the signature may not detect it.
- Resuming a `stdin` plan requires the same input stream to be supplied again.
- Checkpointing is not available with `--dry-run` or `--benchmark`.
