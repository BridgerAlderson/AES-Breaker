# Rule files

Each line is one independent rule applied to every base word. Blank lines and
lines beginning with `#` are ignored. Spaces are significant: `$ ` appends a
literal space. Character arguments accept `\xNN`, `\\`, `\n`, `\r`, and `\t`.

| Syntax | Meaning |
|---|---|
| `:` | no-op (identity) |
| `l` `u` | ASCII lower / upper case |
| `c` `C` | capitalize / invert-capitalize |
| `t` | toggle case everywhere |
| `TN` | toggle case at index N |
| `r` `d` `f` | reverse / duplicate / reflect |
| `{` `}` | rotate left / right |
| `$X` `^X` | append / prepend X |
| `[` `]` | delete first / last byte |
| `DN` | delete byte at index N |
| `xNM` | extract substring starting at N, length M |
| `iNX` | insert X at index N |
| `sXY` | replace every X with Y |
| `@X` | remove every X |
| `pN` | append the word N additional times |
| `zN` `ZN` | repeat the first / last byte N times at the front/back |
| `q` | duplicate every byte (`abc` -> `aabbcc`) |
| `k` `K` | swap the first / last two bytes |
| `<N` `>N` `_N` | reject if length >= N / > N / != N |
| `!X` `(X` `)X` | reject if contains X / unless contains X / unless starts with X |

Numeric positions in `T`, `D`, `x`, `i`, `p`, `z`, and `Z` are single decimal
digits. Length limits accept multi-digit numbers.

Usage:

```bash
aesbreaker crack file.aes -w words.txt --rules rules/common.rule
aesbreaker crack file.aes -w words.txt --rules rules/common.rule --rules rules/leet.rule
aesbreaker crack file.aes -w words.txt --rules-preset common
```

The bundled presets are also embedded in the program: `common`, `leet`,
`digits`, and `years`. The files here are starting points for editing.

Rules are applied to wordlist, stdin, and combinator candidates. They are not
applied to mask-only attacks; use a hybrid (`--mask-append`/`--mask-prepend`)
for that.
