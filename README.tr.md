# AES-Breaker — Türkçe hızlı başlangıç

AES Crypt v1/v2/v3, OpenSSL `enc`, WinZip AES ve açık JSON şemalı custom AES
dosyaları için çevrimdışı parola kurtarma ve çözme aracı.

Tam dokümantasyon İngilizce: [README.md](README.md), format detayları:
[docs/formats.md](docs/formats.md).

## Kurulum

```bash
pip install .
# geliştirme
pip install -e '.[dev]'
```

## Temel kullanım

```bash
aesbreaker selftest
aesbreaker inspect backup.aes
aesbreaker crack backup.aes -w rockyou.txt
aesbreaker decrypt backup.aes -p hunter2 -o backup.tar
aesbreaker crack archive.zip -w words.txt --rules-preset common -j 8
aesbreaker crack blob.b64 --format custom --spec spec.json -w words.txt
```

Uzun saldırılar:

```bash
aesbreaker crack backup.aes -w rockyou.txt \
  --checkpoint backup.progress.json --max-runtime 3600
aesbreaker crack backup.aes -w rockyou.txt --resume backup.progress.json
```

`--max-runtime` dolduğunda çıkış kodu 124'tür; Ctrl-C 130'dur. Checkpoint
parola içermez ve aynı input/wordlist/KDF/şema ile doğrulanır.

## Güvenlik notları

- `-p/--password` süreç argümanlarında ve shell geçmişinde görünür; mümkünse
  interaktif promptu veya `--password-file` kullanın.
- OpenSSL `enc` MAC içermez; bilinen önek olmadan sonuçlar `probable`/`weak`
  olarak etiketlenir.
- AES Crypt v1/v2 `fs16` alanı kimlik doğrulanmaz; v3 PKCS#7 kimlik doğrulanır.

## Lisans

MIT.
