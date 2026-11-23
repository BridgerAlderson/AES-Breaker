#compdef aesbreaker

_arguments -C \
  '1:command:(crack decrypt inspect analyze derive cribdrag recover-iv infer encrypt selftest)' \
  '*::arg:->args'

case $state in
  args)
    case $words[1] in
      crack|decrypt|inspect)
        _arguments \
          '--format[container format]:format:(auto aescrypt openssl-enc zip-aes custom raw)' \
          '--spec[custom JSON spec]:file:_files' \
          '--password[password text]:password:' \
          '--password-file[password file]:file:_files' \
          '--known-prefix[known plaintext prefix]:text:' \
          '--json[write JSON]' \
          '--json-out[JSON output file]:file:_files' \
          '(-o --out)'{-o,--out}'[output path]:path:_files' \
          '--overwrite[replace existing output]' \
          '--help[show help]'
        ;;
      encrypt)
        _arguments \
          '--format[output format]:format:(aescrypt openssl-enc zip-aes)' \
          '--aescrypt-version[AES Crypt version]:version:(2 3)' \
          '--aescrypt-iterations[PBKDF2 iterations]:iterations:' \
          '--password[password text]:password:' \
          '--password-file[password file]:file:_files' \
          '(-o --out)'{-o,--out}'[output path]:path:_files' \
          '--overwrite[replace existing output]' \
          '--help[show help]'
        ;;
      selftest)
        _arguments '--json[write JSON]' '--no-process[skip multiprocess]' '--help[show help]'
        ;;
    esac
    ;;
esac
