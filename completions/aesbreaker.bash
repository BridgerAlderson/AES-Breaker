# Bash completion for AES-Breaker.
_aesbreaker() {
    local cur prev words cword
    _init_completion || return
    local commands="crack decrypt inspect analyze derive cribdrag recover-iv infer encrypt selftest"
    local formats="auto aescrypt openssl-enc zip-aes custom raw"
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$commands --help --version" -- "$cur") )
        return
    fi
    case "${words[1]}" in
        decrypt|inspect|crack)
            COMPREPLY=( $(compgen -W "--format --spec --password --password-hex --password-file --known-prefix --known-prefix-hex --openssl-cipher --openssl-digest --openssl-pbkdf2 --openssl-iterations --openssl-nosalt --openssl-nopad --entry --json --json-out -o --out --overwrite --help" -- "$cur") )
            if [[ $prev == "--format" ]]; then
                COMPREPLY=( $(compgen -W "$formats" -- "$cur") )
            fi
            ;;
        encrypt)
            COMPREPLY=( $(compgen -W "--format --aescrypt-version --aescrypt-iterations --openssl-cipher --openssl-digest --openssl-pbkdf2 --openssl-iterations --openssl-nosalt --openssl-nopad --zip-strength --zip-compression --entry-name --password --password-hex --password-file -o --out --overwrite --json --json-out --help" -- "$cur") )
            ;;
        selftest)
            COMPREPLY=( $(compgen -W "--json --no-process --help" -- "$cur") )
            ;;
        *)
            COMPREPLY=( $(compgen -W "--help" -- "$cur") )
            ;;
    esac
}
complete -F _aesbreaker aesbreaker
