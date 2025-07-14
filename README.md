# Syscall-Tracer

Um rastreador de chamadas de sistema (syscalls) feito em C que utiliza ptrace para interceptar as chamadas feitas por um processo em execução. Os dados são exportados em formato JSON e também exibidos no terminal com argumentos legíveis.

---

## Requisitos

- Linux
- Compilador C (gcc)
- Biblioteca [json-c](https://github.com/json-c/json-c)

### Instalação do json-c no Ubuntu/Debian:
```bash
sudo apt update
sudo apt install libjson-c-dev
```

### Como executar
```
    gcc -o logger_attacg logger_attach.c -ljson-c
    sudo ./logger_attarch <PID>
```

- O script tem como saida um arquivo json com as informações sobre o processo.
