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

### Como compilar e executar

Você pode compilar manualmente ou usar o Makefile já incluso no projeto:

#### Usando o Makefile
```bash
make
sudo ./logger_attach <PID>
```

#### Compilação manual
```bash
gcc -o logger_attach logger_attach.c -ljson-c
sudo ./logger_attach <PID>
```

**Importante:**
- Substitua `<PID>` pelo número do processo que você deseja monitorar. Você pode descobrir o PID usando o comando `python3 processo.py`.
- O resultado será salvo no arquivo `syscalls_log.json` no mesmo diretório, além de ser exibido no terminal.
