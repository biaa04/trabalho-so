# Makefile para o projeto trabalho-so

# Compila o logger_attach.c
logger_attach: logger_attach.c
	gcc -o logger_attach logger_attach.c -ljson-c

# Limpa arquivos gerados
clean:
	rm -f logger_attach

.PHONY: clean
