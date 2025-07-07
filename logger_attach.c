#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <json-c/json.h> // Biblioteca para JSON

const char *syscall_names[450] = {
    [0] = "read",
    [1] = "write",
    [2] = "open",
    [3] = "close",
    [60] = "exit",
    [39] = "getpid",
    [62] = "kill",
    [57] = "fork",
    [59] = "execve",
    [257] = "openat",
    [9] = "mmap",
    [231] = "exit_group"
};

// Gera timestamp legível
void get_timestamp(char *buffer, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm_info = localtime(&ts.tv_sec);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Loga a syscall no terminal e no arquivo JSON
void log_syscall(pid_t pid, struct user_regs_struct *regs, int entering, FILE *json_file) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));

    const char *name = syscall_names[regs->orig_rax] ? syscall_names[regs->orig_rax] : "unknown";

    if (entering) {
        printf("[%s] PID %d -> [SYSCALL ENTER] %s (%lld)\n", timestamp, pid, name, regs->orig_rax);
        printf("    Args: rdi=%lld, rsi=%lld, rdx=%lld\n", regs->rdi, regs->rsi, regs->rdx);
    } else {
        printf("[%s] PID %d -> [SYSCALL EXIT]  %s => Retorno: %lld\n\n", timestamp, pid, name, regs->rax);
    }

    // Criar objeto JSON
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "timestamp", json_object_new_string(timestamp));
    json_object_object_add(obj, "pid", json_object_new_int(pid));
    json_object_object_add(obj, "syscall", json_object_new_string(name));
    json_object_object_add(obj, "number", json_object_new_int64(regs->orig_rax));

    if (entering) {
        json_object_object_add(obj, "tipo", json_object_new_string("enter"));
        struct json_object *args = json_object_new_object();
        json_object_object_add(args, "rdi", json_object_new_int64(regs->rdi));
        json_object_object_add(args, "rsi", json_object_new_int64(regs->rsi));
        json_object_object_add(args, "rdx", json_object_new_int64(regs->rdx));
        json_object_object_add(obj, "args", args);
    } else {
        json_object_object_add(obj, "tipo", json_object_new_string("exit"));
        json_object_object_add(obj, "retorno", json_object_new_int64(regs->rax));
    }

    // Escreve o JSON no arquivo (1 por linha)
    fprintf(json_file, "%s\n", json_object_to_json_string(obj));
    fflush(json_file); // Garante escrita imediata
    json_object_put(obj); // Libera memória
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <PID do processo a ser rastreado>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    // Abre o arquivo de log JSON (modo append)
    FILE *json_file = fopen("syscalls_log.json", "a");
    if (!json_file) {
        perror("Erro ao abrir syscalls_log.json");
        return 1;
    }

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace(ATTACH)");
        fclose(json_file);
        return 1;
    }

    waitpid(pid, NULL, 0);
    printf("Anexado com sucesso ao PID %d\n", pid);

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        perror("ptrace(SYSCALL inicial)");
        fclose(json_file);
        return 1;
    }

    struct user_regs_struct regs;
    int entering = 1;

    while (1) {
        if (waitpid(pid, NULL, 0) == -1) break;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) break;

        log_syscall(pid, &regs, entering, json_file);
        entering = !entering;

        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    fclose(json_file);
    printf("Desanexado do PID %d e log salvo em syscalls_log.json\n", pid);
    return 0;
}