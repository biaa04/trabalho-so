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
#include <json-c/json.h>
#include <fcntl.h>
#include <sys/mman.h>

// Tabela de nomes de algumas syscalls indexada por seus números (orig_rax)
const char *syscall_names[450] = {
    [0] = "read", [1] = "write", [2] = "open", [3] = "close",
    [4] = "stat", [5] = "fstat", [6] = "lstat", [7] = "poll", [44] = "sendto", [45] = "recvfrom",
    [47] = "recvmsg", [49] = "bind", [51] = "getsockname",
    [54] = "ioctl", [63] = "uname", [230] = "clock_nanosleep",[8] = "lseek",
    [9] = "mmap", [10] = "mprotect", [11] = "munmap", [12] = "brk",
    [13] = "rt_sigaction", [14] = "rt_sigprocmask", [16] = "ioctl",
    [17] = "pread64", [18] = "pwrite64", [19] = "readv", [20] = "writev",
    [21] = "access", [22] = "pipe", [23] = "select", [24] = "sched_yield",
    [29] = "pause", [32] = "dup", [33] = "dup2", [34] = "getpid",
    [39] = "fork", [40] = "vfork", [41] = "execve", [42] = "exit",
    [57] = "fork", [59] = "execve", [60] = "exit", [61] = "wait4",
    [62] = "kill", [72] = "fcntl", [74] = "fsync", [78] = "getcwd",
    [79] = "chdir", [80] = "fchdir", [82] = "rename", [83] = "mkdir",
    [84] = "rmdir", [85] = "creat", [86] = "link", [87] = "unlink",
    [88] = "symlink", [89] = "readlink", [90] = "chmod", [91] = "fchmod",
    [92] = "chown", [93] = "fchown", [94] = "lchown", [95] = "umask",
    [96] = "gettimeofday", [97] = "getrlimit", [102] = "getuid",
    [104] = "getgid", [107] = "geteuid", [108] = "getegid",
    [158] = "arch_prctl", [160] = "uname", [202] = "time",
    [218] = "clock_gettime", [228] = "clock_nanosleep",
    [231] = "exit_group", [257] = "openat", [258] = "mkdirat",
    [262] = "newfstatat", [263] = "unlinkat", [264] = "renameat",
    [265] = "linkat", [266] = "symlinkat", [267] = "readlinkat",
    [268] = "fchmodat", [269] = "faccessat", [270] = "pselect6",
    [280] = "utimensat", [281] = "epoll_pwait", [288] = "openat",
    [291] = "epoll_create1", [295] = "accept4", [296] = "signalfd4",
    [299] = "eventfd2", [302] = "pipe2", [319] = "memfd_create",
    [322] = "execveat", [322] = "execveat"
};

// Converte código de sinal para nome legível
const char *get_signal_name(long sig) {
    switch (sig) {
        case 1: return "SIGHUP";
        case 2: return "SIGINT";
        case 3: return "SIGQUIT";
        case 9: return "SIGKILL";
        case 11: return "SIGSEGV";
        case 15: return "SIGTERM";
        default: return "UNKNOWN";
    }
}

// Gera timestamp legível
void get_timestamp(char *buffer, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm_info = localtime(&ts.tv_sec);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// funcao principal que coleta os registradores, interpreta chamadas específicas e gera JSON
void log_syscall(pid_t pid, struct user_regs_struct *regs, int entering, FILE *json_file) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    // Obtém nome da syscall ou "unknown" se não encontrada
    const char *name = syscall_names[regs->orig_rax] ? syscall_names[regs->orig_rax] : "unknown";

    // Criação do objeto JSON
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "timestamp", json_object_new_string(timestamp));
    json_object_object_add(obj, "pid", json_object_new_int(pid));
    json_object_object_add(obj, "syscall", json_object_new_string(name));
    json_object_object_add(obj, "number", json_object_new_int64(regs->orig_rax));

    if (entering) {    // Se estamos entrando na syscall 
        printf("[%s] %s(", timestamp, name);

        struct json_object *args = json_object_new_object();
        
        // Tratamento especial para syscalls específicas
        if (regs->orig_rax == 62) { // kill
            printf("arg1=pid:%lld, arg2=sig:%lld (%s), arg3=%lld",
                   regs->rdi, regs->rsi, get_signal_name(regs->rsi), regs->rdx);
        } else if (regs->orig_rax == 257) { // openat
                        
            // Decodifica flags de abertura de arquivo
            printf("dfd=%lld, filename=%p, flags=0x%llx (", 
                   regs->rdi, (void*)regs->rsi, regs->rdx);
            
            // Converte flags numéricas para strings legíveis
            char flag_buffer[256] = "";
            if (regs->rdx & O_RDONLY) strcat(flag_buffer, "O_RDONLY|");
            if (regs->rdx & O_WRONLY) strcat(flag_buffer, "O_WRONLY|");
            if (regs->rdx & O_RDWR) strcat(flag_buffer, "O_RDWR|");
            if (regs->rdx & O_CREAT) strcat(flag_buffer, "O_CREAT|");
            if (regs->rdx & O_EXCL) strcat(flag_buffer, "O_EXCL|");
            if (regs->rdx & O_TRUNC) strcat(flag_buffer, "O_TRUNC|");
            if (regs->rdx & O_APPEND) strcat(flag_buffer, "O_APPEND|");
            if (regs->rdx & O_CLOEXEC) strcat(flag_buffer, "O_CLOEXEC|");
            
            if (regs->rdx & O_NOFOLLOW) strcat(flag_buffer, "O_NOFOLLOW|");
            if (regs->rdx & O_DIRECTORY) strcat(flag_buffer, "O_DIRECTORY|");
            if (regs->rdx & O_SYNC) strcat(flag_buffer, "O_SYNC|");

            if (strlen(flag_buffer) > 0)
                flag_buffer[strlen(flag_buffer) - 1] = '\0'; // Remove o último '|'

            printf("%s), mode=%llo", flag_buffer, regs->r10);

            // Adiciona ao JSON também
            json_object_object_add(obj, "flags_legivel", json_object_new_string(flag_buffer));
        } else if (regs->orig_rax == 9) { // mmap
            printf("addr=%p, length=%lld, prot=0x%llx, flags=0x%llx, fd=%lld, offset=%lld",
                   (void*)regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9);

            char prot_str[128] = "", flags_str[128] = "";
            
            // Decodifica flags prot e map (mmap usa dois conjuntos diferentes)
            if (regs->rdx & PROT_READ) strcat(prot_str, "PROT_READ|");
            if (regs->rdx & PROT_WRITE) strcat(prot_str, "PROT_WRITE|");
            if (regs->rdx & PROT_EXEC) strcat(prot_str, "PROT_EXEC|");
            if (regs->rdx & PROT_NONE) strcat(prot_str, "PROT_NONE|");
            if (strlen(prot_str) > 0) prot_str[strlen(prot_str) - 1] = '\0';

            if (regs->r10 & MAP_SHARED) strcat(flags_str, "MAP_SHARED|");
            if (regs->r10 & MAP_PRIVATE) strcat(flags_str, "MAP_PRIVATE|");
            if (regs->r10 & MAP_ANONYMOUS) strcat(flags_str, "MAP_ANONYMOUS|");
            if (strlen(flags_str) > 0) flags_str[strlen(flags_str) - 1] = '\0';

            json_object_object_add(obj, "prot_legivel", json_object_new_string(prot_str));
            json_object_object_add(obj, "map_flags_legivel", json_object_new_string(flags_str));
        } else { // Syscalls genéricas
            printf("arg1=%lld, arg2=%lld, arg3=%lld, arg4=%lld, arg5=%lld, arg6=%lld",
                   regs->rdi, regs->rsi, regs->rdx, regs->r10, regs->r8, regs->r9);
        }

        printf(")\n");
        
        // Adiciona argumentos genéricos no JSON
        json_object_object_add(obj, "tipo", json_object_new_string("enter"));
        json_object_object_add(args, "arg1", json_object_new_int64(regs->rdi));
        json_object_object_add(args, "arg2", json_object_new_int64(regs->rsi));
        json_object_object_add(args, "arg3", json_object_new_int64(regs->rdx));
        json_object_object_add(args, "arg4", json_object_new_int64(regs->r10));
        json_object_object_add(args, "arg5", json_object_new_int64(regs->r8));
        json_object_object_add(args, "arg6", json_object_new_int64(regs->r9));
        json_object_object_add(obj, "args", args);  
    } else {
        // Processando saída da syscall
        printf(" = %lld\n\n", regs->rax);

        json_object_object_add(obj, "tipo", json_object_new_string("exit"));
        json_object_object_add(obj, "retorno", json_object_new_int64(regs->rax));
    }
    
    // Escreve a linha JSON no arquivo e libera objeto
    fprintf(json_file, "%s\n", json_object_to_json_string(obj));
    fflush(json_file);
    json_object_put(obj);
}


int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <PID do processo a ser rastreado>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);  // Converte PID para inteiro

    // Abre o arquivo de log JSON
    FILE *json_file = fopen("syscalls_log.json", "a");
    if (!json_file) {
        perror("Erro ao abrir syscalls_log.json");
        return 1;
    }

    // Anexa ao processo alvo
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace(ATTACH)");
        fclose(json_file);
        return 1;
    }
    // Espera o processo parar
    waitpid(pid, NULL, 0);
    printf("Anexado com sucesso ao PID %d\n", pid);
    
    // Configura para rastrear syscalls
    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
        perror("ptrace(SYSCALL inicial)");
        fclose(json_file);
        return 1;
    }

    struct user_regs_struct regs;
    int entering = 1;
    
    // Loop de rastreamento contínuo
    while (1) {
        if (waitpid(pid, NULL, 0) == -1) break; // Espera evento

        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) break;// pega registros

        log_syscall(pid, &regs, entering, json_file);
        entering = !entering;

        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
    }
    // Limpeza final
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    fclose(json_file);
    printf("Desanexado do PID %d e log salvo em syscalls_log.json\n", pid);
    return 0;
}
