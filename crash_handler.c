#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>
#include <time.h>

void dump_registers(ucontext_t *uc, FILE *log) {
#if defined(__x86_64__)
    fprintf(log, "RIP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RIP]);
    fprintf(log, "RSP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RSP]);
    fprintf(log, "RBP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RBP]);
    fprintf(log, "RAX: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RAX]);
    fprintf(log, "RBX: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RBX]);
    fprintf(log, "RCX: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RCX]);
    fprintf(log, "RDX: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RDX]);
    fprintf(log, "RSI: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RSI]);
    fprintf(log, "RDI: 0x%llx\n", (unsigned long long)uc->uc_mcontext.gregs[REG_RDI]);
#elif defined(__aarch64__)
    for (int i = 0; i < 31; i++) {
        fprintf(log, "X[%02d]: 0x%llx\n", i, uc->uc_mcontext.regs[i]);
    }
    fprintf(log, "SP: 0x%llx\n", uc->uc_mcontext.sp);
    fprintf(log, "PC: 0x%llx\n", uc->uc_mcontext.pc);
    fprintf(log, "PSTATE: 0x%llx\n", uc->uc_mcontext.pstate);
#else
    fprintf(log, "Architecture not supported for register dump.\n");
#endif
}

void signal_handler(int sig, siginfo_t *info, void *context) {
    FILE *log = fopen("crash.log", "a");
    if (!log) log = stderr;

    time_t now = time(NULL);
    fprintf(log, "\n\n==== CRASH DETECTED at %s====\n", ctime(&now));
    fprintf(log, "Signal: %d (%s)\n", sig, strsignal(sig));
    fprintf(log, "Fault address: %p\n", info->si_addr);

    ucontext_t *uc = (ucontext_t *)context;
    dump_registers(uc, log);

    if (log != stderr) fclose(log);
    _exit(1);  // безпечний вихід
}

void setup_crash_handler() {
    struct sigaction sa = {0};
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
}

int main() {
    setup_crash_handler();
    printf("Program started. PID: %d\n", getpid());

    // Штучно викликаємо SIGSEGV
    int *ptr = NULL;
    *ptr = 42;

    return 0;
}
