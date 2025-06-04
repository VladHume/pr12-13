
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
    fprintf(log, "Register dump (x86_64):\n");
    fprintf(log, "RIP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rip);
    fprintf(log, "RSP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rsp);
    fprintf(log, "RBP: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rbp);
    fprintf(log, "RAX: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rax);
    fprintf(log, "RBX: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rbx);
    fprintf(log, "RCX: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rcx);
    fprintf(log, "RDX: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rdx);
    fprintf(log, "RSI: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rsi);
    fprintf(log, "RDI: 0x%llx\n", (unsigned long long)uc->uc_mcontext.mc_rdi);
#else
    fprintf(log, "Register dump not implemented for this architecture.\n");
#endif
}

void signal_handler(int sig, siginfo_t *si, void *context) {
    FILE *log = fopen("crash.log", "a");
    if (!log) {
        _exit(1);
    }

    time_t now = time(NULL);
    fprintf(log, "\n---- Crash caught at %s", ctime(&now));
    fprintf(log, "Signal %d (%s) received.\n", sig, strsignal(sig));

    dump_registers((ucontext_t *)context, log);
    fclose(log);
    _exit(1);
}

void setup_signal_handler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = signal_handler;
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, NULL); // segmentation fault
    sigaction(SIGFPE,  &sa, NULL); // floating point exception
    sigaction(SIGILL,  &sa, NULL); // illegal instruction
    sigaction(SIGBUS,  &sa, NULL); // bus error
}

int main() {
    setup_signal_handler();

    printf("Program will now crash intentionally.\n");
    int *ptr = NULL;
    *ptr = 42; // segmentation fault

    return 0;
}
