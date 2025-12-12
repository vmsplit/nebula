/**
 * @file loader.c
 * @brief test loader for neb shellcode
 */


#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ucontext.h>


static void _fault(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = ctx;
    (void)sig;

    fprintf(stderr, "\nneb [loader]: fault @ %p\n", si->si_addr);
    fprintf(stderr, "neb [loader]: pc: %p\n", (void *) uc->uc_mcontext.pc);
    fprintf(stderr, "neb [loader]: sp: %p\n", (void *) uc->uc_mcontext.sp);

    for (int i = 0; i < 8; i++)
        fprintf(stderr, "neb [loader]: x%d: 0x%llx\n", i,
                (unsigned long long) uc->uc_mcontext.regs[i]);

    _exit(1);
}


int main(int argc, char **argv)
{
    const char *path = "bin/nebula.bin";
    struct stat st;
    void *mem;
    int fd;

    struct sigaction sa = {
        .sa_flags = SA_SIGINFO,
        .sa_sigaction = _fault,
    };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    if (argc > 1)
        path = argv[1];

    fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return 1;
    }

    fstat(fd, &st);

    mem = mmap(NULL, st.st_size,
               PROT_READ   | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS,
               -1, 0);

    if (mem == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    read(fd, mem, st.st_size);
    close(fd);

    ((void (*)(void *))mem)(NULL);

    return 0;
}
