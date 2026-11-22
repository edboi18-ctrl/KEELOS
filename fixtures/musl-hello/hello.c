/* Phase 1 acceptance item 1: a C "hello world" statically linked against
 * musl, run as PID 1 on Keel. Uses stdio, so it exercises musl's startup
 * (auxv, TLS via arch_prctl, set_tid_address) and its stdout path
 * (ioctl(TIOCGWINSZ) to detect a terminal, then writev). */
#include <stdio.h>

int main(void)
{
    printf("Hello from musl on Keel\n");
    return 0;
}
