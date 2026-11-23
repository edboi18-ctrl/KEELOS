/* Phase 3, P3-T2: a C "hello world" dynamically linked against musl. The
 * kernel loads it and its PT_INTERP, /lib/ld-musl-x86_64.so.1 (musl's
 * dynamic linker, which is also its libc); the dynamic linker relocates
 * itself and the program, binds printf, then runs main. Without the
 * interpreter the call to printf cannot be resolved and nothing prints. */
#include <stdio.h>

int main(void)
{
    printf("Hello from dynamically linked musl on Keel\n");
    return 0;
}
