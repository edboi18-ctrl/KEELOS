/* P3-T7: a program linked against libkeelgreet.so. It prints the
 * library's string (read through a mapped text and rodata segment) and
 * a count kept in the library's data segment (written after mapping). */
#include <stdio.h>

const char *keel_greeting(void);
int keel_bump(void);

int main(void)
{
    keel_bump();
    keel_bump();
    printf("%s (count %d)\n", keel_greeting(), keel_bump());
    return 0;
}
