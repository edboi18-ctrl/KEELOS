/* P3-T4: POSIX threads on musl (Phase 3 acceptance item 2, threads part).
 * Four workers share a counter under a mutex (futex contention), wait on a
 * condition variable until released together, keep a thread-local value
 * (CLONE_SETTLS), and report their own TID; the main thread joins them
 * (CLONE_CHILD_CLEARTID and the futex wake). Then two more threads are
 * left behind, one waiting for ever on a condition variable and one
 * spinning in user mode, and main returns: exit_group must end both.
 * Before that, a raw clone with CLONE_CHILD_CLEARTID checks the kernel's
 * part of thread exit directly (musl's pthread_join does not rely on it):
 * the TID word is cleared and a futex waiter on it is woken. */
#define _GNU_SOURCE /* syscall() and SYS_gettid */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define WORKERS 4
#define ROUNDS 10000

static __thread long tls_value;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t go = PTHREAD_COND_INITIALIZER;
static pthread_cond_t never = PTHREAD_COND_INITIALIZER;
static long counter;
static int released;

static void *worker(void *arg)
{
    long id = (long)arg;
    tls_value = id;
    for (int i = 0; i < ROUNDS; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
    }
    pthread_mutex_lock(&lock);
    while (!released)
        pthread_cond_wait(&go, &lock);
    pthread_mutex_unlock(&lock);
    if (tls_value != id || syscall(SYS_gettid) == getpid())
        return (void *)-1L;
    return (void *)(id * 10);
}

/* include/uapi/linux/futex.h (no kernel headers in this image). */
#define FUTEX_WAIT 0

static int tid_word;
static char clone_stack[4096] __attribute__((aligned(16)));

/* A thread from the raw clone system call (musl's clone() refuses
 * CLONE_THREAD and CLONE_CHILD_CLEARTID). The child runs only the
 * instructions below: it spins, then exits, and never touches a stack, so
 * it cannot disturb the C frames it shares the memory with.
 *
 * Assembly reasoning (spec section 1, rule 4)
 * Entry: RAX = 56 (clone, arch/x86/entry/syscalls/syscall_64.tbl), RDI =
 *   flags, RSI = new stack (only RSP changes in the child), RDX =
 *   parent_tid, R10 = child_tid, R8 = tls (unused: no CLONE_SETTLS). The
 *   x86-64 order is flags, stack, parent_tid, child_tid, tls
 *   (kernel/fork.c, no CLONE_BACKWARDS on x86-64); arguments go in RDI,
 *   RSI, RDX, R10, R8, R9 and the result comes back in RAX (Linux
 *   arch/x86/entry/entry_64.S, "Registers on entry").
 * SYSCALL overwrites RCX (return RIP) and R11 (RFLAGS) (SDM Vol. 2B,
 *   "SYSCALL"), so both are clobbered; the kernel preserves the rest.
 * Parent: RAX = the child's TID (> 0) or -errno; `jnz 1f` (RAX != 0) goes
 *   straight to the end.
 * Child: RAX = 0. `mov rcx, 20000000; 2: dec rcx; jnz 2b` counts down
 *   (DEC sets ZF at 0, SDM Vol. 2A "DEC"), then exit(0) (RAX = 60, RDI =
 *   0) ends the thread: the kernel clears child_tid and wakes a waiter.
 *   `ud2` (#UD, never reached) stops it if exit ever returned. */
static long raw_thread(unsigned long flags, int *child_tid)
{
    long ret;
    register long r10 __asm__("r10") = (long)child_tid;
    register long r8 __asm__("r8") = 0;
    __asm__ volatile("syscall\n\t"
                     "test %%rax, %%rax\n\t"
                     "jnz 1f\n\t"
                     "mov $20000000, %%rcx\n"
                     "2:\n\t"
                     "dec %%rcx\n\t"
                     "jnz 2b\n\t"
                     "mov $60, %%eax\n\t"
                     "xor %%edi, %%edi\n\t"
                     "syscall\n\t"
                     "ud2\n"
                     "1:"
                     : "=a"(ret)
                     : "a"(56L), "D"(flags), "S"(clone_stack + sizeof clone_stack),
                       "d"(child_tid), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return ret;
}

/* 0 if the kernel cleared the TID word at the thread's exit and woke the
 * waiter; else why not. */
static int cleartid_wakes(void)
{
    long tid = raw_thread(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
                              CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID,
                          &tid_word);
    if (tid <= 0)
        return 10;
    int value;
    while ((value = __atomic_load_n(&tid_word, __ATOMIC_SEQ_CST)) != 0) {
        struct timespec two_seconds = {2, 0};
        long r = syscall(SYS_futex, &tid_word, FUTEX_WAIT, value, &two_seconds, NULL, 0);
        if (r == -1 && errno == ETIMEDOUT)
            return __atomic_load_n(&tid_word, __ATOMIC_SEQ_CST) == 0 ? 11 : 12;
    }
    return 0;
}

static void *waits_for_ever(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&lock);
    for (;;)
        pthread_cond_wait(&never, &lock);
}

static void *spins(void *arg)
{
    (void)arg;
    for (volatile unsigned long n = 0;; n++) {
    }
}

int main(void)
{
    pthread_t threads[WORKERS];
    tls_value = 99;
    for (long i = 0; i < WORKERS; i++)
        if (pthread_create(&threads[i], NULL, worker, (void *)(i + 1)))
            return 1;
    pthread_mutex_lock(&lock);
    released = 1;
    pthread_cond_broadcast(&go);
    pthread_mutex_unlock(&lock);
    long sum = 0;
    for (int i = 0; i < WORKERS; i++) {
        void *result;
        if (pthread_join(threads[i], &result))
            return 2;
        sum += (long)result;
    }
    if (counter != WORKERS * ROUNDS || sum != 100 || tls_value != 99)
        return 3;
    if (cleartid_wakes())
        return 5;
    printf("threads: %d workers, counter %ld, results %ld, thread-local values kept\n",
           WORKERS, counter, sum);
    fflush(stdout);
    pthread_t stuck[2];
    if (pthread_create(&stuck[0], NULL, waits_for_ever, NULL) ||
        pthread_create(&stuck[1], NULL, spins, NULL))
        return 4;
    return 0; /* exit_group: both must end */
}
