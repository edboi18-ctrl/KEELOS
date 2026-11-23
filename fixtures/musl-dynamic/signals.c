/* Signal delivery on musl (P3-T6, ADR 0020): the parts Wine relies on.
 * Wine turns CPU faults into Windows exceptions inside signal handlers,
 * reads and edits the saved context (registers and FPU state), and
 * returns through it; it uses an alternate stack and per-thread signals.
 *
 * Each check exits with its own status (and prints which) on failure, and
 * the program prints one line at the end. It must behave the same on
 * Linux and on Keel: `cargo xtask test` runs it on both.
 *
 * Context layout: musl's <signal.h> (arch/x86_64/bits/signal.h) gives
 * mcontext_t's gregs[] in the kernel's sigcontext order (REG_RIP 16,
 * REG_ERR 19, REG_TRAPNO 20, REG_CR2 22) and fpregs, a pointer to the
 * FXSAVE-format area (struct _fpstate: mxcsr at byte 24, _xmm[16] at
 * byte 160), as Linux's uapi sigcontext.h. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

static void fail(int code, const char *what)
{
	printf("signals: check %d failed: %s\n", code, what);
	fflush(stdout);
	_exit(code);
}

#define CHECK(code, cond) do { if (!(cond)) fail(code, #cond); } while (0)

static volatile sig_atomic_t usr1_count, usr2_count;
static volatile int usr1_code, usr1_pid, usr1_signo;
static volatile int nested_mask_ok;

static void on_usr1(int sig, siginfo_t *info, void *uc_)
{
	(void)uc_;
	usr1_signo = sig == SIGUSR1 && info->si_signo == SIGUSR1;
	usr1_code = info->si_code;
	usr1_pid = info->si_pid;
	sigset_t now;
	sigprocmask(SIG_BLOCK, NULL, &now);
	/* sa_mask (SIGUSR2) and the signal itself are blocked in here. */
	nested_mask_ok = sigismember(&now, SIGUSR1) && sigismember(&now, SIGUSR2);
	usr1_count++;
}

static void on_usr2(int sig)
{
	(void)sig;
	usr2_count++;
}

static void install(int sig, void (*fn)(int, siginfo_t *, void *), int flags, int masked)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = fn;
	sa.sa_flags = SA_SIGINFO | flags;
	sigemptyset(&sa.sa_mask);
	if (masked)
		sigaddset(&sa.sa_mask, masked);
	if (sigaction(sig, &sa, NULL) != 0)
		fail(90, "sigaction");
}

/* --- faults: the handler moves RIP past the faulting instruction --- */

extern char segv_resume[], ill_at[], ill_resume[];
static volatile uintptr_t segv_addr;
static volatile int segv_code;
static volatile long segv_trapno, segv_err, segv_cr2;
static volatile int ill_ok;

/* Assembly reasoning: the pointer is pinned to RDI ("D") and the store is
 * `movl $1, (%rdi)`. It faults with RIP at the store (a #PF is a fault, so
 * the saved RIP is the faulting instruction: SDM Vol. 3A section 7.5), and
 * the handler sets RIP to the label after it, so execution goes on at the
 * function's epilogue as if the store had completed. The store changes no
 * register or flag, so nothing else needs fixing. noinline keeps the
 * global labels defined once. */
__attribute__((noinline)) static void store_to(volatile int *p)
{
	__asm__ volatile("movl $1, (%0)\n\t"
			 ".globl segv_resume\n"
			 "segv_resume:"
			 :: "D"(p) : "memory");
}

/* Assembly reasoning: UD2 (0F 0B, SDM Vol. 2B "UD") always raises #UD, a
 * fault, so the saved RIP and si_addr are the UD2's own address (ill_at);
 * the handler resumes at the label after it. UD2 touches no register or
 * memory, so the asm needs no operands or clobbers. */
__attribute__((noinline)) static void undefined_instruction(void)
{
	__asm__ volatile(".globl ill_at\n"
			 "ill_at: ud2\n\t"
			 ".globl ill_resume\n"
			 "ill_resume:");
}

static void on_segv(int sig, siginfo_t *info, void *uc_)
{
	ucontext_t *uc = uc_;
	(void)sig;
	segv_addr = (uintptr_t)info->si_addr;
	segv_code = info->si_code;
	segv_trapno = uc->uc_mcontext.gregs[REG_TRAPNO];
	segv_err = uc->uc_mcontext.gregs[REG_ERR];
	segv_cr2 = uc->uc_mcontext.gregs[REG_CR2];
	uc->uc_mcontext.gregs[REG_RIP] = (greg_t)segv_resume;
}

static void on_ill(int sig, siginfo_t *info, void *uc_)
{
	ucontext_t *uc = uc_;
	ill_ok = sig == SIGILL && info->si_code == ILL_ILLOPN
		&& info->si_addr == (void *)ill_at
		&& uc->uc_mcontext.gregs[REG_RIP] == (greg_t)ill_at
		&& uc->uc_mcontext.gregs[REG_TRAPNO] == 6;
	uc->uc_mcontext.gregs[REG_RIP] = (greg_t)ill_resume;
}

/* --- FPU state across a handler --- */

static volatile unsigned handler_mxcsr, saved_mxcsr;

static void on_fpu(int sig, siginfo_t *info, void *uc_)
{
	ucontext_t *uc = uc_;
	(void)sig;
	(void)info;
	unsigned m;
	__asm__ volatile("stmxcsr %0" : "=m"(m));
	handler_mxcsr = m;
	saved_mxcsr = uc->uc_mcontext.fpregs->mxcsr;
	/* Clobber the live XMM0 (sigreturn must restore it) and edit the
	 * saved XMM1 (sigreturn must load the edit). */
	__asm__ volatile("pcmpeqd %%xmm0, %%xmm0" ::: "xmm0");
	uc->uc_mcontext.fpregs->_xmm[1].element[0] = 0x5eed1234;
}

/* Loads XMM0 and XMM1 and a non-default MXCSR, sends itself SIGUSR1 with
 * a raw tkill (so nothing between the loads and the delivery touches
 * them), then reads them back.
 *
 * Assembly reasoning:
 * - `stmxcsr`/`ldmxcsr` save and load MXCSR from 32-bit memory operands
 *   (SDM Vol. 2B). 0x7F80 is the default 0x1F80 (all exceptions masked)
 *   with RC (bits 13-14, 0x6000) = 11b, round toward zero (SDM Vol. 1
 *   section 10.2.3 and Table 4-9); the
 *   caller's MXCSR is put back at the end, so the C code after it sees the
 *   default again.
 * - `movd r32, xmm` zeroes the rest of the register and `movd xmm, r32`
 *   reads the low 32 bits (SDM Vol. 2B "MOVD/MOVQ"), so only element 0
 *   matters, which is what the handler edits (_xmm[1].element[0]).
 * - The system call: RAX = 200 (tkill, syscall_64.tbl), RDI = the TID
 *   ("D"), RSI = SIGUSR1 ("S"). SYSCALL overwrites RCX (return RIP) and R11
 *   (RFLAGS) (SDM Vol. 2B "SYSCALL"), and the Linux kernel returns its
 *   result in RAX and preserves every other register, XMM included
 *   (System V AMD64 psABI section A.2.1), so RAX, RCX and R11 are
 *   clobbered. The signal is delivered as the call returns, so the
 *   handler runs between `syscall` and the next instruction.
 * - XMM0 and XMM1 are listed as clobbered, so the compiler keeps nothing
 *   of its own in them across the block; "memory" because the block
 *   reads and writes the MXCSR slots. */
static void fpu_round_trip(unsigned *x0, unsigned *x1, unsigned *mx)
{
	unsigned a = 0x11111111, b = 0x22222222, rz = 0x7f80, old;
	long tid = syscall(SYS_gettid);
	__asm__ volatile("stmxcsr %[old]\n\t"
			 "ldmxcsr %[rz]\n\t"
			 "movd %[a], %%xmm0\n\t"
			 "movd %[b], %%xmm1\n\t"
			 "mov $200, %%eax\n\t"   /* tkill */
			 "syscall\n\t"
			 "movd %%xmm0, %[a]\n\t"
			 "movd %%xmm1, %[b]\n\t"
			 "stmxcsr %[rz]\n\t"
			 "ldmxcsr %[old]"
			 : [a] "+r"(a), [b] "+r"(b), [rz] "+m"(rz), [old] "=m"(old)
			 : "D"(tid), "S"(SIGUSR1)
			 : "rax", "rcx", "r11", "xmm0", "xmm1", "memory");
	*x0 = a;
	*x1 = b;
	*mx = rz;
}

/* --- alternate stack --- */

static char *alt_base;
static size_t alt_size;
static volatile int alt_ok;

static void on_alt(int sig)
{
	(void)sig;
	char here;
	stack_t now;
	sigaltstack(NULL, &now);
	alt_ok = &here > alt_base && &here < alt_base + alt_size
		&& (now.ss_flags & SS_ONSTACK);
}

/* --- threads --- */

static volatile pid_t worker_tid, handled_tid;
static volatile int worker_done, eintr_seen;
static volatile int stop_word;

static void on_thread_signal(int sig)
{
	(void)sig;
	handled_tid = syscall(SYS_gettid);
}

static void *worker(void *arg)
{
	(void)arg;
	worker_tid = syscall(SYS_gettid);
	/* Wait in the kernel on a word nobody changes: only a signal ends
	 * it, with EINTR (the handler has no SA_RESTART). */
	long r = syscall(SYS_futex, &stop_word, 0 /* FUTEX_WAIT */, 0, NULL, NULL, 0);
	eintr_seen = r == -1 && errno == EINTR;
	/* Then spin in user mode until signalled again: the signal arrives
	 * at a timer interrupt, not a system call. */
	handled_tid = 0;
	while (handled_tid == 0)
		;
	worker_done = 1;
	return NULL;
}

static void spin(void)
{
	for (volatile int i = 0; i < 2000000; i++)
		;
}

int main(void)
{
	pid_t me = getpid();

	/* 1. raise: musl's raise is tkill(gettid()), SI_TKILL, si_pid us. */
	install(SIGUSR1, on_usr1, 0, SIGUSR2);
	raise(SIGUSR1);
	CHECK(1, usr1_count == 1 && usr1_signo);
	CHECK(2, usr1_code == SI_TKILL && usr1_pid == me);
	CHECK(3, nested_mask_ok);
	sigset_t now;
	sigprocmask(SIG_BLOCK, NULL, &now);
	CHECK(4, !sigismember(&now, SIGUSR1) && !sigismember(&now, SIGUSR2));

	/* 2. kill: SI_USER. */
	kill(me, SIGUSR1);
	CHECK(5, usr1_count == 2 && usr1_code == SI_USER && usr1_pid == me);

	/* 3. Blocked, then delivered when unblocked. */
	sigset_t one;
	sigemptyset(&one);
	sigaddset(&one, SIGUSR1);
	sigprocmask(SIG_BLOCK, &one, NULL);
	kill(me, SIGUSR1);
	kill(me, SIGUSR1); /* a standard signal is not queued twice */
	CHECK(6, usr1_count == 2);
	sigprocmask(SIG_UNBLOCK, &one, NULL);
	CHECK(7, usr1_count == 3);

	/* 4. SA_RESETHAND: handled once, then the default again. */
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_usr2;
	sa.sa_flags = SA_RESETHAND;
	sigaction(SIGUSR2, &sa, NULL);
	raise(SIGUSR2);
	struct sigaction back;
	sigaction(SIGUSR2, NULL, &back);
	CHECK(8, usr2_count == 1 && back.sa_handler == SIG_DFL);

	/* 5. SIG_IGN: nothing happens. */
	signal(SIGUSR2, SIG_IGN);
	raise(SIGUSR2);
	CHECK(9, usr2_count == 1);

	/* 6. The alternate stack, with SA_ONSTACK. */
	alt_size = 64 * 1024;
	alt_base = malloc(alt_size);
	stack_t ss = { .ss_sp = alt_base, .ss_size = alt_size, .ss_flags = 0 };
	CHECK(10, sigaltstack(&ss, NULL) == 0);
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_alt;
	sa.sa_flags = SA_ONSTACK;
	sigaction(SIGUSR2, &sa, NULL);
	raise(SIGUSR2);
	CHECK(11, alt_ok);

	/* 7. SIGSEGV: an unmapped address (SEGV_MAPERR) and a PROT_NONE page
	 * (SEGV_ACCERR); the handler skips the store. trapno 14 (#PF), err
	 * with the write (2) and user (4) bits, cr2 the address. */
	install(SIGSEGV, on_segv, 0, 0);
	volatile int *unmapped = (volatile int *)(uintptr_t)0x10;
	store_to(unmapped);
	CHECK(12, segv_addr == 0x10 && segv_code == SEGV_MAPERR);
	CHECK(13, segv_trapno == 14 && (segv_err & 6) == 6 && segv_cr2 == 0x10);
	int *none = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	CHECK(14, none != MAP_FAILED);
	store_to(none + 1);
	CHECK(15, segv_addr == (uintptr_t)(none + 1) && segv_code == SEGV_ACCERR);

	/* 8. SIGILL from UD2. */
	install(SIGILL, on_ill, 0, 0);
	undefined_instruction();
	CHECK(16, ill_ok);

	/* 9. FPU state: the handler starts with MXCSR's default (0x1F80)
	 * while the frame holds the interrupted value; the live XMM0 it
	 * clobbers comes back, the saved XMM1 it edits is loaded. */
	install(SIGUSR1, on_fpu, 0, 0);
	unsigned x0, x1, mx;
	fpu_round_trip(&x0, &x1, &mx);
	CHECK(17, handler_mxcsr == 0x1f80 && saved_mxcsr == 0x7f80);
	CHECK(18, x0 == 0x11111111 && x1 == 0x5eed1234 && mx == 0x7f80);

	/* 10. Default actions, in children: SIGTERM ends one with signal 15;
	 * ignored, it does not; a fault with its signal blocked kills even
	 * with a handler installed (Linux forces the default). */
	int status;
	pid_t child = fork();
	if (child == 0) {
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	CHECK(19, waitpid(child, &status, 0) == child && WIFSIGNALED(status)
		  && WTERMSIG(status) == SIGTERM);
	child = fork();
	if (child == 0) {
		signal(SIGTERM, SIG_IGN);
		kill(getpid(), SIGTERM);
		_exit(7);
	}
	CHECK(20, waitpid(child, &status, 0) == child && WIFEXITED(status)
		  && WEXITSTATUS(status) == 7);
	child = fork();
	if (child == 0) {
		sigset_t segv;
		sigemptyset(&segv);
		sigaddset(&segv, SIGSEGV);
		sigprocmask(SIG_BLOCK, &segv, NULL);
		store_to(unmapped);
		_exit(3);
	}
	CHECK(21, waitpid(child, &status, 0) == child && WIFSIGNALED(status)
		  && WTERMSIG(status) == SIGSEGV);

	/* 11. A signal for one thread: pthread_kill (tgkill). The first
	 * interrupts its futex wait with EINTR; the next reaches it spinning
	 * in user mode. Sent repeatedly, since it may arrive before the
	 * worker waits (the handler is harmless). */
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = on_thread_signal;
	sigaction(SIGUSR2, &sa, NULL);
	pthread_t t;
	CHECK(22, pthread_create(&t, NULL, worker, NULL) == 0);
	while (worker_tid == 0)
		spin();
	while (!worker_done) {
		pthread_kill(t, SIGUSR2);
		spin();
	}
	pthread_join(t, NULL);
	CHECK(23, eintr_seen);
	CHECK(24, handled_tid == worker_tid);

	printf("signals: 24 checks passed\n");
	return 0;
}
