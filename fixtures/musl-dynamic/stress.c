/* Phase 3 acceptance item 4: a randomized fork, thread and signal stress
 * test. `stress [SEED [SECONDS]]` (default seed 1, 5 seconds) runs until
 * the time is up, choosing each step from SEED's sequence:
 *
 * - fork a child with one of five plans:
 *   - EXIT: start 0 to 3 threads that make system calls and signal the
 *     main thread, join them, and exit with a chosen code;
 *   - CRASH: write through a null pointer (SIGSEGV);
 *   - WAIT: wait in pause() until the parent sends SIGTERM or SIGKILL;
 *   - NEST: fork a grandchild, reap it, check its status, and exit;
 *   - GROUP: start threads that wait, and end the process from one of
 *     them with _exit (exit_group);
 * - signal a WAIT child (SIGTERM or SIGKILL), stop and continue a child
 *   (SIGSTOP, then wait4 with WUNTRACED, then SIGCONT), or send a child
 *   SIGUSR1, which every process catches;
 * - reap children with WNOHANG;
 * - in the parent, start two threads, each with an alternate signal
 *   stack, that signal each other (SIGUSR2, SA_ONSTACK) and join them;
 * - sleep for a millisecond.
 *
 * Every child's wait status is checked against its plan and what was sent
 * to it. At the end the WAIT children still alive are killed (SIGKILL),
 * every child is reaped, and wait4 must then be ECHILD. A failed check
 * exits with its own status and prints which; success prints one line.
 * Children are at most MAX_KIDS at a time. It must behave the same on
 * Linux and on Keel. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_KIDS 16
#define ALT_SIZE 65536

static void fail(int code, const char *what, long detail)
{
	printf("stress: check %d failed: %s (%ld, errno %d)\n", code, what, detail, errno);
	fflush(stdout);
	_exit(code);
}

#define CHECK(code, cond, detail) do { if (!(cond)) fail(code, #cond, (long)(detail)); } while (0)

static uint64_t rng;

static uint64_t next(void)
{
	/* xorshift64: Marsaglia, "Xorshift RNGs", Journal of Statistical
	 * Software 8(14), 2003, section 3, xor64() (shifts 13, 7, 17, one of
	 * the paper's full-period 64-bit triples). The state must not be 0. */
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng;
}

static unsigned below(unsigned n)
{
	return (unsigned)(next() % n);
}

static volatile sig_atomic_t usr1_seen, usr2_seen;

static void on_usr1(int sig)
{
	(void)sig;
	usr1_seen++;
}

static void on_usr2(int sig)
{
	(void)sig;
	usr2_seen++;
}

static uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static void nap_us(long us)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = us * 1000 };
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

/* --- children --------------------------------------------------------- */

enum plan { EXIT, CRASH, WAIT, NEST, GROUP, PLANS };

static pthread_t child_main;

static void *chatter(void *arg)
{
	unsigned rounds = (unsigned)(uintptr_t)arg;
	for (unsigned i = 0; i < rounds; i++) {
		getppid();
		if (i % 4 == 0)
			sched_yield();
		pthread_kill(child_main, SIGUSR1);
	}
	return NULL;
}

static void *waiter(void *arg)
{
	(void)arg;
	for (;;)
		pause();
	return NULL;
}

static void *ender(void *arg)
{
	nap_us(500);
	_exit((int)(uintptr_t)arg);
}

static void run_child(enum plan plan, unsigned code, unsigned threads)
{
	child_main = pthread_self();
	switch (plan) {
	case EXIT: {
		pthread_t t[3];
		for (unsigned i = 0; i < threads; i++)
			if (pthread_create(&t[i], NULL, chatter, (void *)(uintptr_t)(20 + i * 10)) != 0)
				_exit(101);
		for (unsigned i = 0; i < threads; i++)
			pthread_join(t[i], NULL);
		_exit((int)code);
	}
	case CRASH:
		*(volatile int *)0 = 1;
		_exit(102);
	case WAIT:
		for (;;)
			pause();
	case NEST: {
		pid_t g = fork();
		if (g < 0)
			_exit(103);
		if (g == 0)
			_exit((int)(code ^ 0x55));
		int st;
		if (waitpid(g, &st, 0) != g || !WIFEXITED(st)
		    || WEXITSTATUS(st) != (int)(code ^ 0x55))
			_exit(104);
		_exit((int)code);
	}
	case GROUP: {
		pthread_t t;
		for (unsigned i = 0; i < threads; i++)
			if (pthread_create(&t, NULL, waiter, NULL) != 0)
				_exit(105);
		if (pthread_create(&t, NULL, ender, (void *)(uintptr_t)code) != 0)
			_exit(106);
		for (;;)
			pause();
	}
	default:
		_exit(107);
	}
}

struct kid {
	pid_t pid;
	enum plan plan;
	unsigned code;
	int killed_with; /* the signal sent to a WAIT child, 0 if none */
};

static struct kid kids[MAX_KIDS];
static unsigned live, forked, reaped, stops, signals_sent, thread_pairs;

static void spawn(void)
{
	if (live == MAX_KIDS)
		return;
	enum plan plan = (enum plan)below(PLANS);
	unsigned code = 1 + below(100);
	unsigned threads = below(4);
	pid_t pid = fork();
	CHECK(1, pid >= 0, pid);
	if (pid == 0)
		run_child(plan, code, threads);
	kids[live++] = (struct kid){ .pid = pid, .plan = plan, .code = code };
	forked++;
}

/* Checks a child's final status against its plan and removes it. */
static void settle(unsigned i, int status)
{
	struct kid k = kids[i];
	switch (k.plan) {
	case EXIT:
	case NEST:
	case GROUP:
		CHECK(2, WIFEXITED(status) && WEXITSTATUS(status) == (int)k.code, status);
		break;
	case CRASH:
		CHECK(3, WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV, status);
		break;
	case WAIT:
		CHECK(4, k.killed_with != 0, status);
		CHECK(5, WIFSIGNALED(status) && WTERMSIG(status) == k.killed_with, status);
		break;
	default:
		fail(6, "plan", k.plan);
	}
	kids[i] = kids[--live];
	reaped++;
}

static int index_of(pid_t pid)
{
	for (unsigned i = 0; i < live; i++)
		if (kids[i].pid == pid)
			return (int)i;
	return -1;
}

static void reap(int options)
{
	for (;;) {
		int status;
		pid_t pid = waitpid(-1, &status, options);
		if (pid == 0 || (pid < 0 && errno == ECHILD && live == 0))
			return;
		CHECK(7, pid > 0, pid);
		int i = index_of(pid);
		CHECK(8, i >= 0, pid);
		CHECK(9, !WIFSTOPPED(status), status);
		settle((unsigned)i, status);
		if (!(options & WNOHANG))
			return;
	}
}

static void kill_waiter(void)
{
	for (unsigned tries = 0; tries < live; tries++) {
		unsigned i = below(live);
		if (kids[i].plan == WAIT && kids[i].killed_with == 0) {
			int sig = below(2) ? SIGKILL : SIGTERM;
			CHECK(10, kill(kids[i].pid, sig) == 0, kids[i].pid);
			kids[i].killed_with = sig;
			signals_sent++;
			return;
		}
	}
}

/* SIGSTOP, wait for the stop (or the child's end, which may come first),
 * then SIGCONT. */
static void stop_and_continue(void)
{
	if (live == 0)
		return;
	unsigned i = below(live);
	pid_t pid = kids[i].pid;
	CHECK(11, kill(pid, SIGSTOP) == 0, pid);
	int status;
	pid_t got = waitpid(pid, &status, WUNTRACED);
	CHECK(12, got == pid, got);
	if (WIFSTOPPED(status)) {
		CHECK(13, WSTOPSIG(status) == SIGSTOP, status);
		CHECK(14, kill(pid, SIGCONT) == 0, pid);
		stops++;
	} else {
		settle(i, status);
	}
}

static void poke(void)
{
	if (live == 0)
		return;
	unsigned i = below(live);
	CHECK(15, kill(kids[i].pid, SIGUSR1) == 0, kids[i].pid);
	signals_sent++;
}

/* --- threads in the parent -------------------------------------------- */

struct pair {
	pthread_t self, other;
	/* start: both threads and the main thread, once both IDs are known;
	 * done: both threads, once both have sent all their signals. */
	pthread_barrier_t *start, *done;
	char *alt;
};

static void *pinger(void *arg)
{
	struct pair *p = arg;
	stack_t ss = { .ss_sp = p->alt, .ss_size = ALT_SIZE, .ss_flags = 0 };
	CHECK(16, sigaltstack(&ss, NULL) == 0, 0);
	pthread_barrier_wait(p->start);
	for (int i = 0; i < 25; i++) {
		int r = pthread_kill(p->other, SIGUSR2);
		CHECK(17, r == 0, r);
		if (i % 5 == 0)
			sched_yield();
	}
	/* Both have sent all theirs before either leaves. */
	pthread_barrier_wait(p->done);
	stack_t off = { .ss_flags = SS_DISABLE };
	CHECK(18, sigaltstack(&off, NULL) == 0, 0);
	return NULL;
}

static void thread_pair(void)
{
	static char alt[2][ALT_SIZE];
	pthread_barrier_t start, done;
	pthread_barrier_init(&start, NULL, 3);
	pthread_barrier_init(&done, NULL, 2);
	struct pair p[2] = {
		{ .start = &start, .done = &done, .alt = alt[0] },
		{ .start = &start, .done = &done, .alt = alt[1] },
	};
	CHECK(19, pthread_create(&p[0].self, NULL, pinger, &p[0]) == 0, 0);
	p[1].other = p[0].self;
	CHECK(19, pthread_create(&p[1].self, NULL, pinger, &p[1]) == 0, 1);
	p[0].other = p[1].self;
	/* Neither signals before both know the other's ID. */
	pthread_barrier_wait(&start);
	CHECK(20, pthread_join(p[0].self, NULL) == 0, 0);
	CHECK(20, pthread_join(p[1].self, NULL) == 0, 1);
	pthread_barrier_destroy(&start);
	pthread_barrier_destroy(&done);
	thread_pairs++;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	uint64_t seed = argc > 1 ? strtoull(argv[1], NULL, 10) : 1;
	uint64_t seconds = argc > 2 ? strtoull(argv[2], NULL, 10) : 5;
	rng = seed * 0x9e3779b97f4a7c15u + 1;
	if (rng == 0)
		rng = 1;

	struct sigaction sa = { .sa_handler = on_usr1, .sa_flags = SA_RESTART };
	sigemptyset(&sa.sa_mask);
	CHECK(21, sigaction(SIGUSR1, &sa, NULL) == 0, 0);
	sa.sa_handler = on_usr2;
	sa.sa_flags = SA_RESTART | SA_ONSTACK;
	CHECK(21, sigaction(SIGUSR2, &sa, NULL) == 0, 0);

	uint64_t deadline = now_ns() + seconds * 1000000000u;
	while (now_ns() < deadline) {
		switch (below(10)) {
		case 0:
		case 1:
		case 2:
			spawn();
			break;
		case 3:
			kill_waiter();
			break;
		case 4:
			stop_and_continue();
			break;
		case 5:
			poke();
			break;
		case 6:
		case 7:
			reap(WNOHANG);
			break;
		case 8:
			thread_pair();
			break;
		default:
			nap_us(1000);
			break;
		}
	}
	/* The end: every WAIT child still unsignalled gets SIGKILL; all are
	 * reaped; then there are none. */
	for (unsigned i = 0; i < live; i++)
		if (kids[i].plan == WAIT && kids[i].killed_with == 0) {
			CHECK(22, kill(kids[i].pid, SIGKILL) == 0, kids[i].pid);
			kids[i].killed_with = SIGKILL;
		}
	while (live > 0)
		reap(0);
	int status;
	CHECK(23, waitpid(-1, &status, 0) == -1 && errno == ECHILD, 0);
	fprintf(stderr, "stress: seed %llu, %llu s: %u children forked and reaped, %u stops, %u signals sent, %u thread pairs\n",
		(unsigned long long)seed, (unsigned long long)seconds, forked, stops, signals_sent, thread_pairs);
	CHECK(24, forked == reaped && forked > 0, forked);
	printf("stress: passed\n");
	return 0;
}
