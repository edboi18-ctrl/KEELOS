/* Phase 3 acceptance item 2: one dynamically linked musl program that
 * uses POSIX threads, a signal handler on an alternate stack, and a Unix
 * socket to a forked child, all at once.
 *
 * - The parent binds a Unix stream socket to a path in a fresh directory
 *   under /tmp and forks. The child connects to it.
 * - The parent starts WORKERS threads. Each sets up its own alternate
 *   signal stack and waits. The parent sends each one SIGUSR1 with
 *   pthread_kill. The handler (SA_ONSTACK) checks that it runs on that
 *   thread's alternate stack: the address of one of its locals is inside
 *   the thread's stack buffer. It calls no function, since sigaltstack(2)
 *   is not async-signal-safe (signal-safety(7) does not list it).
 * - The thread then goes on through a semaphore the main thread posts
 *   after pthread_kill (sem_post is async-signal-safe, signal-safety(7);
 *   the main thread is not in a handler anyway). A new thread starts with
 *   no alternate stack (sigaltstack(2): a clone with CLONE_VM and without
 *   CLONE_VFORK disables it), so each sets its own.
 * - Each thread then sends a value over the socket to the child. The
 *   child adds them up and sends back the sum and its PID.
 * - The main thread also takes a signal on its own alternate stack.
 *
 * Each check exits with its own status (and prints which) on failure, and
 * the program prints one line at the end. It must behave the same on
 * Linux and on Keel: `cargo xtask test` runs it on both. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define WORKERS 4
#define ALT_SIZE 65536

static void fail(int code, const char *what)
{
	printf("acceptance2: check %d failed: %s (errno %d)\n", code, what, errno);
	fflush(stdout);
	_exit(code);
}

#define CHECK(code, cond) do { if (!(cond)) fail(code, #cond); } while (0)

/* This thread's alternate stack, and whether its handler ran there. */
static __thread char *alt_low, *alt_high;
static __thread volatile sig_atomic_t on_alt;

static void on_usr1(int sig)
{
	char here;
	(void)sig;
	on_alt = &here >= alt_low && &here < alt_high;
}

struct worker {
	pthread_t thread;
	int index;
	int sock;
	sem_t ready, signalled;
	int ok;
	pthread_mutex_t *lock;
};

/* An alternate stack of this thread's own. */
static void own_alt_stack(char *buf)
{
	stack_t ss = { .ss_sp = buf, .ss_size = ALT_SIZE, .ss_flags = 0 };
	alt_low = buf;
	alt_high = buf + ALT_SIZE;
	CHECK(1, sigaltstack(&ss, NULL) == 0);
}

static void *work(void *arg)
{
	struct worker *w = arg;
	char *buf = malloc(ALT_SIZE);
	CHECK(2, buf != NULL);
	own_alt_stack(buf);
	sem_post(&w->ready);
	/* Wait, with SIGUSR1 deliverable, until the handler has run. */
	while (sem_wait(&w->signalled) != 0)
		CHECK(3, errno == EINTR);
	w->ok = on_alt;
	uint64_t value = (uint64_t)(w->index + 1) * 1000 + 7;
	pthread_mutex_lock(w->lock);
	CHECK(4, write(w->sock, &value, sizeof value) == sizeof value);
	pthread_mutex_unlock(w->lock);
	/* Leave the stack before freeing it. */
	stack_t off = { .ss_flags = SS_DISABLE };
	CHECK(5, sigaltstack(&off, NULL) == 0);
	free(buf);
	return NULL;
}

/* The forked child: connects, adds up WORKERS values, sends back the sum
 * and its PID. */
static int child(const char *path)
{
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strcpy(addr.sun_path, path);
	if (s < 0 || connect(s, (struct sockaddr *)&addr, sizeof addr) != 0)
		return 20;
	uint64_t sum = 0;
	for (int i = 0; i < WORKERS; i++) {
		uint64_t v;
		size_t got = 0;
		while (got < sizeof v) {
			ssize_t n = read(s, (char *)&v + got, sizeof v - got);
			if (n <= 0)
				return 21;
			got += (size_t)n;
		}
		sum += v;
	}
	uint64_t reply[2] = { sum, (uint64_t)getpid() };
	if (write(s, reply, sizeof reply) != sizeof reply)
		return 22;
	close(s);
	return 0;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	char dir[] = "/tmp/keel-accept2-XXXXXX";
	CHECK(6, mkdtemp(dir) != NULL);
	char path[sizeof dir + 8];
	snprintf(path, sizeof path, "%s/sock", dir);

	struct sigaction sa = { .sa_handler = on_usr1, .sa_flags = SA_ONSTACK };
	sigemptyset(&sa.sa_mask);
	CHECK(7, sigaction(SIGUSR1, &sa, NULL) == 0);

	int listener = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strcpy(addr.sun_path, path);
	CHECK(8, listener >= 0);
	CHECK(8, bind(listener, (struct sockaddr *)&addr, sizeof addr) == 0);
	CHECK(8, listen(listener, 1) == 0);

	pid_t pid = fork();
	CHECK(9, pid >= 0);
	if (pid == 0) {
		close(listener);
		_exit(child(path));
	}
	int conn = accept(listener, NULL, NULL);
	CHECK(10, conn >= 0);

	/* The main thread's own alternate stack and signal. */
	static char main_alt[ALT_SIZE];
	own_alt_stack(main_alt);
	CHECK(11, raise(SIGUSR1) == 0 && on_alt);

	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
	struct worker w[WORKERS];
	for (int i = 0; i < WORKERS; i++) {
		w[i].index = i;
		w[i].sock = conn;
		w[i].ok = 0;
		w[i].lock = &lock;
		sem_init(&w[i].ready, 0, 0);
		sem_init(&w[i].signalled, 0, 0);
		CHECK(12, pthread_create(&w[i].thread, NULL, work, &w[i]) == 0);
	}
	for (int i = 0; i < WORKERS; i++) {
		while (sem_wait(&w[i].ready) != 0)
			CHECK(13, errno == EINTR);
		/* The handler runs in the thread before pthread_kill's signal
		 * is taken; the semaphore then lets the thread go on. */
		CHECK(14, pthread_kill(w[i].thread, SIGUSR1) == 0);
		sem_post(&w[i].signalled);
	}
	for (int i = 0; i < WORKERS; i++) {
		CHECK(15, pthread_join(w[i].thread, NULL) == 0);
		CHECK(16, w[i].ok);
	}

	uint64_t reply[2];
	size_t got = 0;
	while (got < sizeof reply) {
		ssize_t n = read(conn, (char *)reply + got, sizeof reply - got);
		CHECK(17, n > 0);
		got += (size_t)n;
	}
	uint64_t want = 0;
	for (int i = 0; i < WORKERS; i++)
		want += (uint64_t)(i + 1) * 1000 + 7;
	CHECK(18, reply[0] == want && reply[1] == (uint64_t)pid);
	int status;
	CHECK(19, waitpid(pid, &status, 0) == pid && WIFEXITED(status)
		&& WEXITSTATUS(status) == 0);
	close(conn);
	close(listener);
	CHECK(20, unlink(path) == 0 && rmdir(dir) == 0);
	printf("acceptance2: %d threads took signals on their own alternate stacks; sum %llu from a forked child over a Unix socket\n",
	       WORKERS, (unsigned long long)want);
	return 0;
}
