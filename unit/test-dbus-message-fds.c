/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <ell/ell.h>
#include <ell/dbus-private.h>

#define TEST_BUS_ADDRESS "unix:path=/tmp/ell-test-bus"

static pid_t dbus_daemon_pid = -1;

static bool start_dbus_daemon(void)
{
	char *prg_argv[5];
	char *prg_envp[1];
	pid_t pid;

	prg_argv[0] = "/usr/bin/dbus-daemon";
	prg_argv[1] = "--nopidfile";
	prg_argv[2] = "--nofork";
	prg_argv[3] = "--config-file=" TESTDATADIR "/dbus.conf";
	prg_argv[4] = NULL;

	prg_envp[0] = NULL;

	l_info("launching dbus-daemon");

	pid = fork();
	if (pid < 0) {
		l_error("failed to fork new process");
		return false;
	}

	if (pid == 0) {
		execve(prg_argv[0], prg_argv, prg_envp);
		exit(EXIT_SUCCESS);
	}

	l_info("dbus-daemon process %d created", pid);

	dbus_daemon_pid = pid;

	return true;
}

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	case SIGCHLD:
		while (1) {
			pid_t pid;
			int status;

			pid = waitpid(WAIT_ANY, &status, WNOHANG);
			if (pid < 0 || pid == 0)
				break;

			l_info("process %d terminated with status=%d\n",
								pid, status);

			if (pid == dbus_daemon_pid) {
				dbus_daemon_pid = -1;
				l_main_quit();
			}
		}
		break;
	}
}

static struct l_dbus *dbus;

struct dbus_test {
	const char *name;
	void (*start)(struct l_dbus *dbus, void *);
	void *data;
};

static bool success;
static struct l_queue *tests;
static const struct l_queue_entry *current;

static void test_add(const char *name,
			void (*start)(struct l_dbus *dbus, void *),
			void *test_data)
{
	struct dbus_test *test = l_new(struct dbus_test, 1);

	test->name = name;
	test->start = start;
	test->data = test_data;

	if (!tests)
		tests = l_queue_new();

	l_queue_push_tail(tests, test);
}

static void test_next()
{
	struct dbus_test *test;

	if (current)
		current = current->next;
	else
		current = l_queue_get_entries(tests);

	if (!current) {
		success = true;
		l_main_quit();
		return;
	}

	test = current->data;

	l_info("TEST: %s", test->name);

	test->start(dbus, test->data);
}

#define test_assert(cond)	\
	do {	\
		if (!(cond)) {	\
			l_info("TEST FAILED in %s at %s:%i: %s",	\
				__func__, __FILE__, __LINE__,	\
				L_STRINGIFY(cond));	\
			l_main_quit();	\
			return;	\
		}	\
	} while (0)

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	l_info("request name result=%s",
		success ? (queued ? "queued" : "success") : "failed");

	test_next();
}

static void ready_callback(void *user_data)
{
	l_info("ready");

	l_dbus_name_acquire(dbus, "org.test", false, false, false,
				request_name_callback, NULL);
}

static void disconnect_callback(void *user_data)
{
	l_info("Disconnected from DBus");
	l_main_quit();
}

static struct l_dbus_message *get_random_callback(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *reply;
	int fd;

	reply = l_dbus_message_new_method_return(message);

	fd = open("/dev/random", O_RDONLY);
	l_dbus_message_set_arguments(reply, "h", fd);
	close(fd);

	return reply;
}

static void setup_test_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetRandom", 0, get_random_callback,
				"h", "", "randomfd");
}

static int count_fds(void)
{
	int fd;
	int count = 0;
	int flags;

	for (fd = 0; fd < FD_SETSIZE; fd++) {
		flags = fcntl(fd, F_GETFL);
		if (flags < 0) /* ignore any files we can't operate on */
			continue;

		/*
		 * Only count files that are read-only or write-only.  This is
		 * to work around the issue that fakeroot opens a TCP socket
		 * in RDWR mode in a separate thread
		 *
		 * Note: This means that files used for file-descriptor passing
		 * tests should be opened RDONLY or WRONLY
		 */
		if (flags & O_RDWR)
			continue;

		count++;
	}

	return count;
}

static bool compare_failed;

static void compare_files(int a, int b)
{
	struct stat sa, sb;

	compare_failed = true;

	test_assert(fstat(a, &sa) == 0);
	test_assert(fstat(b, &sb) == 0);

	test_assert(sa.st_dev == sb.st_dev);
	test_assert(sa.st_ino == sb.st_ino);
	test_assert(sa.st_rdev == sb.st_rdev);

	compare_failed = false;
}

static int open_fds;

static void get_random_idle_callback(void *user_data)
{
	test_assert(count_fds() == open_fds);

	test_next();
}

static void get_random_return_callback(struct l_dbus_message *message,
					void *user_data)
{
	int fd0, fd1;

	test_assert(!l_dbus_message_get_error(message, NULL, NULL));

	test_assert(l_dbus_message_get_arguments(message, "h", &fd1));

	fd0 = open("/dev/random", O_RDONLY);
	test_assert(fd0 != -1);

	compare_files(fd0, fd1);
	if (compare_failed)
		return;

	close(fd0);
	close(fd1);

	test_assert(l_idle_oneshot(get_random_idle_callback, NULL, NULL));
}

static void test_fd_passing_1(struct l_dbus *dbus, void *test_data)
{
	open_fds = count_fds();

	l_dbus_method_call(dbus, "org.test", "/test", "org.test", "GetRandom",
				NULL, get_random_return_callback, NULL, NULL);
}

static void test_run(void)
{
	success = false;

	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	if (!l_dbus_register_interface(dbus, "org.test", setup_test_interface,
					NULL, true)) {
		l_info("Unable to register interface");
		return;
	}

	if (!l_dbus_object_add_interface(dbus, "/test", "org.test", NULL)) {
		l_info("Unable to instantiate interface");
		return;
	}

	l_main_run();
}

int main(int argc, char *argv[])
{
	struct l_signal *signal;
	sigset_t mask;
	int i;

	if (!l_main_init())
		return -1;

	test_add("FD passing 1", test_fd_passing_1, NULL);

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGCHLD);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	if (!start_dbus_daemon())
		return -1;

	for (i = 0; i < 10; i++) {
		usleep(200 * 1000);

		dbus = l_dbus_new(TEST_BUS_ADDRESS);
		if (dbus)
			break;
	}

	if (!dbus)
		goto done;

	test_run();

	l_dbus_destroy(dbus);

done:
	if (dbus_daemon_pid > 0)
		kill(dbus_daemon_pid, SIGKILL);

	l_signal_remove(signal);
	l_queue_destroy(tests, l_free);

	l_main_exit();

	if (!success)
		abort();

	return 0;
}
