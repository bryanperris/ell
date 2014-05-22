/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>
#include <ell/dbus.h>

#define TEST_BUS_ADDRESS "unix:path=/tmp/ell-test-bus"

static pid_t dbus_daemon_pid = -1;

static void start_dbus_daemon(void)
{
	char *prg_argv[6];
	char *prg_envp[1];
	pid_t pid;

	prg_argv[0] = "/usr/bin/dbus-daemon";
	prg_argv[1] = "--session";
	prg_argv[2] = "--address=" TEST_BUS_ADDRESS;
	prg_argv[3] = "--nopidfile";
	prg_argv[4] = "--nofork";
	prg_argv[5] = NULL;

	prg_envp[0] = NULL;

	l_info("launching dbus-daemon");

	pid = fork();
	if (pid < 0) {
		l_error("failed to fork new process");
		return;
	}

	if (pid == 0) {
		execve(prg_argv[0], prg_argv, prg_envp);
		exit(EXIT_SUCCESS);
	}

	l_info("dbus-daemon process %d created", pid);

	dbus_daemon_pid = pid;
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

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void signal_message(struct l_dbus_message *message, void *user_data)
{
	const char *path, *interface, *member, *destination, *sender;

	path = l_dbus_message_get_path(message);
	destination = l_dbus_message_get_destination(message);

	l_info("path=%s destination=%s", path, destination);

	interface = l_dbus_message_get_interface(message);
	member = l_dbus_message_get_member(message);

	l_info("interface=%s member=%s", interface, member);

	sender = l_dbus_message_get_sender(message);

	l_info("sender=%s", sender);

	if (!strcmp(member, "NameOwnerChanged")) {
		const char *name, *old_owner, *new_owner;

		if (!l_dbus_message_get_arguments(message, "sss",
					&name, &old_owner, &new_owner))
			return;

		l_info("name=%s old=%s new=%s", name, old_owner, new_owner);
	}
}

static void request_name_setup(struct l_dbus_message *message, void *user_data)
{
	const char *name = "org.test";
	uint32_t flags = 0;

	l_dbus_message_set_arguments(message, "su", &name, &flags);
}

static void request_name_callback(struct l_dbus_message *message,
							void *user_data)
{
	const char *error, *text;
	uint32_t result;

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("error=%s", error);
		l_error("message=%s", text);
		goto done;
	}

	if (!l_dbus_message_get_arguments(message, "u", &result))
		goto done;

	l_info("request name result=%d", result);

done:
	l_main_quit();
}

static const char *match_rule = "type=signal,sender=org.freedesktop.DBus";

static void add_match_setup(struct l_dbus_message *message, void *user_data)
{
	l_dbus_message_set_arguments(message, "s", &match_rule);
}

static void add_match_callback(struct l_dbus_message *message, void *user_data)
{
	const char *error, *text;

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("error=%s", error);
		l_error("message=%s", text);
		return;
	}

	if (!l_dbus_message_get_arguments(message, ""))
		return;

	l_info("add match");
}

static void ready_callback(void *user_data)
{
	l_info("ready");
}

static void disconnect_callback(void *user_data)
{
	l_main_quit();
}

int main(int argc, char *argv[])
{
	struct l_dbus *dbus;
	struct l_signal *signal;
	sigset_t mask;
	int i;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGCHLD);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	start_dbus_daemon();

	for (i = 0; i < 10; i++) {
		usleep(200 * 1000);

		dbus = l_dbus_new(TEST_BUS_ADDRESS);
		if (dbus)
			break;
	}

	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);

	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	l_dbus_register(dbus, signal_message, NULL, NULL);

	l_dbus_method_call(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "AddMatch",
				add_match_setup,
				add_match_callback, NULL, NULL);

	l_dbus_method_call(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "RequestName",
				request_name_setup,
				request_name_callback, NULL, NULL);

	l_main_run();

	l_dbus_destroy(dbus);

	if (dbus_daemon_pid > 0)
		kill(dbus_daemon_pid, SIGKILL);

	l_signal_remove(signal);

	return 0;
}
