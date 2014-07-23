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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include <ell/ell.h>
#include <ell/dbus.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
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
		return;
	}

	if (!l_dbus_message_get_arguments(message, "u", &result))
		return;

	l_info("request name result=%d", result);
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

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	dbus = l_dbus_new_default(L_DBUS_SESSION_BUS);
	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);
	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	l_dbus_method_call(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "RequestName",
				request_name_setup,
				request_name_callback, NULL, NULL);

	l_main_run();

	l_dbus_destroy(dbus);
	l_signal_remove(signal);

	return EXIT_SUCCESS;
}
