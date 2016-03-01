/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2016  Intel Corporation. All rights reserved.
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

static void ready_callback(void *user_data)
{
	l_info("ready");
}

static void disconnect_callback(void *user_data)
{
	l_main_quit();
}

static void service_appeared(struct l_dbus *dbus, void *user_data)
{
	l_info("Service appeared");
}

static void service_disappeared(struct l_dbus *dbus, void *user_data)
{
	l_info("Service disappeared, quitting...");
	l_main_quit();
}

int main(int argc, char *argv[])
{
	struct l_dbus *dbus;
	struct l_signal *signal;
	sigset_t mask;
	uint32_t watch_id;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);
	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	watch_id = l_dbus_add_service_watch(dbus, "net.connman.iwd",
						service_appeared,
						service_disappeared,
						NULL, NULL);

	l_main_run();

	l_dbus_remove_watch(dbus, watch_id);

	l_dbus_destroy(dbus);
	l_signal_remove(signal);

	return 0;
}
