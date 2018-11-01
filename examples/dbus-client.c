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

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>

#include <ell/ell.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void signal_handler(uint32_t signo, void *user_data)
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

static void iwd_service_appeared(struct l_dbus *dbus, void *user_data)
{
	l_info("Service appeared");
}

static void iwd_service_disappeared(struct l_dbus *dbus, void *user_data)
{
	l_info("Service disappeared");
}

static void bluez_client_connected(struct l_dbus *dbus, void *user_data)
{
	l_info("client connected");
}

static void bluez_client_disconnected(struct l_dbus *dbus, void *user_data)
{
	l_info("client disconnected");
}

static void bluez_client_ready(struct l_dbus_client *client, void *user_data)
{
	l_info("client ready");
}

static void proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("proxy added: %s %s", path, interface);

	if (!strcmp(interface, "org.bluez.Adapter1") ||
				!strcmp(interface, "org.bluez.Device1")) {
		char *str;

		if (!l_dbus_proxy_get_property(proxy, "Address", "s", &str))
			return;

		l_info("   Address: %s", str);
	}
}

static void proxy_removed(struct l_dbus_proxy *proxy, void *user_data)
{
	l_info("proxy removed: %s %s", l_dbus_proxy_get_path(proxy),
					l_dbus_proxy_get_interface(proxy));
}

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	l_info("property changed: %s (%s %s)", name,
					l_dbus_proxy_get_path(proxy),
					l_dbus_proxy_get_interface(proxy));

	if (!strcmp(name, "Address")) {
		char *str;

		if (!l_dbus_message_get_arguments(msg, "s", &str)) {
			return;
		}

		l_info("   Address: %s", str);
	}
}

int main(int argc, char *argv[])
{
	struct l_dbus_client *client;
	struct l_dbus *dbus;
	uint32_t iwd_watch_id;


	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);
	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);
	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	/* service basic watch */
	iwd_watch_id = l_dbus_add_service_watch(dbus, "net.connman.iwd",
						iwd_service_appeared,
						iwd_service_disappeared,
						NULL, NULL);

	/* proxy example */
	client = l_dbus_client_new(dbus, "org.bluez", "/org/bluez");

	l_dbus_client_set_connect_handler(client, bluez_client_connected, NULL,
									NULL);
	l_dbus_client_set_disconnect_handler(client, bluez_client_disconnected,
								NULL, NULL);

	l_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							property_changed, NULL, NULL);

	l_dbus_client_set_ready_handler(client, bluez_client_ready, NULL, NULL);


	l_main_run_with_signal(signal_handler, NULL);

	l_dbus_remove_watch(dbus, iwd_watch_id);

	l_dbus_client_destroy(client);

	l_dbus_destroy(dbus);

	l_main_exit();

	return 0;
}
