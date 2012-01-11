/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>
#include <ell/dbus.h>

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
	l_dbus_message_set_arguments(message, "su", "org.test", 0);
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
	l_dbus_message_set_arguments(message, "s", match_rule);
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

	l_log_set_stderr();

	dbus = l_dbus_new(L_DBUS_SESSION_BUS);

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

	return 0;
}
