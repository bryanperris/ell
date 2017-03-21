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

#include <sys/socket.h>
#include <assert.h>

#include <ell/ell.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void family_vanished(void *user_data)
{
	bool *vanished_called = user_data;

	*vanished_called = true;
}

static void idle_callback(struct l_idle *idle, void *user_data)
{
	static int count = 0;

	/*
	 * Allow the main loop to iterate at least twice to allow the
	 * generic netlink watches to be called.
	 */
	if (++count > 1)
		l_main_quit();
}

int main(int argc, char *argv[])
{
	struct l_genl *genl;
	struct l_genl_family *family;
	struct l_idle *idle;

	/*
	 * Use a bogus family name to trigger the vanished watch to
	 * be called.
	 */
	static const char BOGUS_GENL_NAME[] = "bogus_genl_family";

	bool vanished_called = false;

	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	genl = l_genl_new_default();

	l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	family = l_genl_family_new(genl, BOGUS_GENL_NAME);
	l_genl_family_set_watches(family, NULL, family_vanished,
					&vanished_called, NULL);

	idle = l_idle_create(idle_callback, NULL, NULL);

	l_main_run();

	l_idle_remove(idle);

	l_genl_family_unref(family);
	l_genl_unref(genl);

	l_main_exit();

	assert(vanished_called);

	return 0;
}
