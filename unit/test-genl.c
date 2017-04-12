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

struct test_data
{
	struct l_genl_family *appeared_family;
	struct l_genl_family *vanished_family;

	unsigned int group_id;
	bool vanished_called;
};

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void notify_callback(struct l_genl_msg *msg, void *user_data)
{
}

static void family_appeared(void *user_data)
{
	struct test_data *data = user_data;

	data->group_id = l_genl_family_register(data->appeared_family,
						"notify",
						notify_callback,
						NULL,
						NULL);
}

static void family_vanished(void *user_data)
{
	struct test_data *data = user_data;

	data->vanished_called = true;
}

static bool prep_family_appeared(struct l_genl *genl,
					struct test_data *data)
{
	/*
	 * Set a family_appeared watch for the "nlctrl" family.
	 *
	 * The "nlctrl" generic netlink family always exists in the
	 * kernel so it is a suitable family to use for testing
	 * the family_appeared watch and related family registration
	 * operations.
	 */
	data->appeared_family = l_genl_family_new(genl, "nlctrl");

	return l_genl_family_set_watches(data->appeared_family,
						family_appeared, NULL,
						data, NULL);
}

static bool prep_family_vanished(struct l_genl *genl,
					struct test_data *data)
{
	/*
	 * Use a bogus family name to trigger the vanished watch to
	 * be called during the ELL event loop run.
	 */
	static const char BOGUS_GENL_NAME[] = "bogus_genl_family";

	data->vanished_family = l_genl_family_new(genl, BOGUS_GENL_NAME);
	return l_genl_family_set_watches(data->vanished_family,
						NULL, family_vanished,
						data, NULL);
}

static bool check_test_data(struct test_data *data)
{
    return data->group_id != 0 && data->vanished_called;
}

static void idle_callback(struct l_idle *idle, void *user_data)
{
	struct test_data *data = user_data;
	static int count = 0;

	/*
	 * Exit the event loop if the desired results have been
	 * obtained, but limit the number of iterations to prevent the
	 * loop from running indefinitely if the conditions for
	 * success are never reached.
	 *
	 * Allow the main loop to iterate at least four times to allow
	 * the generic netlink watches and family registration to be
	 * called and completed, respectively.
	 */
	if (check_test_data(data) || ++count > 3)
		l_main_quit();
}

static bool destroy_test_data(struct test_data *data)
{
	bool unregistered =
			l_genl_family_unregister(data->appeared_family,
							data->group_id);

	l_genl_family_unref(data->vanished_family);
	l_genl_family_unref(data->appeared_family);

	return unregistered;
}

int main(int argc, char *argv[])
{
	struct l_genl *genl;
	struct l_idle *idle;
	struct test_data data = { .group_id = 0 };

	if (!l_main_init())
		return -1;

	l_log_set_stderr();

	genl = l_genl_new_default();

	l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	assert(prep_family_appeared(genl, &data));
	assert(prep_family_vanished(genl, &data));

	idle = l_idle_create(idle_callback, &data, NULL);

	l_main_run();

	l_idle_remove(idle);

	assert(check_test_data(&data));
	assert(destroy_test_data(&data));

	l_genl_unref(genl);

	l_main_exit();

	return 0;
}
