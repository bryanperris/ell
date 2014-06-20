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

#include <ell/ell.h>
#include <ell/genl.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void idle_callback(void *user_data)
{
	l_main_quit();
}

int main(int argc, char *argv[])
{
	struct l_genl *genl;

	l_log_set_stderr();

	genl = l_genl_new_default();

	l_genl_set_debug(genl, do_debug, "[GENL] ", NULL);

	l_idle_oneshot(idle_callback, NULL, NULL);

	l_main_run();

	l_genl_unref(genl);

	return 0;
}
