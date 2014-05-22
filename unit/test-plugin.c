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

#include <ell/ell.h>

static int builtin_init(void)
{
	l_info("Builtin demo plugin init");

	return 0;
}

static void builtin_exit(void)
{
	l_info("Builtin demo plugin exit");
}

L_PLUGIN_DEFINE(__builtin_desc, builtin_demo, "Builtin demo plugin", VERSION,
			L_PLUGIN_PRIORITY_DEFAULT, builtin_init, builtin_exit)

int main(int argc, char *argv[])
{
	l_log_set_stderr();

	l_plugin_add(&__builtin_desc, VERSION);

	l_plugin_load("unit/.libs/*.so", "demo_plugin_desc", VERSION);

	l_plugin_unload();

	return 0;
}
