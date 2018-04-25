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

static int demo_init(void)
{
	l_info("External demo plugin init");
	l_debug("some debug info");

	return 0;
}

static void demo_exit(void)
{
	l_info("External demo plugin exit");
	l_debug("some more debug info");
}

L_PLUGIN_DEFINE_DEBUG(demo_plugin_desc, demo, "External demo plugin",
					VERSION, L_PLUGIN_PRIORITY_DEFAULT,
					demo_init, demo_exit, __debug)
