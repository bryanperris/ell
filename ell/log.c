/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fnmatch.h>

#include "log.h"
#include "private.h"

/**
 * SECTION:log
 * @short_description: Logging framework
 *
 * Logging framework
 */

/**
 * l_debug_desc:
 *
 * Debug descriptor.
 */

static void log_null(int priority, const char *format, va_list ap)
{
}

static l_log_func_t log_func = log_null;

/**
 * l_log_set_handler:
 * @function: log handler function
 *
 * Sets the log handler function.
 **/
LIB_EXPORT void l_log_set_handler(l_log_func_t function)
{
	L_DEBUG_SYMBOL(__debug_intern, "");

	log_func = function;
}

/**
 * l_log:
 * @priority: priority level
 * @format: format string
 * @...: format arguments
 *
 * Log information.
 **/
LIB_EXPORT void l_log(int priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_func(priority, format, ap);
	va_end(ap);
}

/**
 * l_error:
 * @format: format string
 * @...: format arguments
 *
 **/

/**
 * l_warn:
 * @format: format string
 * @...: format arguments
 *
 **/

/**
 * l_info:
 * @format: format string
 * @...: format arguments
 *
 **/

/**
 * l_debug:
 * @format: format string
 * @...: format arguments
 **/

extern struct l_debug_desc __start___debug[];
extern struct l_debug_desc __stop___debug[];

/**
 * l_debug_enable:
 * @pattern: debug pattern
 *
 * Enable debug sections based on @pattern.
 **/
LIB_EXPORT void l_debug_enable(const char *pattern)
{
	struct l_debug_desc *desc;
	char *pattern_copy;

	if (!pattern)
		return;

	pattern_copy = strdupa(pattern);

	while (pattern_copy) {
		char *str = strsep(&pattern_copy, ":,");
		if (!str)
			break;

		for (desc = __start___debug; desc < __stop___debug; desc++) {
			if (!fnmatch(str, desc->file, 0))
				desc->flags |= L_DEBUG_FLAG_PRINT;
			if (!fnmatch(str, desc->func, 0))
				desc->flags |= L_DEBUG_FLAG_PRINT;
		}
	}
}

/**
 * l_debug_disable:
 *
 * Disable all debug sections.
 **/
LIB_EXPORT void l_debug_disable(void)
{
	struct l_debug_desc *desc;

	for (desc = __start___debug; desc < __stop___debug; desc++)
		desc->flags &= ~L_DEBUG_FLAG_PRINT;
}
