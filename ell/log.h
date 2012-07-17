/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __ELL_LOG_H
#define __ELL_LOG_H

#include <stdarg.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define L_LOG_ERR	3
#define L_LOG_WARNING	4
#define L_LOG_INFO	6
#define L_LOG_DEBUG	7

typedef void (*l_log_func_t) (int priority, const char *file, const char *line,
			const char *func, const char *format, va_list ap);

void l_log_set_ident(const char *ident);
void l_log_set_handler(l_log_func_t function);
void l_log_set_null(void);
void l_log_set_stderr(void);
void l_log_set_syslog(void);

void l_log_with_location(int priority, const char *file, const char *line,
				const char *func, const char *format, ...)
				__attribute__((format(printf, 5, 6)));

#define l_log(priority, format, args...)  l_log_with_location(priority, \
					__FILE__, L_STRINGIFY(__LINE__), \
					__func__, format "\n", ## args)

struct l_debug_desc {
	const char *file;
	const char *func;
#define L_DEBUG_FLAG_DEFAULT (0)
#define L_DEBUG_FLAG_PRINT   (1 << 0)
	unsigned int flags;
} __attribute__((aligned(8)));

#define L_DEBUG_SYMBOL(symbol, format, args...) do { \
	static struct l_debug_desc symbol \
	__attribute__((used, section("__debug"), aligned(8))) = { \
		.file = __FILE__, .func = __FUNCTION__, \
		.flags = L_DEBUG_FLAG_DEFAULT, \
	}; \
	if (symbol.flags & L_DEBUG_FLAG_PRINT) \
		l_log(L_LOG_DEBUG, "%s:%s() " format "\n", __FILE__, \
					__PRETTY_FUNCTION__ , ## args); \
} while (0)

void l_debug_enable(const char *pattern);
void l_debug_disable(void);

#define l_error(format, args...)  l_log(L_LOG_ERR, format "\n", ## args)
#define l_warn(format, args...)   l_log(L_LOG_WARNING, format "\n", ## args)
#define l_info(format, args...)   l_log(L_LOG_INFO, format "\n", ## args)
#define l_debug(format, args...)  L_DEBUG_SYMBOL(__debug_desc, format, ## args)

#ifdef __cplusplus
}
#endif

#endif /* __ELL_LOG_H */
