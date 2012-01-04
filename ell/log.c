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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <fnmatch.h>
#include <sys/socket.h>
#include <sys/un.h>

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
static const char *log_ident = "";
static int syslog_fd = -1;
static unsigned long syslog_pid;

/**
 * l_log_set_ident:
 * @ident: string identifier
 *
 * Sets the log identifier string.
 **/
LIB_EXPORT void l_log_set_ident(const char *ident)
{
	log_ident = ident;
}

/**
 * l_log_set_handler:
 * @function: log handler function
 *
 * Sets the log handler function.
 **/
LIB_EXPORT void l_log_set_handler(l_log_func_t function)
{
	L_DEBUG_SYMBOL(__debug_intern, "");

	if (syslog_fd > 0) {
		close(syslog_fd);
		syslog_fd = -1;
	}

	log_func = function;
}

static void log_syslog(int priority, const char *format, va_list ap)
{
	char header[64];
	struct msghdr msg;
	struct iovec iov[2];
	char *str;
	int len;

	len = vasprintf(&str, format, ap);
	if (len < 0)
		return;

	snprintf(header, sizeof(header), "<%i>%s[%lu]: ", priority,
				log_ident, (unsigned long) syslog_pid);

	iov[0].iov_base = header;
	iov[0].iov_len  = strlen(header);
	iov[1].iov_base = str;
	iov[1].iov_len  = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	sendmsg(syslog_fd, &msg, 0);
}

/**
 * l_log_set_syslog:
 * @enable: #true to enable and #false to disable
 *
 * Enable or disable syslog logging.
 **/
LIB_EXPORT bool l_log_set_syslog(bool enable)
{
	struct sockaddr_un addr;

	if (syslog_fd > 0) {
		if (!enable) {
			close(syslog_fd);
			syslog_fd = -1;
		}
		return true;
	} else if (!enable)
		return true;

	syslog_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (syslog_fd < 0)
		return false;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "/dev/log", sizeof(addr.sun_path));

	if (connect(syslog_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(syslog_fd);
		syslog_fd = -1;
		return false;
	}

	syslog_pid = getpid();

	log_func = log_syslog;

	return true;
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
