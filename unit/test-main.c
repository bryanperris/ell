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

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

static void timeout_handler(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
}

static void idle_handler(struct l_idle *idle, void *user_data)
{
	static int count = 0;

	if ((count % 1000000) == 0)
		l_info("Idling...");

	count += 1;
}

static void oneshot_handler(void *user_data)
{
	l_info("One-shot");
}

int main(int argc, char *argv[])
{
	struct l_timeout *timeout;
	struct l_signal *signal;
	struct l_idle *idle;
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	timeout = l_timeout_create(3, timeout_handler, NULL, NULL);

	idle = l_idle_create(idle_handler, NULL, NULL);

	l_log_set_stderr();

	l_debug_enable("*");

	l_debug("hello");

	l_idle_oneshot(oneshot_handler, NULL, NULL);

	l_main_run();

	l_timeout_remove(timeout);

	l_signal_remove(signal);

	l_idle_remove(idle);

	return 0;
}
