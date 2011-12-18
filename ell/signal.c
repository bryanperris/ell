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

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

#include "util.h"
#include "signal.h"
#include "private.h"

/**
 * SECTION:signal
 * @short_description: Unix signal support
 *
 * Unix signal support
 */

/**
 * l_signal:
 *
 * Opague object representing the signal.
 */
struct l_signal {
	int fd;
	sigset_t oldmask;
	l_signal_notify_cb_t callback;
	l_signal_destroy_cb_t destroy;
	void *user_data;
};

static void signal_destroy(void *user_data)
{
	struct l_signal *signal = user_data;

	close(signal->fd);

	if (signal->destroy)
		signal->destroy(signal->user_data);

	l_free(signal);
}

static void signal_callback(int fd, uint32_t events, void *user_data)
{
	struct l_signal *signal = user_data;
	struct signalfd_siginfo si;
	ssize_t result;

	result = read(signal->fd, &si, sizeof(si));
	if (result != sizeof(si))
		return;

	if (signal->callback)
		signal->callback(signal, si.ssi_signo, signal->user_data);
}

/**
 * l_signal_create:
 * @mask: set of signal mask
 * @callback: signal callback function
 * @user_data: user data provided to signal callback function
 * @destroy: destroy function for user data
 *
 * Create new signal callback handling for a given set of signals.
 *
 * From now on every signal from the set is reported via @callback function
 * indicating the Unix signal number that triggered it.
 *
 * Returns: a new allocated #l_signal object
 **/
LIB_EXPORT struct l_signal *l_signal_create(const sigset_t *mask,
			l_signal_notify_cb_t callback,
			void *user_data, l_signal_destroy_cb_t destroy)
{
	struct l_signal *signal;

	signal = l_new(struct l_signal, 1);

	signal->callback = callback;
	signal->destroy = destroy;
	signal->user_data = user_data;

	if (sigprocmask(SIG_BLOCK, mask, &signal->oldmask) < 0) {
		l_free(signal);
		return NULL;
	}

	signal->fd = signalfd(-1, mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (signal->fd < 0) {
		l_free(signal);
		return NULL;
	}

	watch_add(signal->fd, EPOLLIN, signal_callback,
					signal, signal_destroy);

	return signal;
}

/**
 * l_signal_remove:
 * @signal: signal object
 *
 * Remove signal handling.
 **/
LIB_EXPORT void l_signal_remove(struct l_signal *signal)
{
	if (!signal)
		return;

	watch_remove(signal->fd);
}
