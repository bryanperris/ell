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

#define _GNU_SOURCE
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
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
	sigset_t mask;
	uint32_t signo;
	l_signal_notify_cb_t callback;
	l_signal_destroy_cb_t destroy;
	void *user_data;
};

static int masked_signals[_NSIG] = { };

static void signal_destroy(void *user_data)
{
	struct l_signal *signal = user_data;

	close(signal->fd);
	signal->fd = -1;

	if (signal->destroy)
		signal->destroy(signal->user_data);
}

static void signal_callback(int fd, uint32_t events, void *user_data)
{
	struct l_signal *signal = user_data;
	struct signalfd_siginfo si;
	ssize_t result;

	result = read(signal->fd, &si, sizeof(si));
	if (result != sizeof(si))
		return;

	if (signal->signo != si.ssi_signo)
		return;

	if (signal->callback)
		signal->callback(signal->user_data);
}

static int masked_signals_add(const sigset_t *mask)
{
	sigset_t set;
	int i, err, count = 0;

	sigemptyset(&set);

	for (i = 0; i < _NSIG; i++) {
		if (sigismember(mask, i)) {
			masked_signals[i]++;
			if (masked_signals[i] == 1) {
				sigaddset(&set, i);
				count++;
			}
		}
	}

	if (!count)
		return 0;

	err = sigprocmask(SIG_BLOCK, &set, NULL);
	if (err < 0) {
		for (i = 0; i < _NSIG; i++) {
			if (sigismember(mask, i))
				masked_signals[i]--;
		}
	}

	return err;
}

static int masked_signals_del(const sigset_t *mask)
{
	sigset_t set;
	int i, count = 0;

	sigemptyset(&set);

	for (i = 0; i < _NSIG; i++) {
		if (sigismember(mask, i)) {
			masked_signals[i]--;
			if (masked_signals[i] == 0) {
				sigaddset(&set, i);
				count++;
			}
		}
	}

	if (!count)
		return 0;

	return sigprocmask(SIG_UNBLOCK, &set, NULL);
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
 * Returns: a newly allocated #l_signal object
 **/
LIB_EXPORT struct l_signal *l_signal_create(uint32_t signo,
				l_signal_notify_cb_t callback,
				void *user_data, l_signal_destroy_cb_t destroy)
{
	struct l_signal *signal;
	sigset_t mask;
	int err;

	if (unlikely(signo <= 1 || signo >= _NSIG || !callback))
		return NULL;

	signal = l_new(struct l_signal, 1);

	sigemptyset(&mask);
	sigaddset(&mask, signo);

	signal->signo = signo;
	signal->callback = callback;
	signal->destroy = destroy;
	signal->user_data = user_data;
	memcpy(&signal->mask, &mask, sizeof(sigset_t));

	if (masked_signals_add(&mask) < 0) {
		l_free(signal);
		return NULL;
	}

	signal->fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (signal->fd < 0)
		goto error;

	err = watch_add(signal->fd, EPOLLIN, signal_callback,
			signal, signal_destroy);

	if (err < 0)
		goto error;

	return signal;

error:
	masked_signals_del(&mask);
	l_free(signal);
	return NULL;
}

/**
 * l_signal_remove:
 * @signal: signal object
 *
 * Remove signal handling.
 **/
LIB_EXPORT void l_signal_remove(struct l_signal *signal)
{
	if (unlikely(!signal))
		return;

	watch_remove(signal->fd);
	masked_signals_del(&signal->mask);

	l_free(signal);
}
