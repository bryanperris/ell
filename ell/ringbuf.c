/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2015  Intel Corporation. All rights reserved.
 *
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
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/param.h>

#include "private.h"
#include "ringbuf.h"

#ifndef MIN
#define MIN(x,y) ((x)<(y)?(x):(y))
#endif

/**
 * SECTION:ringbuf
 * @short_description: Ring Buffer support
 *
 * Ring Buffer support
 */

/**
 * l_ringbuf:
 *
 * Opague object representing the Ring Buffer.
 */
struct l_ringbuf {
	void *buffer;
	size_t size;
	size_t in;
	size_t out;
	l_ringbuf_tracing_func_t in_tracing;
	void *in_data;
};

#define RINGBUF_RESET 0

/* Find last (most siginificant) set bit */
static inline unsigned int fls(unsigned int x)
{
	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

/* Round up to nearest power of two */
static inline unsigned int align_power2(unsigned int u)
{
	return 1 << fls(u - 1);
}

/**
 * l_ringbuf_new:
 * @size: Minimum size of the ring buffer.
 *
 * Create a new ring buffer
 *
 * Returns: a newly allocated #l_ringbuf object
 **/
LIB_EXPORT struct l_ringbuf *l_ringbuf_new(size_t size)
{
	struct l_ringbuf *ringbuf;
	size_t real_size;

	if (size < 2 || size > UINT_MAX)
		return NULL;

	/* Find the next power of two for size */
	real_size = align_power2(size);

	ringbuf = l_new(struct l_ringbuf, 1);
	ringbuf->buffer = l_malloc(real_size);

	ringbuf->size = real_size;
	ringbuf->in = RINGBUF_RESET;
	ringbuf->out = RINGBUF_RESET;

	return ringbuf;
}

/**
 * l_ringbuf_free:
 * @ringbuf: Ring Buffer object
 *
 * Free the Ring Buffer object and associated memory.
 **/
LIB_EXPORT void l_ringbuf_free(struct l_ringbuf *ringbuf)
{
	if (!ringbuf)
		return;

	l_free(ringbuf->buffer);
	l_free(ringbuf);
}

/**
 * l_ringbuf_set_input_tracing:
 * @ringbuf: Ring Buffer object
 * @callback: Callback function
 * @user_data: user_data for the callback function
 *
 * Sets a tracing callback that will be called whenever input data is
 * processed.  @user_data will be passed to the callback.
 *
 * Returns: Whether setting the callback succeeded.
 **/
LIB_EXPORT bool l_ringbuf_set_input_tracing(struct l_ringbuf *ringbuf,
			l_ringbuf_tracing_func_t callback, void *user_data)
{
	if (!ringbuf)
		return false;

	ringbuf->in_tracing = callback;
	ringbuf->in_data = user_data;

	return true;
}

/**
 * l_ringbuf_capacity:
 * @ringbuf: Ring Buffer object
 *
 * Returns: Total capacity of the Ring Buffer.
 **/
LIB_EXPORT size_t l_ringbuf_capacity(struct l_ringbuf *ringbuf)
{
	if (!ringbuf)
		return 0;

	return ringbuf->size;
}

/**
 * l_ringbuf_len:
 * @ringbuf: Ring Buffer object
 *
 * Returns: Number of occupied bytes in the ring buffer
 **/
LIB_EXPORT size_t l_ringbuf_len(struct l_ringbuf *ringbuf)
{
	if (!ringbuf)
		return 0;

	return ringbuf->in - ringbuf->out;
}

/**
 * l_ringbuf_drain:
 * @ringbuf: Ring Buffer object
 * @count: Number of bytes to drain
 *
 * Drains a number of bytes specified.  The occupied bytes are discarded.
 *
 * Returns: Number of bytes drained
 **/
LIB_EXPORT size_t l_ringbuf_drain(struct l_ringbuf *ringbuf, size_t count)
{
	size_t len;

	if (!ringbuf)
		return 0;

	len = MIN(count, ringbuf->in - ringbuf->out);
	if (!len)
		return 0;

	ringbuf->out += len;

	if (ringbuf->out == ringbuf->in) {
		ringbuf->in = RINGBUF_RESET;
		ringbuf->out = RINGBUF_RESET;
	}

	return len;
}

/**
 * l_ringbuf_peek:
 * @ringbuf: Ring Buffer object
 * @offset: Offset into the ring buffer
 * @len_nowrap: Number of contiguous bytes starting from the current offset
 *
 * Peeks into the ring buffer at offset specified by @offset.  Since the ring
 * buffer can wrap around, the stored bytes might be in two contiguous
 * locations.  Typically offset of 0 is used first.  Then, if len_nowrap
 * is less than the length returned by l_ringbuf_len, the rest of the data
 * can be obtained by calling l_ringbuf_peek with offset set to len_nowrap.
 *
 * Returns: Pointer into ring buffer internal storage
 **/
LIB_EXPORT void *l_ringbuf_peek(struct l_ringbuf *ringbuf, size_t offset,
							size_t *len_nowrap)
{
	if (!ringbuf)
		return NULL;

	offset = (ringbuf->out + offset) & (ringbuf->size - 1);

	if (len_nowrap) {
		size_t len = ringbuf->in - ringbuf->out;
		*len_nowrap = MIN(len, ringbuf->size - offset);
	}

	return ringbuf->buffer + offset;
}

/**
 * l_ringbuf_write:
 * @ringbuf: Ring Buffer object
 * @fd: file descriptor to write to
 *
 * Tries to write the contents of the ring buffer out to a file descriptor
 *
 * Returns: Number of bytes written or -1 if the write failed.
 **/
LIB_EXPORT ssize_t l_ringbuf_write(struct l_ringbuf *ringbuf, int fd)
{
	size_t len, offset, end;
	struct iovec iov[2];
	ssize_t consumed;

	if (!ringbuf || fd < 0)
		return -1;

	/* Determine how much data is available */
	len = ringbuf->in - ringbuf->out;
	if (!len)
		return 0;

	/* Grab data from buffer starting at offset until the end */
	offset = ringbuf->out & (ringbuf->size - 1);
	end = MIN(len, ringbuf->size - offset);

	iov[0].iov_base = ringbuf->buffer + offset;
	iov[0].iov_len = end;

	/* Use second vector for remainder from the beginning */
	iov[1].iov_base = ringbuf->buffer;
	iov[1].iov_len = len - end;

	consumed = writev(fd, iov, 2);
	if (consumed < 0)
		return -1;

	ringbuf->out += consumed;

	if (ringbuf->out == ringbuf->in) {
		ringbuf->in = RINGBUF_RESET;
		ringbuf->out = RINGBUF_RESET;
	}

	return consumed;
}

/**
 * l_ringbuf_avail:
 * @ringbuf: Ring Buffer object
 *
 * Returns: Number of unoccupied bytes in the ring buffer
 **/
LIB_EXPORT size_t l_ringbuf_avail(struct l_ringbuf *ringbuf)
{
	if (!ringbuf)
		return 0;

	return ringbuf->size - ringbuf->in + ringbuf->out;
}

/**
 * l_ringbuf_printf:
 * @ringbuf: Ring Buffer object
 * @format: printf-style format string
 *
 * Writes contents to the ring buffer using printf-style semantics
 *
 * Returns: Number of bytes written
 **/
LIB_EXPORT int l_ringbuf_printf(struct l_ringbuf *ringbuf,
						const char *format, ...)
{
	va_list ap;
	int len;

	va_start(ap, format);
	len = l_ringbuf_vprintf(ringbuf, format, ap);
	va_end(ap);

	return len;
}

/**
 * l_ringbuf_printf:
 * @ringbuf: Ring Buffer object
 * @format: printf-style format string
 * @ap: variable argument list
 *
 * Writes contents to the ring buffer using printf-style semantics
 *
 * Returns: Number of bytes written
 **/
LIB_EXPORT int l_ringbuf_vprintf(struct l_ringbuf *ringbuf,
						const char *format, va_list ap)
{
	size_t avail, offset, end;
	char *str;
	int len;

	if (!ringbuf || !format)
		return -1;

	/* Determine maximum length available for string */
	avail = ringbuf->size - ringbuf->in + ringbuf->out;
	if (!avail)
		return -1;

	len = vasprintf(&str, format, ap);
	if (len < 0)
		return -1;

	if ((size_t) len > avail) {
		l_free(str);
		return -1;
	}

	/* Determine possible length of string before wrapping */
	offset = ringbuf->in & (ringbuf->size - 1);
	end = MIN((size_t) len, ringbuf->size - offset);
	memcpy(ringbuf->buffer + offset, str, end);

	if (ringbuf->in_tracing)
		ringbuf->in_tracing(ringbuf->buffer + offset, end,
							ringbuf->in_data);

	if (len - end > 0) {
		/* Put the remainder of string at the beginning */
		memcpy(ringbuf->buffer, str + end, len - end);

		if (ringbuf->in_tracing)
			ringbuf->in_tracing(ringbuf->buffer, len - end,
							ringbuf->in_data);
	}

	l_free(str);

	ringbuf->in += len;

	return len;
}

/**
 * l_ringbuf_read:
 * @ringbuf: Ring Buffer object
 * @fd: file descriptor to read from
 *
 * Reads data from a file descriptor given by @fd into the ring buffer.
 *
 * Returns: Number of bytes read or -1 if the read failed.
 **/
LIB_EXPORT ssize_t l_ringbuf_read(struct l_ringbuf *ringbuf, int fd)
{
	size_t avail, offset, end;
	struct iovec iov[2];
	ssize_t consumed;

	if (!ringbuf || fd < 0)
		return -1;

	/* Determine how much can actually be consumed */
	avail = ringbuf->size - ringbuf->in + ringbuf->out;
	if (!avail)
		return -1;

	/* Determine how much to consume before wrapping */
	offset = ringbuf->in & (ringbuf->size - 1);
	end = MIN(avail, ringbuf->size - offset);

	iov[0].iov_base = ringbuf->buffer + offset;
	iov[0].iov_len = end;

	/* Now put the remainder into the second vector */
	iov[1].iov_base = ringbuf->buffer;
	iov[1].iov_len = avail - end;

	consumed = readv(fd, iov, 2);
	if (consumed < 0)
		return -1;

	if (ringbuf->in_tracing) {
		size_t len = MIN((size_t) consumed, end);

		ringbuf->in_tracing(ringbuf->buffer + offset, len,
							ringbuf->in_data);

		if (consumed - len > 0)
			ringbuf->in_tracing(ringbuf->buffer, consumed - len,
							ringbuf->in_data);
	}

	ringbuf->in += consumed;

	return consumed;
}
