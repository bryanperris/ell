/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include "private.h"
#include "tls.h"
#include "checksum.h"
#include "tls-private.h"

LIB_EXPORT void l_tls_handle_rx(struct l_tls *tls, const uint8_t *data,
				size_t len)
{
	int need_len;
	int chunk_len;

	/* Reassemble TLSCiphertext structures from the received chunks */

	while (1) {
		/* Do we have a full header in tls->record_buf? */
		if (tls->record_buf_len >= 5) {
			need_len = 5 + l_get_be16(tls->record_buf + 3);

			/* Do we have a full structure? */
			if (tls->record_buf_len == need_len) {
				tls->record_buf_len = 0;
				need_len = 5;
			}

			if (!len)
				break;
		} else
			need_len = 5;

		/* Try to fill up tls->record_buf up to need_len */
		if (tls->record_buf_max_len < need_len) {
			tls->record_buf_max_len = need_len;
			tls->record_buf = l_realloc(tls->record_buf, need_len);
		}

		need_len -= tls->record_buf_len;
		chunk_len = need_len;
		if (len < (size_t) chunk_len)
			chunk_len = len;

		memcpy(tls->record_buf + tls->record_buf_len, data, chunk_len);
		tls->record_buf_len += chunk_len;
		data += chunk_len;
		len -= chunk_len;

		if (chunk_len < need_len)
			break;
	}
}
