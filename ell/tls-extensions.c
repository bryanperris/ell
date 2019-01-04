/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <errno.h>

#include "util.h"
#include "tls.h"
#include "cipher.h"
#include "checksum.h"
#include "cert.h"
#include "tls-private.h"

static const struct tls_named_curve tls_curve_pref[] = {
	{ "secp256r1", 23, 19, 64 },
	{ "secp384r1", 24, 20, 96 },
};

/* RFC 8422, Section 5.1 */
static ssize_t tls_elliptic_curves_client_write(struct l_tls *tls,
						uint8_t *buf, size_t len)
{
	uint8_t *ptr = buf;
	unsigned int i;

	if (len < 2 + L_ARRAY_SIZE(tls_curve_pref) * 2)
		return -ENOMEM;

	l_put_be16(L_ARRAY_SIZE(tls_curve_pref) * 2, ptr);
	ptr += 2;

	for (i = 0; i < L_ARRAY_SIZE(tls_curve_pref); i++) {
		l_put_be16(tls_curve_pref[i].id, ptr);
		ptr += 2;
	}

	return ptr - buf;
}

static bool tls_elliptic_curves_client_handle(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	if (len < 2)
		return false;

	if (l_get_be16(buf) != len - 2 || (len & 1))
		return false;

	buf += 2;
	len -= 2;

	while (len) {
		unsigned int i;
		uint16_t id;

		id = l_get_be16(buf);
		buf += 2;
		len -= 2;

		for (i = 0; i < L_ARRAY_SIZE(tls_curve_pref); i++)
			if (tls_curve_pref[i].id == id) {
				tls->negotiated_curve = &tls_curve_pref[i];
				TLS_DEBUG("Negotiated %s",
						tls_curve_pref[i].name);
				return true;
			}
	}

	TLS_DEBUG("non-fatal: No common supported elliptic curves");
	return true;
}

static bool tls_elliptic_curves_client_absent(struct l_tls *tls)
{
	tls->negotiated_curve = &tls_curve_pref[0];
	return true;
}

static bool tls_ec_point_formats_client_handle(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	if (len < 2)
		return false;

	if (buf[0] != len - 1)
		return false;

	if (!memchr(buf + 1, 0, len - 1)) {
		TLS_DEBUG("Uncompressed point format missing");
		return false;
	}

	return true;
}

/*
 * For compatibility with clients respond to a valid Client Hello Supported
 * Point Formats extension with the hardcoded confirmation that we do
 * support the single valid point format.  As a client we never send this
 * extension so we never have to handle a server response to it either.
 */
static ssize_t tls_ec_point_formats_server_write(struct l_tls *tls,
						uint8_t *buf, size_t len)
{
	if (len < 2)
		return -ENOMEM;

	buf[0] = 0x01;	/* ec_point_format_list length */
	buf[1] = 0x00;	/* uncompressed */
	return 2;
}

const struct tls_hello_extension tls_extensions[] = {
	{
		"Supported Elliptic Curves", "elliptic_curves", 10,
		tls_elliptic_curves_client_write,
		tls_elliptic_curves_client_handle,
		tls_elliptic_curves_client_absent,
		NULL, NULL, NULL,
	},
	{
		"Supported Point Formats", "ec_point_formats", 11,
		NULL,
		tls_ec_point_formats_client_handle,
		NULL,
		tls_ec_point_formats_server_write,
		NULL, NULL,
	},
	{}
};
