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

const struct tls_hello_extension tls_extensions[] = {
	{
		"Supported Elliptic Curves", "elliptic_curves", 10,
		tls_elliptic_curves_client_write,
		tls_elliptic_curves_client_handle,
		tls_elliptic_curves_client_absent,
		NULL, NULL, NULL,
	},
	{}
};
