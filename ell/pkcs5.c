/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include "checksum.h"
#include "private.h"
#include "pkcs5.h"

/* RFC8018 section 5.1 */
LIB_EXPORT bool l_pkcs5_pbkdf1(enum l_checksum_type type, const char *password,
				const uint8_t *salt, size_t salt_len,
				unsigned int iter_count,
				uint8_t *out_dk, size_t dk_len)
{
	size_t hash_len, t_len;
	uint8_t t[20 + salt_len + strlen(password)];
	struct l_checksum *checksum;

	switch (type) {
	case L_CHECKSUM_MD5:
		hash_len = 16;
		break;
	case L_CHECKSUM_SHA1:
		hash_len = 20;
		break;
	default:
		return false;
	}

	if (dk_len > hash_len)
		return false;

	checksum = l_checksum_new(type);
	if (!checksum)
		return false;

	memcpy(t, password, strlen(password));
	memcpy(t + strlen(password), salt, salt_len);
	t_len = strlen(password) + salt_len;

	while (iter_count) {
		l_checksum_reset(checksum);

		if (!l_checksum_update(checksum, t, t_len))
			break;

		if (l_checksum_get_digest(checksum, t, hash_len) !=
				(ssize_t) hash_len)
			break;

		t_len = hash_len;
		iter_count--;
	}

	l_checksum_free(checksum);

	if (iter_count)
		return false;

	memcpy(out_dk, t, dk_len);
	return true;
}

/* RFC8018 section 5.2 */
LIB_EXPORT bool l_pkcs5_pbkdf2(enum l_checksum_type type, const char *password,
				const uint8_t *salt, size_t salt_len,
				unsigned int iter_count,
				uint8_t *out_dk, size_t dk_len)
{
	size_t h_len;
	struct l_checksum *checksum;
	unsigned int i;

	switch (type) {
	case L_CHECKSUM_SHA1:
		h_len = 20;
		break;
	case L_CHECKSUM_SHA224:
		h_len = 28;
		break;
	case L_CHECKSUM_SHA256:
		h_len = 32;
		break;
	case L_CHECKSUM_SHA384:
		h_len = 48;
		break;
	case L_CHECKSUM_SHA512:
		h_len = 64;
		break;
	default:
		return false;
	}

	checksum = l_checksum_new_hmac(type, password, strlen(password));
	if (!checksum)
		return false;

	for (i = 1; dk_len; i++) {
		unsigned int j, k;
		uint8_t u[salt_len + 64];
		size_t u_len;
		size_t block_len = h_len;

		if (block_len > dk_len)
			block_len = dk_len;

		memset(out_dk, 0, block_len);

		memcpy(u, salt, salt_len);
		l_put_be32(i, u + salt_len);
		u_len = salt_len + 4;

		for (j = 0; j < iter_count; j++) {
			l_checksum_reset(checksum);

			if (!l_checksum_update(checksum, u, u_len))
				break;

			if (l_checksum_get_digest(checksum, u, h_len) !=
					(ssize_t) h_len)
				break;

			u_len = h_len;

			for (k = 0; k < block_len; k++)
				out_dk[k] ^= u[k];
		}

		if (j < iter_count)
			break;

		out_dk += block_len;
		dk_len -= block_len;
	}

	l_checksum_free(checksum);

	return !dk_len;
}
