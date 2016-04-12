/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>

#include "private.h"
#include "util.h"
#include "key.h"

static int32_t keyring_base;

struct l_key {
	int type;
	int32_t serial;
};

static const char * const key_type_names[] = {
	[L_KEY_RAW] = "user",
	[L_KEY_ASYMMETRIC] = "asymmetric",
};

static long kernel_add_key(const char *type, const char *description,
				const void *payload, size_t len, int32_t keyring)
{
	return syscall(__NR_add_key, type, description, payload, len, keyring);
}

static long kernel_read_key(int32_t serial, const void *payload, size_t len)
{
	return syscall(__NR_keyctl, KEYCTL_READ, serial, payload, len);
}

static long kernel_update_key(int32_t serial, const void *payload, size_t len)
{
	return syscall(__NR_keyctl, KEYCTL_UPDATE, serial, payload, len);
}

static long kernel_revoke_key(int32_t serial)
{
	return syscall(__NR_keyctl, KEYCTL_REVOKE, serial);
}

static bool setup_keyring_base(void)
{
	keyring_base = kernel_add_key("keyring", "ell-keyring", 0, 0,
					KEY_SPEC_THREAD_KEYRING);

	if (keyring_base <= 0) {
		keyring_base = 0;
		return false;
	}

	return true;
}

LIB_EXPORT struct l_key *l_key_new(enum l_key_type type, const void *payload,
					size_t payload_length)
{
	struct l_key *key;
	char *description;

	if (unlikely(!payload))
		return NULL;

	if (unlikely((size_t)type >= L_ARRAY_SIZE(key_type_names)))
		return NULL;

	if (!keyring_base && !setup_keyring_base()) {
		return NULL;
	}

	key = l_new(struct l_key, 1);
	key->type = type;
	description = l_strdup_printf("ell-%p", key);
	key->serial = kernel_add_key(key_type_names[type], description, payload,
					payload_length, keyring_base);
	l_free(description);

	if (key->serial < 0) {
		l_free(key);
		key = NULL;
	}

	return key;
}

LIB_EXPORT void l_key_free(struct l_key *key)
{
	if (unlikely(!key))
		return;

	kernel_revoke_key(key->serial);

	l_free(key);
}

LIB_EXPORT bool l_key_update(struct l_key *key, const void *payload, size_t len)
{
	long error;

	if (unlikely(!key))
		return false;

	error = kernel_update_key(key->serial, payload, len);

	return error == 0;
}

LIB_EXPORT bool l_key_extract(struct l_key *key, void *payload, size_t *len)
{
	long keylen;

	if (unlikely(!key))
		return false;

	keylen = kernel_read_key(key->serial, payload, *len);

	if (keylen < 0 || (size_t)keylen > *len) {
		memset(payload, 0, *len);
		return false;
	}

	*len = keylen;
	return true;
}

LIB_EXPORT ssize_t l_key_get_size(struct l_key *key)
{
	return kernel_read_key(key->serial, NULL, 0);
}
