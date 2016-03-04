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

#include <assert.h>

#include <ell/ell.h>

#define KEY1_STR "This key has exactly _32_ bytes!"
#define KEY1_LEN (strlen(KEY1_STR))
#define KEY2_STR "This key is longer than 32 bytes, just to be different."
#define KEY2_LEN (strlen(KEY2_STR))

static void test_unsupported(const void *data)
{
	struct l_key *key;

	key = l_key_new(42, KEY1_STR, KEY1_LEN);
	assert(!key);
}

static void test_user(const void *data)
{
	struct l_key *key;
	bool ok;
	char buf[64] = { 0 };
	size_t len;
	ssize_t reported_len;

	assert(KEY1_LEN < KEY2_LEN);
	assert(KEY2_LEN < sizeof(buf));

	key = l_key_new(L_KEY_RAW, KEY1_STR, KEY1_LEN);
	assert(key);

	reported_len = l_key_get_size(key);
	assert(reported_len == KEY1_LEN);

	len = KEY1_LEN - 1;
	ok = l_key_extract(key, buf, &len);
	assert(!ok);

	len = sizeof(buf);
	ok = l_key_extract(key, buf, &len);
	assert(ok);
	assert(len == KEY1_LEN);
	assert(!strcmp(buf, KEY1_STR));

	ok = l_key_update(key, KEY2_STR, KEY2_LEN);
	assert(ok);

	len = sizeof(buf);
	ok = l_key_extract(key, buf, &len);
	assert(ok);
	assert(len == KEY2_LEN);
	assert(!strcmp(buf, KEY2_STR));

	l_key_free(key);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	l_test_add("user key", test_user, NULL);

	return l_test_run();
}
