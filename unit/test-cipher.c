/*
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>

#include <ell/ell.h>

#define FIXED_STR  "The quick brown fox jumps over the lazy dog. " \
		   "Jackdaws love my big sphinx of quartz. "       \
		   "Pack my box with five dozen liquor jugs. "     \
		   "How razorback-jumping frogs can level six piqued gymnasts!"
#define FIXED_LEN  (strlen(FIXED_STR))

#define KEY_STR "This key has exactly _32_ bytes!"
#define KEY_LEN (strlen(KEY_STR))

static void test_unsupported(const void *data)
{
	struct l_cipher *cipher;

	cipher = l_cipher_new(42, KEY_STR, KEY_LEN);
	assert(!cipher);
}

static void test_aes(const void *data)
{
	struct l_cipher *cipher;
	char buf[256] = {};
	int r;

	cipher = l_cipher_new(L_CIPHER_AES, KEY_STR, KEY_LEN);
	assert(cipher);

	memcpy(buf, FIXED_STR, FIXED_LEN);

	l_cipher_encrypt(cipher, buf, buf, 256);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	l_cipher_decrypt(cipher, buf, buf, 256);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

static void test_arc4(const void *data)
{
	struct l_cipher *cipher;
	char buf[256] = {};
	int r;

	cipher = l_cipher_new(L_CIPHER_ARC4, KEY_STR, KEY_LEN);
	assert(cipher);

	memcpy(buf, FIXED_STR, FIXED_LEN);

	l_cipher_encrypt(cipher, buf, buf, 256);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	l_cipher_decrypt(cipher, buf, buf, 256);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	l_test_add("aes", test_aes, NULL);

	l_test_add("arc4", test_arc4, NULL);

	return l_test_run();
}
