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

#include <assert.h>

#include <ell/ell.h>

#define FIXED_STR  "The quick brown fox jumps over the lazy dog. " \
		   "Jackdaws love my big sphinx of quartz. "       \
		   "Pack my box with five dozen liquor jugs. "     \
		   "How razorback-jumping frogs can level six piqued gymnasts!"
#define FIXED_LEN  (strlen (FIXED_STR))

static void test_unsupported(const void *data)
{
	struct l_checksum *checksum;

	checksum = l_checksum_new(42);
	assert(!checksum);
}

static void test_md5(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[16];
	char *str;

	checksum = l_checksum_new(L_CHECKSUM_MD5);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	str = l_checksum_get_string(checksum);
	l_info("%s", str);
	l_free(str);

	l_checksum_free(checksum);
}

static void test_sha1(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[20];
	char *str;

	checksum = l_checksum_new(L_CHECKSUM_SHA1);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	str = l_checksum_get_string(checksum);
	l_info("%s", str);
	l_free(str);

	l_checksum_free(checksum);
}

static void test_sha256(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[32];
	char *str;

	checksum = l_checksum_new(L_CHECKSUM_SHA256);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	str = l_checksum_get_string(checksum);
	l_info("%s", str);
	l_free(str);

	l_checksum_free(checksum);
}

static void test_reset(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[16];
	char *str;

	checksum = l_checksum_new(L_CHECKSUM_MD5);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_reset(checksum);
	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_get_digest(checksum, digest, sizeof(digest));

	str = l_checksum_get_string(checksum);
	l_info("%s", str);
	l_free(str);

	l_checksum_free(checksum);
}

static void test_updatev(const void *data)
{
	struct l_checksum *checksum;
	unsigned char digest[20];
	struct iovec iov[2];
	char *str;
	char *str2;

	checksum = l_checksum_new(L_CHECKSUM_SHA1);
	assert(checksum);

	l_checksum_update(checksum, FIXED_STR, FIXED_LEN);
	l_checksum_get_digest(checksum, digest, sizeof(digest));
	str = l_checksum_get_string(checksum);

	iov[0].iov_base = FIXED_STR;
	iov[0].iov_len = FIXED_LEN / 2;

	iov[1].iov_base = FIXED_STR + FIXED_LEN / 2;
	iov[1].iov_len = FIXED_LEN - FIXED_LEN / 2;

	l_checksum_updatev(checksum, iov, 2);
	l_checksum_get_digest(checksum, digest, sizeof(digest));
	str2 = l_checksum_get_string(checksum);

	assert(!strcmp(str, str2));

	l_free(str);
	l_free(str2);

	l_checksum_free(checksum);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	l_test_add("md5-1", test_md5, NULL);

	l_test_add("sha1-1", test_sha1, NULL);

	l_test_add("sha256-1", test_sha256, NULL);

	l_test_add("checksum reset", test_reset, NULL);

	l_test_add("checksum updatev", test_updatev, NULL);

	return l_test_run();
}
