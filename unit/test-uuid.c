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

#define _GNU_SOURCE
#include <assert.h>

#include <ell/ell.h>

static void test_v3(const void *data)
{
	uint8_t uuid[16];
	bool r;
	const char *dns = "01.org";
	uint8_t dns_expected[16] = {
		0xc4, 0x29, 0x62, 0xbe, 0xd8, 0xb6, 0x38, 0xf6,
		0xa9, 0xdb, 0xea, 0x5b, 0x75, 0xca, 0x39, 0x2d,
	};
	const char *url = "http://01.org";
	uint8_t url_expected[16] = {
		0x4d, 0x73, 0xd5, 0x05, 0xd0, 0xf1, 0x34, 0x69,
		0xb5, 0x0d, 0x27, 0x6d, 0x29, 0xac, 0x7e, 0x07,
	};
	const char *oid = "1.3.6.1";
	uint8_t oid_expected[16] = {
		0xdd, 0x1a, 0x1c, 0xef, 0x13, 0xd5, 0x36, 0x8a,
		0xad, 0x82, 0xec, 0xa7, 0x1a, 0xcd, 0x4c, 0xd1,
	};
	const char *x500 = "c=ca";
	uint8_t x500_expected[16] = {
		0x65, 0x8d, 0x30, 0x02, 0xdb, 0x6b, 0x30, 0x40,
		0xa1, 0xd1, 0x8d, 0xdd, 0x7d, 0x18, 0x9a, 0x4d,
	};

	r = l_uuid_v3(L_UUID_NAMESPACE_DNS, dns, strlen(dns), uuid);
	assert(r);
	assert(!memcmp(uuid, dns_expected, 16));
	assert(l_uuid_is_valid(uuid));
	assert(l_uuid_get_version(uuid) == L_UUID_VERSION_3_MD5);

	r = l_uuid_v3(L_UUID_NAMESPACE_URL, url, strlen(url), uuid);
	assert(r);
	assert(!memcmp(uuid, url_expected, 16));
	assert(l_uuid_is_valid(uuid));

	r = l_uuid_v3(L_UUID_NAMESPACE_OID, oid, strlen(oid), uuid);
	assert(r);
	assert(!memcmp(uuid, oid_expected, 16));
	assert(l_uuid_is_valid(uuid));

	r = l_uuid_v3(L_UUID_NAMESPACE_X500, x500, strlen(x500), uuid);
	assert(r);
	assert(!memcmp(uuid, x500_expected, 16));
	assert(l_uuid_is_valid(uuid));
}

static void test_v4(const void *data)
{
	uint8_t uuid1[16];
	uint8_t uuid2[16];
	bool r;

	r = l_uuid_v4(uuid1);
	assert(r);
	assert(l_uuid_is_valid(uuid1));
	assert(l_uuid_get_version(uuid1) == L_UUID_VERSION_4_RANDOM);

	r = l_uuid_v4(uuid2);
	assert(r);
	assert(l_uuid_is_valid(uuid2));

	assert(memcmp(uuid1, uuid2, 16));
}

static void test_v5(const void *data)
{
	uint8_t uuid[16];
	bool r;
	const char *dns = "01.org";
	uint8_t dns_expected[16] = {
		0x65, 0xfc, 0xc6, 0x97, 0x07, 0x76, 0x5b, 0xf9,
		0x85, 0x73, 0x72, 0xa5, 0x10, 0x80, 0xc7, 0xde,
	};
	const char *url = "http://01.org";
	uint8_t url_expected[16] = {
		0x4c, 0x98, 0xbc, 0x3c, 0x20, 0xa1, 0x55, 0xb0,
		0x9b, 0x7c, 0x42, 0xa4, 0xd0, 0x6e, 0xa6, 0xb6,
	};
	const char *oid = "1.3.6.1";
	uint8_t oid_expected[16] = {
		0x14, 0x47, 0xfa, 0x61, 0x52, 0x77, 0x5f, 0xef,
		0xa9, 0xb3, 0xfb, 0xc6, 0xe4, 0x4f, 0x4a, 0xf3,
	};
	const char *x500 = "c=ca";
	uint8_t x500_expected[16] = {
		0xcc, 0x95, 0x7d, 0xd1, 0xa9, 0x72, 0x53, 0x49,
		0x98, 0xcd, 0x87, 0x41, 0x90, 0x00, 0x27, 0x98,
	};

	r = l_uuid_v5(L_UUID_NAMESPACE_DNS, dns, strlen(dns), uuid);
	assert(r);
	assert(!memcmp(uuid, dns_expected, 16));
	assert(l_uuid_is_valid(uuid));
	assert(l_uuid_get_version(uuid) == L_UUID_VERSION_5_SHA1);

	r = l_uuid_v5(L_UUID_NAMESPACE_URL, url, strlen(url), uuid);
	assert(r);
	assert(!memcmp(uuid, url_expected, 16));
	assert(l_uuid_is_valid(uuid));

	r = l_uuid_v5(L_UUID_NAMESPACE_OID, oid, strlen(oid), uuid);
	assert(r);
	assert(!memcmp(uuid, oid_expected, 16));
	assert(l_uuid_is_valid(uuid));

	r = l_uuid_v5(L_UUID_NAMESPACE_X500, x500, strlen(x500), uuid);
	assert(r);
	assert(!memcmp(uuid, x500_expected, 16));
	assert(l_uuid_is_valid(uuid));
}

static void test_to_string(const void *data)
{
	uint8_t uuid[16];
	bool r;
	const char *dns = "01.org";
	const char *expected_uuid = "65fcc697-0776-5bf9-8573-72a51080c7de";
	char buf[64];

	r = l_uuid_v5(L_UUID_NAMESPACE_DNS, dns, strlen(dns), uuid);
	assert(r);

	r = l_uuid_to_string(uuid, buf, sizeof(buf));
	assert(r);

	assert(!strcmp(buf, expected_uuid));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("/uuid/v3", test_v3, NULL);

	if (l_getrandom_is_supported())
		l_test_add("/uuid/v4", test_v4, NULL);

	l_test_add("/uuid/v5", test_v5, NULL);
	l_test_add("/uuid/to string", test_to_string, NULL);

	return l_test_run();

}
