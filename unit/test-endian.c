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

static void big_endian_16(const void *data)
{
	uint8_t val[2] = { 0x12, 0x34 }, *ptr = val;

	assert(l_get_be16(ptr) == 0x1234);
}

static void big_endian_32(const void *data)
{
	uint8_t val[4] = { 0x12, 0x34, 0x56, 0x78 }, *ptr = val;

	assert(l_get_be32(ptr) == 0x12345678);
}

static void big_endian_64(const void *data)
{
	uint8_t val[8] = { 0x12, 0x34, 0x56, 0x78,
				0x9a, 0xbc, 0xde, 0xf0 }, *ptr = val;

	assert(l_get_be64(ptr) == 0x123456789abcdef0);
}

static void little_endian_16(const void *data)
{
	uint8_t val[2] = { 0x34, 0x12 }, *ptr = val;

	assert(l_get_le16(ptr) == 0x1234);
}

static void little_endian_32(const void *data)
{
	uint8_t val[4] = { 0x78, 0x56, 0x34, 0x12 }, *ptr = val;

	assert(l_get_le32(ptr) == 0x12345678);
}

static void little_endian_64(const void *data)
{
	uint8_t val[8] = { 0xf0, 0xde, 0xbc, 0x9a,
				0x78, 0x56, 0x34, 0x12 }, *ptr = val;

	assert(l_get_le64(ptr) == 0x123456789abcdef0);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Big endian 16", big_endian_16, NULL);
	l_test_add("Big endian 32", big_endian_32, NULL);
	l_test_add("Big endian 64", big_endian_64, NULL);
	l_test_add("Little endian 16", little_endian_16, NULL);
	l_test_add("Little endian 32", little_endian_32, NULL);
	l_test_add("Little endian 64", little_endian_64, NULL);

	return l_test_run();
}
