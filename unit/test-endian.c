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

static void big_endian(const void *data)
{
	uint8_t val[2] = { 0x12, 0x34 }, *ptr = val;

	assert(L_BE16_TO_CPU(L_GET_UNALIGNED((uint16_t *) ptr)) == 0x1234);
}

static void litte_endian(const void *data)
{
	uint8_t val[2] = { 0x34, 0x12 }, *ptr = val;

	assert(L_LE16_TO_CPU(L_GET_UNALIGNED((uint16_t *) ptr)) == 0x1234);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Big endian", big_endian, NULL);
	l_test_add("Little endian", litte_endian, NULL);

	return l_test_run();
}
