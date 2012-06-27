/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>

#include <ell/ell.h>
#include "ell/private.h"

struct signature_test {
	bool valid;
	const char *signature;
};

static struct signature_test sig_test1 = {
	.valid = false,
	.signature = "a",
};

static struct signature_test sig_test2 = {
	.valid = false,
	.signature = "a{vs}",
};

static void test_signature(const void *test_data)
{
	const struct signature_test *test = test_data;
	bool valid;

	valid = _dbus_valid_signature(test->signature);

	assert(valid == test->valid);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Signature Test 1", test_signature, &sig_test1);
	l_test_add("Signature Test 2", test_signature, &sig_test2);

	return l_test_run();
}
