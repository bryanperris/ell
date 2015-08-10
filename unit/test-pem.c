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

struct pem_test {
	const char *input;
	bool valid;
	const char *label;
	size_t decoded_size;
};

static const struct pem_test invalid_header1 = {
	.input = "-----BEGIN FOOBAR -----\r\n"
			"----END FOOBAR -----\r\n",
	.valid = false,
};

static const struct pem_test invalid_header2 = {
	.input = "-----BEGIN CERT  IFICATE-----\r\n"
			"-----END CERT  IFICATE----\r\n",
	.valid = false,
};

static const struct pem_test empty = {
	.input = "-----BEGIN CERTIFICATE-----\r\n"
			"-----END CERTIFICATE-----\r\n",
	.valid = false,
};

static const struct pem_test empty_label = {
	.input = "-----BEGIN -----\r\n"
			"U28/PHA+\r\n"
			"-----END -----\r\n",
	.valid = true,
	.label = "",
	.decoded_size = 6,
};

static void test_pem(const void *data)
{
	const struct pem_test *test = data;
	uint8_t *decoded;
	char *label;
	size_t decoded_size;

	decoded = l_pem_load_buffer((const uint8_t *) test->input,
					strlen(test->input), 0,
					&label, &decoded_size);

	if (!test->valid) {
		assert(!decoded);
		return;
	}

	assert(decoded);

	assert(!strcmp(test->label, label));
	assert(decoded_size == test->decoded_size);

	l_free(label);
	l_free(decoded);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("pem/invalid header/test 1", test_pem, &invalid_header1);
	l_test_add("pem/invalid header/test 2", test_pem, &invalid_header2);

	l_test_add("pem/empty", test_pem, &empty);

	l_test_add("pem/empty label", test_pem, &empty_label);

	return l_test_run();
}
