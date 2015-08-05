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

struct base64_decode_test {
	const char *input;
	const uint8_t *output;
	size_t output_size;
};

static const uint8_t decode_output_1[] = {
	'p', 'l', 'e', 'a', 's', 'u', 'r', 'e', '.'
};

static const struct base64_decode_test decode_1 = {
	.input = "cGxlYXN1cmUu",
	.output = decode_output_1,
	.output_size = 9,
};

static const struct base64_decode_test decode_2 = {
	.input = "bGVhc3VyZS4=",
	.output = decode_output_1 + 1,
	.output_size = 8,
};

static const struct base64_decode_test decode_3 = {
	.input = "ZWFzdXJlLg==",
	.output = decode_output_1 + 2,
	.output_size = 7,
};

static const uint8_t decode_output_2[] = {
	'S', 'o', '?', '<', 'p', '>',
};

static const struct base64_decode_test decode_4 = {
	.input = "U28/PHA+",
	.output = decode_output_2,
	.output_size = 6,
};

static void test_base64_decode(const void *data)
{
	const struct base64_decode_test *test = data;
	uint8_t *decoded;
	size_t decoded_size;

	decoded = l_base64_decode(test->input, strlen(test->input),
								&decoded_size);
	assert(decoded);
	assert(decoded_size == test->output_size);
	assert(!memcmp(decoded, test->output, decoded_size));

	l_free(decoded);
}

struct base64_encode_test {
	const char *input;
	const char *output;
	int columns;
};

static const struct base64_encode_test encode_1 = {
	.input = "So?<p>",
	.columns = 4,
	.output = "U28/\nPHA+",
};

static const struct base64_encode_test encode_2 = {
	.input = "pleasure.",
	.columns = 0,
	.output = "cGxlYXN1cmUu",
};

static const struct base64_encode_test encode_3 = {
	.input = "leasure.",
	.columns = 0,
	.output = "bGVhc3VyZS4=",
};

static const struct base64_encode_test encode_4 = {
	.input = "easure.",
	.columns = 0,
	.output = "ZWFzdXJlLg==",
};

static void test_base64_encode(const void *data)
{
	const struct base64_encode_test *test = data;
	char *encoded;
	size_t encoded_size;

	encoded = l_base64_encode((uint8_t *)test->input, strlen(test->input),
					test->columns, &encoded_size);
	assert(encoded);
	assert(encoded_size == strlen(test->output));
	assert(!memcmp(encoded, test->output, encoded_size));

	l_free(encoded);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("base64/decode/test1", test_base64_decode, &decode_1);
	l_test_add("base64/decode/test2", test_base64_decode, &decode_2);
	l_test_add("base64/decode/test3", test_base64_decode, &decode_3);
	l_test_add("base64/decode/test4", test_base64_decode, &decode_4);

	l_test_add("base64/encode/test1", test_base64_encode, &encode_1);
	l_test_add("base64/encode/test2", test_base64_encode, &encode_2);
	l_test_add("base64/encode/test3", test_base64_encode, &encode_3);
	l_test_add("base64/encode/test4", test_base64_encode, &encode_4);

	return l_test_run();
}
