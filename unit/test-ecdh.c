/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2018 Intel Corporation. All rights reserved.
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

#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "ell/ecc-private.h"

static bool use_real_getrandom = true;

bool __wrap_l_getrandom(void *buf, size_t len);
bool __real_l_getrandom(void *buf, size_t len);

bool __wrap_l_getrandom(void *buf, size_t len)
{
	static const uint8_t random_buf[] = { 0x75, 0xc5, 0xfe, 0x3e, 0x53,
						0xcc, 0x33, 0x33, 0x64, 0xea,
						0xdd, 0xa1, 0xe6, 0x62, 0x7a,
						0xb1, 0x98, 0xa7, 0xa0, 0x1e,
						0xac, 0x4b, 0x1d, 0xb8, 0x71,
						0x5b, 0x1d, 0x00, 0x36, 0xd0,
						0x0f, 0xde };

	if (use_real_getrandom)
		return __real_l_getrandom(buf, len);

	memcpy(buf, random_buf, len);

	return true;
}

/*
 * Tests the most basic case. Generate two full public keys and use to create
 * two identical shared secrets.
 */
static void test_basic(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_get(19);

	struct l_ecc_scalar *private1;
	struct l_ecc_scalar *private2;

	struct l_ecc_point *public1;
	struct l_ecc_point *public2;

	struct l_ecc_scalar *secret1;
	struct l_ecc_scalar *secret2;

	assert(l_ecdh_generate_key_pair(curve, &private1, &public1));
	assert(l_ecdh_generate_key_pair(curve, &private2, &public2));

	assert(l_ecdh_generate_shared_secret(curve, private1, public2, &secret1));
	assert(l_ecdh_generate_shared_secret(curve, private2, public1, &secret2));

	assert(!memcmp(secret1->c, secret2->c, 32));

	l_ecc_scalar_free(private1);
	l_ecc_scalar_free(private2);
	l_ecc_point_free(public1);
	l_ecc_point_free(public2);
	l_ecc_scalar_free(secret1);
	l_ecc_scalar_free(secret2);
}

/*
 * Test vector from RFC 5114 - 256-bit Random ECP Group
 */
static void test_vector_p256(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_get(19);

	uint64_t a_sec_buf[4] = { 0x867B7291D507A3AFull, 0x3FAF432A5ABCE59Eull,
				0xE96A8E337A128499ull, 0x814264145F2F56F2ull };
	uint64_t a_pub_buf[8] = { 0x5E8D3B4BA83AEB15ull, 0x7165BE50BC42AE4Aull,
				0xC9B5A8D4160D09E9ull, 0x2AF502F3BE8952F2ull,
				0xC0F5015ECE5EFD85ull, 0x6795BD4BFF6E6DE3ull,
				0x8681A0F9872D79D5ull, 0xEB0FAF4CA986C4D3ull };

	uint64_t b_sec_buf[4] = { 0xEE1B593761CF7F41ull, 0x19CE6BCCAD562B8Eull,
				0xDB95A200CC0AB26Aull, 0x2CE1788EC197E096ull };
	uint64_t b_pub_buf[8] = { 0xB3AB0715F6CE51B0ull, 0xAE06AAEA279FA775ull,
				0x5346E8DE6C2C8646ull, 0xB120DE4AA3649279ull,
				0x85C34DDE5708B2B6ull, 0x3727027092A84113ull,
				0xD8EC685FA3F071D8ull, 0x9F1B7EECE20D7B5Eull };

	uint64_t ss_buf[4] = { 0x7F80D21C820C2788ull,
					0xF5811E9DC8EC8EEAull,
					0x93310412D19A08F1ull,
					0xDD0F5396219D1EA3ull };

	struct l_ecc_scalar *a_shared;
	struct l_ecc_scalar *b_shared;

	struct l_ecc_scalar *a_secret = _ecc_constant_new(curve, a_sec_buf,
							sizeof(a_sec_buf));
	struct l_ecc_point *a_public = l_ecc_point_new(curve);

	struct l_ecc_scalar *b_secret = _ecc_constant_new(curve, b_sec_buf,
							sizeof(b_sec_buf));
	struct l_ecc_point *b_public = l_ecc_point_new(curve);

	memcpy(a_public->x, a_pub_buf, 32);
	memcpy(a_public->y, a_pub_buf + 4, 32);
	memcpy(b_public->x, b_pub_buf, 32);
	memcpy(b_public->y, b_pub_buf + 4, 32);

	use_real_getrandom = false;

	assert(l_ecdh_generate_shared_secret(curve, a_secret, b_public,
						&a_shared));
	assert(l_ecdh_generate_shared_secret(curve, b_secret, a_public,
						&b_shared));

	assert(!memcmp(a_shared->c, ss_buf, 32));
	assert(!memcmp(b_shared->c, ss_buf, 32));

	use_real_getrandom = true;

	l_ecc_scalar_free(a_secret);
	l_ecc_scalar_free(b_secret);
	l_ecc_point_free(a_public);
	l_ecc_point_free(b_public);
	l_ecc_scalar_free(a_shared);
	l_ecc_scalar_free(b_shared);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (l_getrandom_is_supported())
		l_test_add("ECDH Basic", test_basic, NULL);

	l_test_add("ECDH test vector P256", test_vector_p256, NULL);

	return l_test_run();
}
