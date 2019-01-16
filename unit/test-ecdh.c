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
	static const uint8_t random_buf[] = { 0xba, 0xaf, 0x6d, 0x97, 0x71,
						0xe5, 0xda, 0xc9, 0x89, 0x6e,
						0x58, 0x18, 0x92, 0xf8, 0x55,
						0x4f, 0x29, 0xf0, 0xbd, 0x10,
						0xaf, 0x0e, 0x38, 0xb5, 0xe6,
						0x44, 0x56, 0x9d, 0x99, 0x2a,
						0x7f, 0xe2, 0x8d, 0x46, 0xb0,
						0x73, 0xcd, 0xd3, 0x6a, 0x7b,
						0xa6, 0xd3, 0xde, 0xbf, 0x38,
						0x96, 0xb7, 0xc3 };

	if (use_real_getrandom)
		return __real_l_getrandom(buf, len);

	if (len > sizeof(random_buf))
		return false;

	memcpy(buf, random_buf, len);

	return true;
}

/*
 * Tests the most basic case. Generate two full public keys and use to create
 * two identical shared secrets.
 */
static void test_basic(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_get_ike_group(19);

	struct l_ecc_scalar *private1;
	struct l_ecc_scalar *private2;

	struct l_ecc_point *public1;
	struct l_ecc_point *public2;

	struct l_ecc_scalar *secret1;
	struct l_ecc_scalar *secret2;

	assert(l_ecdh_generate_key_pair(curve, &private1, &public1));
	assert(l_ecdh_generate_key_pair(curve, &private2, &public2));

	assert(l_ecdh_generate_shared_secret(private1, public2, &secret1));
	assert(l_ecdh_generate_shared_secret(private2, public1, &secret2));

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
	const struct l_ecc_curve *curve = l_ecc_curve_get_ike_group(19);

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

	assert(l_ecdh_generate_shared_secret(a_secret, b_public, &a_shared));
	assert(l_ecdh_generate_shared_secret(b_secret, a_public, &b_shared));

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

/*
 * Test vector from RFC 5114 - 384-bit Random ECP Group
 */
static void test_vector_p384(const void *data)
{
	const struct l_ecc_curve *curve = l_ecc_curve_get_ike_group(20);

	uint64_t a_sec_buf[6] = { 0x86F05FEADB9376F1ull, 0xD706A90CBCB5DF29ull,
				0xD709EE7A7962A156ull, 0x5DFD8A7965571C48ull,
				0x44DD14E9FD126071ull, 0xD27335EA71664AF2ull };
	uint64_t a_pub_buf[12] = { 0x7D016FE27A8B8C66ull, 0x7E6A8EA9D1FD7742ull,
				0x0EE6B0403D627954ull, 0xE057AB62F82054D1ull,
				0xDA4C6D9074417D05ull, 0x793148F1787634D5ull,
				0xBACED214A1A1D128ull, 0x8F7A685923DE3B67ull,
				0x6B8F398BB29E4236ull, 0xC947392E94F4C3F0ull,
				0xF480F4FB4CD40504ull, 0xC6C41294331D23E6ull };
	uint64_t b_sec_buf[6] = { 0x2C4A6C768BCD94D2ull, 0x9BE52E00C194A413ull,
				0x1F80231121CCE3D3ull, 0x3B6125262C36A7DFull,
				0x9C0F00D456C2F702ull, 0x52D1791FDB4B70F8ull };
	uint64_t b_pub_buf[12] = { 0x223F12B5A1ABC120ull, 0x789D72A84865AE2Full,
				0x4ABC17647B6B9999ull, 0x5B36DB65915359B4ull,
				0xF74B8D4EFB708B3Dull, 0x5CD42AB9C41B5347ull,
				0xE035B0EDF36755DEull, 0x40BDE8723415A8ECull,
				0x0CECA16356CA9332ull, 0x8F6D5B348C0FA4D8ull,
				0xA3A8BFAC46B404BDull, 0xE171458FEAA939AAull };
	uint64_t ss_buf[6] = {
				0xDE159A58028ABC0Eull, 0x27AA8A4540884C37ull,
				0x59D926EB1B8456E4ull, 0xCAE53160137D904Cull,
				0x55981B110575E0A8ull, 0x5EA1FC4AF7256D20ull };
	struct l_ecc_scalar *a_shared;
	struct l_ecc_scalar *b_shared;

	struct l_ecc_scalar *a_secret = _ecc_constant_new(curve, a_sec_buf,
							sizeof(a_sec_buf));
	struct l_ecc_point *a_public = l_ecc_point_new(curve);

	struct l_ecc_scalar *b_secret = _ecc_constant_new(curve, b_sec_buf,
							sizeof(b_sec_buf));
	struct l_ecc_point *b_public = l_ecc_point_new(curve);

	memcpy(a_public->x, a_pub_buf, 48);
	memcpy(a_public->y, a_pub_buf + 6, 48);
	memcpy(b_public->x, b_pub_buf, 48);
	memcpy(b_public->y, b_pub_buf + 6, 48);

	use_real_getrandom = false;

	assert(l_ecdh_generate_shared_secret(a_secret, b_public, &a_shared));
	assert(l_ecdh_generate_shared_secret(b_secret, a_public, &b_shared));

	assert(!memcmp(a_shared->c, ss_buf, 48));
	assert(!memcmp(b_shared->c, ss_buf, 48));

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
	l_test_add("ECDH test vector P384", test_vector_p384, NULL);

	return l_test_run();
}
