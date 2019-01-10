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

#include <stdbool.h>
#include <stdint.h>

#include "ecc.h"

struct l_ecc_curve;

struct l_ecc_point {
	uint64_t x[L_ECC_MAX_DIGITS];
	uint64_t y[L_ECC_MAX_DIGITS];
	const struct l_ecc_curve *curve;
};

struct l_ecc_curve {
	unsigned int ndigits;
	unsigned int group;
	struct l_ecc_point g;
	uint64_t p[L_ECC_MAX_DIGITS];
	uint64_t n[L_ECC_MAX_DIGITS];
	uint64_t b[L_ECC_MAX_DIGITS];
};

struct l_ecc_scalar {
	uint64_t c[L_ECC_MAX_DIGITS];
	const struct l_ecc_curve *curve;
};

void _ecc_be2native(uint64_t *dest, const uint64_t *bytes,
							unsigned int ndigits);

void _ecc_native2be(uint64_t *dest, const uint64_t *native,
							unsigned int ndigits);

void _vli_mod_inv(uint64_t *result, const uint64_t *input, const uint64_t *mod,
			unsigned int ndigits);

void _vli_mod_sub(uint64_t *result, const uint64_t *left, const uint64_t *right,
		const uint64_t *curve_prime, unsigned int ndigits);

void _vli_mod_add(uint64_t *result, const uint64_t *left, const uint64_t *right,
			const uint64_t *curve_prime, unsigned int ndigits);

void _vli_rshift1(uint64_t *vli, unsigned int ndigits);

void _vli_mod_mult_fast(uint64_t *result, const uint64_t *left,
		const uint64_t *right, const uint64_t *curve_prime,
		unsigned int ndigits);
void _vli_mod_square_fast(uint64_t *result, const uint64_t *left,
					const uint64_t *curve_prime,
					unsigned int ndigits);
void _vli_mod_exp(uint64_t *result, uint64_t *base, uint64_t *exp,
		const uint64_t *mod, unsigned int ndigits);

int _vli_cmp(const uint64_t *left, const uint64_t *right, unsigned int ndigits);

int _vli_legendre(uint64_t *val, const uint64_t *p, unsigned int ndigits);

bool _ecc_point_is_zero(const struct l_ecc_point *point);

void _ecc_calculate_p2(const struct l_ecc_curve *curve, uint64_t *p2);

bool _ecc_compute_y(const struct l_ecc_curve *curve, uint64_t *y, uint64_t *x);

void _ecc_point_mult(struct l_ecc_point *result,
			const struct l_ecc_point *point, const uint64_t *scalar,
			uint64_t *initial_z, const uint64_t *curve_prime);
void _ecc_point_add(struct l_ecc_point *ret, const struct l_ecc_point *p,
			const struct l_ecc_point *q,
			const uint64_t *curve_prime);
struct l_ecc_scalar *_ecc_constant_new(const struct l_ecc_curve *curve,
						const void *buf, size_t len);
