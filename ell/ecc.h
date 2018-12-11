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

#ifndef __ELL_ECC_H
#define __ELL_ECC_H

#ifdef __cplusplus
extern "C" {
#endif

#define L_ECC_MAX_DIGITS 4
#define L_ECC_SCALAR_MAX_BYTES		L_ECC_MAX_DIGITS * 8
#define L_ECC_POINT_MAX_BYTES		L_ECC_SCALAR_MAX_BYTES * 2

struct l_ecc_curve;
struct l_ecc_point;
struct l_ecc_scalar;

enum l_ecc_point_type {
	L_ECC_POINT_TYPE_COMPLIANT = 0x01,
	L_ECC_POINT_TYPE_COMPRESSED_BIT0 = 0x02,
	L_ECC_POINT_TYPE_COMPRESSED_BIT1 = 0x03,
	L_ECC_POINT_TYPE_FULL = 0x04,
};

const struct l_ecc_curve *l_ecc_curve_get(unsigned int group);

struct l_ecc_point *l_ecc_point_new(const struct l_ecc_curve *curve);
struct l_ecc_point *l_ecc_point_from_data(const struct l_ecc_curve *curve,
					enum l_ecc_point_type type,
					const void *data, size_t len);

ssize_t l_ecc_point_get_x(const struct l_ecc_point *p, void *x, size_t xlen);
ssize_t l_ecc_point_get_data(const struct l_ecc_point *p, void *buf, size_t len);
void l_ecc_point_free(struct l_ecc_point *p);

struct l_ecc_scalar *l_ecc_scalar_new(const struct l_ecc_curve *curve,
						void *buf, size_t len);
struct l_ecc_scalar *l_ecc_scalar_new_random(
					const struct l_ecc_curve *curve);
ssize_t l_ecc_scalar_get_data(const struct l_ecc_scalar *c, void *buf,
					size_t len);
void l_ecc_scalar_free(struct l_ecc_scalar *c);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_ECC_H */
