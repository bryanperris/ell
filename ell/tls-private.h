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

void tls10_prf(const uint8_t *secret, size_t secret_len,
		const char *label,
		const uint8_t *seed, size_t seed_len,
		uint8_t *out, size_t out_len);

void tls12_prf(enum l_checksum_type type, size_t hash_len,
		const uint8_t *secret, size_t secret_len,
		const char *label,
		const uint8_t *seed, size_t seed_len,
		uint8_t *out, size_t out_len);
