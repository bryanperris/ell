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

#ifndef __ELL_CIPHER_H
#define __ELL_CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

struct l_cipher;

enum l_cipher_type {
	L_CIPHER_AES = 0,
	L_CIPHER_AES_CBC,
	L_CIPHER_ARC4,
	L_CIPHER_DES3_EDE_CBC,
};

struct l_cipher *l_cipher_new(enum l_cipher_type type,
				const void *key, size_t key_length);

void l_cipher_free(struct l_cipher *cipher);

bool l_cipher_encrypt(struct l_cipher *cipher,
			const void *in, void *out, size_t len);

bool l_cipher_decrypt(struct l_cipher *cipher,
			const void *in, void *out, size_t len);

bool l_cipher_set_iv(struct l_cipher *cipher, const uint8_t *iv,
			size_t iv_length);

struct l_asymmetric_cipher;

enum l_asymmetric_cipher_type {
	L_CIPHER_RSA_PKCS1_V1_5,
};

struct l_asymmetric_cipher *l_asymmetric_cipher_new(
					enum l_asymmetric_cipher_type type,
					const void *key, size_t key_length);

void l_asymmetric_cipher_free(struct l_asymmetric_cipher *cipher);

int l_asymmetric_cipher_get_key_size(struct l_asymmetric_cipher *cipher);

bool l_asymmetric_cipher_encrypt(struct l_asymmetric_cipher *cipher,
					const void *in, void *out,
					size_t len_in, size_t len_out);

bool l_asymmetric_cipher_decrypt(struct l_asymmetric_cipher *cipher,
					const void *in, void *out,
					size_t len_in, size_t len_out);

bool l_asymmetric_cipher_sign(struct l_asymmetric_cipher *cipher,
				const void *in, void *out,
				size_t len_in, size_t len_out);

bool l_asymmetric_cipher_verify(struct l_asymmetric_cipher *cipher,
				const void *in, void *out,
				size_t len_in, size_t len_out);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_CIPHER_H */
