/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>

#include "checksum.h"
#include "cipher.h"
#include "util.h"
#include "asn1-private.h"
#include "pkcs5.h"
#include "pkcs5-private.h"
#include "private.h"
#include "missing.h"

/* RFC8018 section 5.1 */
LIB_EXPORT bool l_pkcs5_pbkdf1(enum l_checksum_type type, const char *password,
				const uint8_t *salt, size_t salt_len,
				unsigned int iter_count,
				uint8_t *out_dk, size_t dk_len)
{
	size_t hash_len, t_len;
	uint8_t t[20 + salt_len + strlen(password)];
	struct l_checksum *checksum;

	switch (type) {
	case L_CHECKSUM_MD5:
		hash_len = 16;
		break;
	case L_CHECKSUM_SHA1:
		hash_len = 20;
		break;
	case L_CHECKSUM_NONE:
	case L_CHECKSUM_MD4:
	case L_CHECKSUM_SHA224:
	case L_CHECKSUM_SHA256:
	case L_CHECKSUM_SHA384:
	case L_CHECKSUM_SHA512:
		return false;
	default:
		return false;
	}

	if (dk_len > hash_len)
		return false;

	checksum = l_checksum_new(type);
	if (!checksum)
		return false;

	memcpy(t, password, strlen(password));
	memcpy(t + strlen(password), salt, salt_len);
	t_len = strlen(password) + salt_len;

	while (iter_count) {
		l_checksum_reset(checksum);

		if (!l_checksum_update(checksum, t, t_len))
			break;

		if (l_checksum_get_digest(checksum, t, hash_len) !=
				(ssize_t) hash_len)
			break;

		t_len = hash_len;
		iter_count--;
	}

	l_checksum_free(checksum);

	if (!iter_count)
		memcpy(out_dk, t, dk_len);

	explicit_bzero(t, sizeof(t));
	return !iter_count;
}

/* RFC8018 section 5.2 */
LIB_EXPORT bool l_pkcs5_pbkdf2(enum l_checksum_type type, const char *password,
				const uint8_t *salt, size_t salt_len,
				unsigned int iter_count,
				uint8_t *out_dk, size_t dk_len)
{
	size_t h_len;
	struct l_checksum *checksum;
	unsigned int i;

	switch (type) {
	case L_CHECKSUM_SHA1:
		h_len = 20;
		break;
	case L_CHECKSUM_SHA224:
		h_len = 28;
		break;
	case L_CHECKSUM_SHA256:
		h_len = 32;
		break;
	case L_CHECKSUM_SHA384:
		h_len = 48;
		break;
	case L_CHECKSUM_SHA512:
		h_len = 64;
		break;
	case L_CHECKSUM_NONE:
	case L_CHECKSUM_MD4:
	case L_CHECKSUM_MD5:
		return false;
	default:
		return false;
	}

	checksum = l_checksum_new_hmac(type, password, strlen(password));
	if (!checksum)
		return false;

	for (i = 1; dk_len; i++) {
		unsigned int j, k;
		uint8_t u[salt_len + 64];
		size_t u_len;
		size_t block_len = h_len;

		if (block_len > dk_len)
			block_len = dk_len;

		memset(out_dk, 0, block_len);

		memcpy(u, salt, salt_len);
		l_put_be32(i, u + salt_len);
		u_len = salt_len + 4;

		for (j = 0; j < iter_count; j++) {
			l_checksum_reset(checksum);

			if (!l_checksum_update(checksum, u, u_len))
				break;

			if (l_checksum_get_digest(checksum, u, h_len) !=
					(ssize_t) h_len)
				break;

			u_len = h_len;

			for (k = 0; k < block_len; k++)
				out_dk[k] ^= u[k];
		}

		if (j < iter_count)
			break;

		out_dk += block_len;
		dk_len -= block_len;
	}

	l_checksum_free(checksum);

	return !dk_len;
}

static struct asn1_oid pkcs5_pbkdf2_oid = {
	9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c }
};

static struct asn1_oid pkcs5_pbes2_oid = {
	9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d }
};

static const struct pkcs5_pbes1_encryption_oid {
	enum l_checksum_type checksum_type;
	enum l_cipher_type cipher_type;
	struct asn1_oid oid;
} pkcs5_pbes1_encryption_oids[] = {
	{ /* pbeWithMD5AndDES-CBC */
		L_CHECKSUM_MD5, L_CIPHER_DES_CBC,
		{ 9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x03 } },
	},
	{ /* pbeWithSHA1AndDES-CBC */
		L_CHECKSUM_SHA1, L_CIPHER_DES_CBC,
		{ 9, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0a } },
	},
	/* MD2- and RC2-based schemes 1, 4, 6 and 11 not supported */
};

static const struct pkcs5_digest_alg_oid {
	enum l_checksum_type type;
	struct asn1_oid oid;
} pkcs5_digest_alg_oids[] = {
	{ /* hmacWithSHA1 */
		L_CHECKSUM_SHA1,
		{ 8, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07 } },
	},
	{ /* hmacWithSHA224 */
		L_CHECKSUM_SHA224,
		{ 8, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x08 } },
	},
	{ /* hmacWithSHA256 */
		L_CHECKSUM_SHA256,
		{ 8, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09 } },
	},
	{ /* hmacWithSHA384 */
		L_CHECKSUM_SHA384,
		{ 8, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a } },
	},
	{ /* hmacWithSHA512 */
		L_CHECKSUM_SHA512,
		{ 8, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b } },
	},
	/* hmacWithSHA512-224 and hmacWithSHA512-256 not supported */
};

static const struct pkcs5_enc_alg_oid {
	enum l_cipher_type cipher_type;
	uint8_t key_size, iv_size;
	struct asn1_oid oid;
} pkcs5_enc_alg_oids[] = {
	{ /* desCBC */
		L_CIPHER_DES_CBC, 8, 8,
		{ 5, { 0x2b, 0x0e, 0x03, 0x02, 0x07 } },
	},
	{ /* des-EDE3-CBC */
		L_CIPHER_DES3_EDE_CBC, 24, 8,
		{ 8, { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07 } },
	},
	/* RC2/RC5-based schemes 2 and 9 not supported */
	{ /* aes128-CBC-PAD */
		L_CIPHER_AES_CBC, 16, 16,
		{ 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 } },
	},
	{ /* aes192-CBC-PAD */
		L_CIPHER_AES_CBC, 24, 16,
		{ 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16 } },
	},
	{ /* aes256-CBC-PAD */
		L_CIPHER_AES_CBC, 32, 16,
		{ 9, { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a } },
	},
};

static struct l_cipher *pkcs5_cipher_from_pbes2_params(
						const uint8_t *pbes2_params,
						size_t pbes2_params_len,
						const char *password)
{
	uint8_t tag;
	const uint8_t *kdf_sequence, *enc_sequence, *oid, *params,
		*salt, *iter_count_buf, *key_len_buf, *prf_sequence;
	size_t kdf_len, enc_len, params_len, salt_len, key_len, tmp_len;
	unsigned int i, iter_count, pos;
	enum l_checksum_type prf_alg = L_CHECKSUM_NONE;
	const struct pkcs5_enc_alg_oid *enc_scheme = NULL;
	uint8_t derived_key[64];
	struct l_cipher *cipher;

	/* RFC8018 section A.4 */

	kdf_sequence = asn1_der_find_elem(pbes2_params, pbes2_params_len, 0,
						&tag, &kdf_len);
	if (!kdf_sequence || tag != ASN1_ID_SEQUENCE)
		return NULL;

	enc_sequence = asn1_der_find_elem(pbes2_params, pbes2_params_len, 1,
						&tag, &enc_len);
	if (!enc_sequence || tag != ASN1_ID_SEQUENCE)
		return NULL;

	if (asn1_der_find_elem(pbes2_params, pbes2_params_len, 2,
						&tag, &tmp_len))
		return NULL;

	/* RFC8018 section A.2 */

	oid = asn1_der_find_elem(kdf_sequence, kdf_len, 0, &tag, &tmp_len);
	if (!oid || tag != ASN1_ID_OID)
		return NULL;

	if (!asn1_oid_eq(&pkcs5_pbkdf2_oid, tmp_len, oid))
		return NULL;

	params = asn1_der_find_elem(kdf_sequence, kdf_len, 1,
						&tag, &params_len);
	if (!params || tag != ASN1_ID_SEQUENCE)
		return NULL;

	if (asn1_der_find_elem(kdf_sequence, kdf_len, 2, &tag, &tmp_len))
		return NULL;

	salt = asn1_der_find_elem(params, params_len, 0, &tag, &salt_len);
	if (!salt || tag != ASN1_ID_OCTET_STRING ||
			salt_len < 1 || salt_len > 512)
		return NULL;

	iter_count_buf = asn1_der_find_elem(params, params_len, 1,
						&tag, &tmp_len);
	if (!iter_count_buf || tag != ASN1_ID_INTEGER ||
			tmp_len < 1 || tmp_len > 4)
		return NULL;

	iter_count = 0;

	while (tmp_len--)
		iter_count = (iter_count << 8) | *iter_count_buf++;

	pos = 2;
	key_len_buf = asn1_der_find_elem(params, params_len, pos,
						&tag, &tmp_len);
	if (key_len_buf && tag == ASN1_ID_INTEGER) {
		if (tmp_len != 1)
			return NULL;

		pos++;
		key_len = 0;

		while (tmp_len--)
			key_len = (key_len << 8) | *key_len_buf++;
	} else
		key_len = 0;

	prf_sequence = asn1_der_find_elem(params, params_len, pos,
						&tag, &tmp_len);
	if (prf_sequence && tag == ASN1_ID_SEQUENCE) {
		pos++;

		oid = asn1_der_find_elem(prf_sequence, tmp_len, 0,
						&tag, &tmp_len);
		if (!oid || tag != ASN1_ID_OID)
			return NULL;

		for (i = 0; i < L_ARRAY_SIZE(pkcs5_digest_alg_oids); i++)
			if (asn1_oid_eq(&pkcs5_digest_alg_oids[i].oid,
						tmp_len, oid))
				prf_alg = pkcs5_digest_alg_oids[i].type;

		if (prf_alg == L_CHECKSUM_NONE)
			return NULL;
	} else
		prf_alg = L_CHECKSUM_SHA1;

	oid = asn1_der_find_elem(enc_sequence, enc_len, 0, &tag, &tmp_len);
	if (!oid || tag != ASN1_ID_OID)
		return NULL;

	for (i = 0; i < L_ARRAY_SIZE(pkcs5_enc_alg_oids); i++) {
		if (asn1_oid_eq(&pkcs5_enc_alg_oids[i].oid, tmp_len, oid)) {
			enc_scheme = &pkcs5_enc_alg_oids[i];
			break;
		}
	}

	if (!enc_scheme)
		return NULL;

	params = asn1_der_find_elem(enc_sequence, enc_len, 1,
						&tag, &params_len);
	if (!params)
		return NULL;

	/* RFC8018 section B.2 */

	/*
	 * Since we don't support RC2/RC5, all our PKCS#5 ciphers only
	 * have an obligatory OCTET STRING IV parameter and a fixed key
	 * length.
	 */
	if (tag != ASN1_ID_OCTET_STRING || params_len != enc_scheme->iv_size)
		return NULL;

	if (key_len && enc_scheme->key_size != key_len)
		return NULL;

	key_len = enc_scheme->key_size;

	if (asn1_der_find_elem(enc_sequence, enc_len, 2, &tag, &tmp_len))
		return NULL;

	/* RFC8018 section 6.2 */

	if (!l_pkcs5_pbkdf2(prf_alg, password, salt, salt_len, iter_count,
				derived_key, key_len))
		return NULL;

	cipher = l_cipher_new(enc_scheme->cipher_type, derived_key, key_len);
	if (cipher && !l_cipher_set_iv(cipher, params, enc_scheme->iv_size)) {
		l_cipher_free(cipher);
		cipher = NULL;
	}

	explicit_bzero(derived_key, 16);
	return cipher;
}

struct l_cipher *pkcs5_cipher_from_alg_id(const uint8_t *id_asn1,
						size_t id_asn1_len,
						const char *password)
{
	uint8_t tag;
	const uint8_t *oid, *params, *salt, *iter_count_buf;
	size_t oid_len, params_len, tmp_len;
	unsigned int i, iter_count;
	const struct pkcs5_pbes1_encryption_oid *pbes1_scheme = NULL;
	uint8_t derived_key[16];
	struct l_cipher *cipher;

	oid = asn1_der_find_elem(id_asn1, id_asn1_len, 0, &tag, &oid_len);
	if (!oid || tag != ASN1_ID_OID)
		return NULL;

	params = asn1_der_find_elem(id_asn1, id_asn1_len, 1, &tag, &params_len);
	if (!params || tag != ASN1_ID_SEQUENCE)
		return NULL;

	if (asn1_der_find_elem(id_asn1, id_asn1_len, 2, &tag, &tmp_len))
		return NULL;

	if (asn1_oid_eq(&pkcs5_pbes2_oid, oid_len, oid))
		return pkcs5_cipher_from_pbes2_params(params, params_len,
							password);

	/* RFC8018 section A.3 */

	for (i = 0; i < L_ARRAY_SIZE(pkcs5_pbes1_encryption_oids); i++) {
		if (asn1_oid_eq(&pkcs5_pbes1_encryption_oids[i].oid,
					oid_len, oid)) {
			pbes1_scheme = &pkcs5_pbes1_encryption_oids[i];
			break;
		}
	}

	if (!pbes1_scheme)
		return NULL;

	salt = asn1_der_find_elem(params, params_len, 0, &tag, &tmp_len);
	if (!salt || tag != ASN1_ID_OCTET_STRING || tmp_len != 8)
		return NULL;

	iter_count_buf = asn1_der_find_elem(params, params_len, 1,
						&tag, &tmp_len);
	if (!iter_count_buf || tag != ASN1_ID_INTEGER ||
			tmp_len < 1 || tmp_len > 4)
		return NULL;

	iter_count = 0;

	while (tmp_len--)
		iter_count = (iter_count << 8) | *iter_count_buf++;

	if (asn1_der_find_elem(params, params_len, 2, &tag, &tmp_len))
		return NULL;

	/* RFC8018 section 6.1 */

	if (!l_pkcs5_pbkdf1(pbes1_scheme->checksum_type,
				password, salt, 8, iter_count, derived_key, 16))
		return NULL;

	cipher = l_cipher_new(pbes1_scheme->cipher_type, derived_key + 0, 8);
	if (cipher && !l_cipher_set_iv(cipher, derived_key + 8, 8)) {
		l_cipher_free(cipher);
		cipher = NULL;
	}

	explicit_bzero(derived_key, 16);
	return cipher;
}
