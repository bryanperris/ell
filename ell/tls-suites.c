/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "util.h"
#include "tls.h"
#include "cipher.h"
#include "checksum.h"
#include "cert.h"
#include "tls-private.h"
#include "key.h"
#include "random.h"

static bool tls_rsa_validate_cert_key(struct l_cert *cert)
{
	return l_cert_get_pubkey_type(cert) == L_CERT_KEY_RSA;
}

static bool tls_send_rsa_client_key_xchg(struct l_tls *tls)
{
	uint8_t buf[1024 + 32];
	uint8_t *ptr = buf + TLS_HANDSHAKE_HEADER_SIZE;
	uint8_t pre_master_secret[48];
	ssize_t bytes_encrypted;

	if (!tls->peer_pubkey) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Peer public key not received");

		return false;
	}

	/* Must match the version in tls_send_client_hello */
	pre_master_secret[0] = (uint8_t) (TLS_VERSION >> 8);
	pre_master_secret[1] = (uint8_t) (TLS_VERSION >> 0);

	l_getrandom(pre_master_secret + 2, 46);

	if (tls->peer_pubkey_size + 32 > (int) sizeof(buf)) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Peer public key too big: %zi",
				tls->peer_pubkey_size);

		return false;
	}

	l_put_be16(tls->peer_pubkey_size, ptr);
	bytes_encrypted = l_key_encrypt(tls->peer_pubkey,
					L_KEY_RSA_PKCS1_V1_5, L_CHECKSUM_NONE,
					pre_master_secret, ptr + 2, 48,
					tls->peer_pubkey_size);
	ptr += tls->peer_pubkey_size + 2;

	if (bytes_encrypted != (ssize_t) tls->peer_pubkey_size) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
				"Encrypting PreMasterSecret failed: %s",
				strerror(-bytes_encrypted));

		return false;
	}

	tls_tx_handshake(tls, TLS_CLIENT_KEY_EXCHANGE, buf, ptr - buf);

	tls_generate_master_secret(tls, pre_master_secret, 48);
	memset(pre_master_secret, 0, 48);

	return true;
}

static void tls_handle_rsa_client_key_xchg(struct l_tls *tls,
						const uint8_t *buf, size_t len)
{
	uint8_t pre_master_secret[48], random_secret[46];
	ssize_t bytes_decrypted;

	if (!tls->priv_key || !tls->priv_key_size) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, TLS_ALERT_BAD_CERT,
				"No private key");

		return;
	}

	if (len != tls->priv_key_size + 2) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"ClientKeyExchange len %zi not %zi", len,
				tls->priv_key_size + 2);

		return;
	}

	len = l_get_be16(buf);

	if (len != tls->priv_key_size) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"EncryptedPreMasterSecret len %zi not %zi",
				len, tls->priv_key_size);

		return;
	}

	bytes_decrypted = l_key_decrypt(tls->priv_key, L_KEY_RSA_PKCS1_V1_5,
					L_CHECKSUM_NONE, buf + 2,
					pre_master_secret, tls->priv_key_size,
					48);

	/*
	 * Assume correct premaster secret client version which according
	 * to the TLS1.2 spec is unlikely in client implementations SSLv3
	 * and prior.  Spec suggests either not supporting them or adding
	 * a configurable override for <= SSLv3 clients.  For now we have
	 * no need to support them.
	 *
	 * On any decode error randomise the Pre Master Secret as per the
	 * countermeasures in 7.4.7.1 and don't generate any alerts.
	 */
	l_getrandom(random_secret, 46);

	pre_master_secret[0] = tls->client_version >> 8;
	pre_master_secret[1] = tls->client_version >> 0;

	if (bytes_decrypted != 48) {
		memcpy(pre_master_secret + 2, random_secret, 46);

		TLS_DEBUG("Error decrypting PreMasterSecret: %s",
				strerror(-bytes_decrypted));
	}

	tls_generate_master_secret(tls, pre_master_secret, 48);
	memset(pre_master_secret, 0, 48);
	memset(random_secret, 0, 46);
}

static ssize_t tls_rsa_sign(struct l_tls *tls, uint8_t *out, size_t len,
				tls_get_hash_t get_hash)
{
	ssize_t result = -EMSGSIZE;
	enum l_checksum_type sign_checksum_type;
	uint8_t sign_input[HANDSHAKE_HASH_MAX_SIZE + 36];
	size_t sign_input_len;
	uint8_t *ptr = out;

	if (!tls->priv_key || !tls->priv_key_size) {
		TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, TLS_ALERT_BAD_CERT,
				"No private key loaded");

		return -ENOKEY;
	}

	if (tls->negotiated_version >= L_TLS_V12) {
		const struct tls_hash_algorithm *hash_type =
			&tls_handshake_hash_data[tls->signature_hash];

		/* Build the DigitallySigned struct */
		if (len < 2)	/* Is there space for the algorithm IDs */
			goto error;

		get_hash(tls, hash_type->tls_id, sign_input, NULL, NULL);
		sign_checksum_type = hash_type->l_id;
		sign_input_len = hash_type->length;

		*ptr++ = hash_type->tls_id;
		*ptr++ = 1;	/* RSA_sign */
		len -= 2;
	} else {
		get_hash(tls, 1, sign_input + 0, NULL, NULL);	/* MD5 */
		get_hash(tls, 2, sign_input + 16, NULL, NULL);	/* SHA1 */
		sign_checksum_type = L_CHECKSUM_NONE;
		sign_input_len = 36;
	}

	if (len < tls->priv_key_size + 2)
		goto error;

	l_put_be16(tls->priv_key_size, ptr);
	result = l_key_sign(tls->priv_key, L_KEY_RSA_PKCS1_V1_5,
				sign_checksum_type, sign_input, ptr + 2,
				sign_input_len, tls->priv_key_size);
	ptr += tls->priv_key_size + 2;

	if (result == (ssize_t) tls->priv_key_size)
		return ptr - out; /* Success */

error:
	TLS_DISCONNECT(TLS_ALERT_INTERNAL_ERROR, 0,
			"Signing the hash failed: %s",
			strerror(-result));
	return result;
}

static bool tls_rsa_verify(struct l_tls *tls, const uint8_t *in, size_t len,
				tls_get_hash_t get_hash)
{
	enum l_checksum_type hash_type;
	uint8_t expected[HANDSHAKE_HASH_MAX_SIZE + 36];
	size_t expected_len;
	unsigned int offset;
	bool success;

	/* 2 bytes for SignatureAndHashAlgorithm if version >= 1.2 */
	offset = 2;
	if (tls->negotiated_version < L_TLS_V12)
		offset = 0;

	if (len < offset + 2 ||
			(size_t) l_get_be16(in + offset) + offset + 2 != len) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0, "Signature msg too "
				"short (%zi) or signature length doesn't match",
				len);

		return false;
	}

	/* Only the default hash type supported */
	if (len != offset + 2 + tls->peer_pubkey_size) {
		TLS_DISCONNECT(TLS_ALERT_DECODE_ERROR, 0,
				"Signature length %zi not equal %zi", len,
				offset + 2 + tls->peer_pubkey_size);

		return false;
	}

	if (tls->negotiated_version >= L_TLS_V12) {
		/* Only RSA supported */
		if (in[1] != 1 /* RSA_sign */) {
			TLS_DISCONNECT(TLS_ALERT_DECRYPT_ERROR, 0,
					"Unknown signature algorithm %i",
					in[1]);

			return false;
		}

		if (!get_hash(tls, in[0], expected, &expected_len,
				&hash_type)) {
			TLS_DISCONNECT(TLS_ALERT_DECRYPT_ERROR, 0,
					"Unknown hash type %i", in[0]);

			return false;
		}

		/*
		 * Note: Next we let the l_key_verify's underlying kernel
		 * operation prepend the OID to the hash to build the
		 * DigestInfo struct.  However according to 4.7 we need to
		 * support at least two forms of the signed content in the
		 * verification:
		 *  - DigestInfo with NULL AlgorithmIdentifier.parameters,
		 *  - DigestInfo with empty AlgorithmIdentifier.parameters,
		 *
		 * while the kernel only understands the former encoding.
		 * Note PKCS#1 versions 2.0 and later section A.2.4 do
		 * mandate NULL AlgorithmIdentifier.parameters.
		 *
		 * Additionally PKCS#1 v1.5 said BER is used in place of DER
		 * for DigestInfo encoding which adds more ambiguity in the
		 * encoding.
		 */
	} else {
		get_hash(tls, 1, expected + 0, NULL, NULL);	/* MD5 */
		get_hash(tls, 2, expected + 16, NULL, NULL);	/* SHA1 */
		expected_len = 36;
		hash_type = L_CHECKSUM_NONE;

		/*
		 * Note: Within the RSA padding for signatures PKCS#1 1.5
		 * allows the block format to be either 0 or 1, while PKCS#1
		 * v2.0+ mandates block type 1 making the signatures
		 * unambiguous.  TLS 1.0 doesn't additionally specify which
		 * block type is to be used (TLS 1.2 does) meaning that both
		 * PKCS#1 v1.5 types are allowed.  The l_key_verify's
		 * underlying kernel implementation only accepts block type
		 * 1.  If this ever becomes an issue we'd need to go back to
		 * using L_KEY_RSA_RAW and our own PKCS#1 v1.5 verify logic.
		 */
	}

	success = l_key_verify(tls->peer_pubkey, L_KEY_RSA_PKCS1_V1_5,
				hash_type, expected, in + offset + 2,
				expected_len, tls->peer_pubkey_size);

	if (!success)
		TLS_DISCONNECT(TLS_ALERT_DECRYPT_ERROR, 0,
				"Peer signature verification failed");
	else
		TLS_DEBUG("Peer signature verified");

	return success;
}

static struct tls_key_exchange_algorithm tls_rsa = {
	.id = 1, /* RSA_sign */
	.certificate_check = true,
	.validate_cert_key_type = tls_rsa_validate_cert_key,
	.send_client_key_exchange = tls_send_rsa_client_key_xchg,
	.handle_client_key_exchange = tls_handle_rsa_client_key_xchg,
	.sign = tls_rsa_sign,
	.verify = tls_rsa_verify,
};

static struct tls_bulk_encryption_algorithm tls_rc4 = {
	.cipher_type = TLS_CIPHER_STREAM,
	.l_id = L_CIPHER_ARC4,
	.key_length = 16,
}, tls_aes128 = {
	.cipher_type = TLS_CIPHER_BLOCK,
	.l_id = L_CIPHER_AES_CBC,
	.key_length = 16,
	.iv_length = 16,
	.block_length = 16,
}, tls_aes256 = {
	.cipher_type = TLS_CIPHER_BLOCK,
	.l_id = L_CIPHER_AES_CBC,
	.key_length = 32,
	.iv_length = 16,
	.block_length = 16,
}, tls_3des_ede = {
	.cipher_type = TLS_CIPHER_BLOCK,
	.l_id = L_CIPHER_DES3_EDE_CBC,
	.key_length = 24,
	.iv_length = 8,
	.block_length = 8,
}, tls_aes128_gcm = {
	.cipher_type = TLS_CIPHER_AEAD,
	.l_aead_id = L_AEAD_CIPHER_AES_GCM,
	.key_length = 16,
	.iv_length = 12,
	.fixed_iv_length = 4,
	.auth_tag_length = 16,
}, tls_aes256_gcm = {
	.cipher_type = TLS_CIPHER_AEAD,
	.l_aead_id = L_AEAD_CIPHER_AES_GCM,
	.key_length = 32,
	.iv_length = 12,
	.fixed_iv_length = 4,
	.auth_tag_length = 16,
};

static struct tls_mac_algorithm tls_md5 = {
	.id = 1,
	.hmac_type = L_CHECKSUM_MD5,
	.mac_length = 16,
}, tls_sha = {
	.id = 2,
	.hmac_type = L_CHECKSUM_SHA1,
	.mac_length = 20,
}, tls_sha256 = {
	.id = 4,
	.hmac_type = L_CHECKSUM_SHA256,
	.mac_length = 32,
};

static struct tls_cipher_suite tls_rsa_with_rc4_128_md5 = {
	.id = { 0x00, 0x04 },
	.name = "TLS_RSA_WITH_RC4_128_MD5",
	.verify_data_length = 12,
	.encryption = &tls_rc4,
	.mac = &tls_md5,
	.key_xchg = &tls_rsa,
}, tls_rsa_with_rc4_128_sha = {
	.id = { 0x00, 0x05 },
	.name = "TLS_RSA_WITH_RC4_128_SHA",
	.verify_data_length = 12,
	.encryption = &tls_rc4,
	.mac = &tls_sha,
	.key_xchg = &tls_rsa,
}, tls_rsa_with_3des_ede_cbc_sha = {
	.id = { 0x00, 0x0a },
	.name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
	.verify_data_length = 12,
	.encryption = &tls_3des_ede,
	.mac = &tls_sha,
	.key_xchg = &tls_rsa,
}, tls_rsa_with_aes_128_cbc_sha = {
	.id = { 0x00, 0x2f },
	.name = "TLS_RSA_WITH_AES_128_CBC_SHA",
	.verify_data_length = 12,
	.encryption = &tls_aes128,
	.mac = &tls_sha,
	.key_xchg = &tls_rsa,
}, tls_rsa_with_aes_256_cbc_sha = {
	.id = { 0x00, 0x35 },
	.name = "TLS_RSA_WITH_AES_256_CBC_SHA",
	.verify_data_length = 12,
	.encryption = &tls_aes256,
	.mac = &tls_sha,
	.key_xchg = &tls_rsa,
}, tls_rsa_with_aes_128_cbc_sha256 = {
	.id = { 0x00, 0x3c },
	.name = "TLS_RSA_WITH_AES_128_CBC_SHA256",
	.verify_data_length = 12,
	.encryption = &tls_aes128,
	.mac = &tls_sha256,
	.key_xchg = &tls_rsa,
}, tls_rsa_with_aes_256_cbc_sha256 = {
	.id = { 0x00, 0x3d },
	.name = "TLS_RSA_WITH_AES_256_CBC_SHA256",
	.verify_data_length = 12,
	.encryption = &tls_aes256,
	.mac = &tls_sha256,
	.key_xchg = &tls_rsa,
}, tls_rsa_with_aes_128_gcm_sha256 = {
	.id = { 0x00, 0x9c },
	.name = "TLS_RSA_WITH_AES_128_GCM_SHA256",
	.verify_data_length = 12,
	.encryption = &tls_aes128_gcm,
	.key_xchg = &tls_rsa,
}, tls_rsa_with_aes_256_gcm_sha384 = {
	.id = { 0x00, 0x9d },
	.name = "TLS_RSA_WITH_AES_256_GCM_SHA384",
	.verify_data_length = 12,
	.encryption = &tls_aes256_gcm,
	.prf_hmac = L_CHECKSUM_SHA384,
	.key_xchg = &tls_rsa,
};

struct tls_cipher_suite *tls_cipher_suite_pref[] = {
	&tls_rsa_with_aes_256_cbc_sha,
	&tls_rsa_with_aes_128_cbc_sha,
	&tls_rsa_with_aes_256_cbc_sha256,
	&tls_rsa_with_aes_128_cbc_sha256,
	&tls_rsa_with_aes_256_gcm_sha384,
	&tls_rsa_with_aes_128_gcm_sha256,
	&tls_rsa_with_3des_ede_cbc_sha,
	&tls_rsa_with_rc4_128_sha,
	&tls_rsa_with_rc4_128_md5,
	NULL,
};
