/*
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include "util.h"
#include "private.h"
#include "tls.h"
#include "checksum.h"
#include "tls-private.h"

void tls10_prf(const uint8_t *secret, size_t secret_len,
		const char *label,
		const uint8_t *seed, size_t seed_len,
		uint8_t *out, size_t out_len)
{
	uint8_t p_hash2[out_len];
	uint8_t l_s1 = (secret_len + 1) / 2;
	unsigned int i;

	tls12_prf(L_CHECKSUM_MD5, 16,
			secret, l_s1,
			label, seed, seed_len,
			out, out_len);
	tls12_prf(L_CHECKSUM_SHA1, 20,
			secret + secret_len - l_s1, l_s1,
			label, seed, seed_len,
			p_hash2, out_len);

	for (i = 0; i < out_len; i++)
		out[i] ^= p_hash2[i];
}

void tls12_prf(enum l_checksum_type type, size_t hash_len,
		const uint8_t *secret, size_t secret_len,
		const char *label,
		const uint8_t *seed, size_t seed_len,
		uint8_t *out, size_t out_len)
{
	struct l_checksum *hmac = l_checksum_new_hmac(type, secret, secret_len);
	size_t a_len, chunk_len, prfseed_len = strlen(label) + seed_len;
	uint8_t a[128], prfseed[prfseed_len];

	/* Generate the hash seed or A(0) as label + seed */
	memcpy(prfseed, label, strlen(label));
	memcpy(prfseed + strlen(label), seed, seed_len);

	memcpy(a, prfseed, prfseed_len);
	a_len = prfseed_len;

	while (out_len) {
		/* Generate A(i) */
		l_checksum_reset(hmac);
		l_checksum_update(hmac, a, a_len);
		l_checksum_get_digest(hmac, a, hash_len);
		a_len = hash_len;

		/* Append seed & generate output */
		memcpy(a + a_len, prfseed, prfseed_len);
		l_checksum_reset(hmac);
		l_checksum_update(hmac, a, a_len + prfseed_len);

		chunk_len = out_len < hash_len ? out_len : hash_len;
		l_checksum_get_digest(hmac, out, chunk_len);
		out += chunk_len;
		out_len -= chunk_len;
	}

	l_checksum_free(hmac);
}

/*
 * Callers make sure this is about the last function before returning
 * from the stack frames up to the exported library call so that the
 * user-supplied disconnected callback here is free to use l_tls_free
 * for example.
 */
void tls_disconnect(struct l_tls *tls, enum l_tls_alert_desc desc,
			enum l_tls_alert_desc local_desc)
{
	tls->ready = false;

	tls->disconnected(tls->user_data, local_desc ?: desc,
				local_desc && !desc);
}

LIB_EXPORT struct l_tls *l_tls_new(bool server,
				l_tls_write_cb_t app_data_handler,
				l_tls_write_cb_t tx_handler,
				l_tls_ready_cb_t ready_handler,
				l_tls_disconnect_cb_t disconnect_handler,
				void *user_data)
{
	struct l_tls *tls;

	tls = l_new(struct l_tls, 1);
	tls->server = server;
	tls->rx = app_data_handler;
	tls->tx = tx_handler;
	tls->ready_handle = ready_handler;
	tls->disconnected = disconnect_handler;
	tls->user_data = user_data;

	return tls;
}

LIB_EXPORT void l_tls_free(struct l_tls *tls)
{
	if (unlikely(!tls))
		return;

	l_tls_set_cacert(tls, NULL);
	l_tls_set_auth_data(tls, NULL, NULL, NULL);

	if (tls->record_buf)
		l_free(tls->record_buf);

	if (tls->message_buf)
		l_free(tls->message_buf);

	l_free(tls);
}

LIB_EXPORT void l_tls_set_cacert(struct l_tls *tls, const char *ca_cert_path)
{
	if (tls->ca_cert_path) {
		l_free(tls->ca_cert_path);
		tls->ca_cert_path = NULL;
	}

	if (ca_cert_path)
		tls->ca_cert_path = l_strdup(ca_cert_path);
}

LIB_EXPORT void l_tls_set_auth_data(struct l_tls *tls, const char *cert_path,
				const char *priv_key_path,
				const char *priv_key_passphrase)
{
	if (tls->cert_path) {
		l_free(tls->cert_path);
		l_free(tls->priv_key_path);
		tls->cert_path = NULL;
		tls->priv_key_path = NULL;
	}

	if (cert_path) {
		tls->cert_path = l_strdup(cert_path);
		tls->priv_key_path = l_strdup(priv_key_path);
	}

	if (tls->priv_key_passphrase) {
		memset(tls->priv_key_passphrase, 0,
				strlen(tls->priv_key_passphrase));
		l_free(tls->priv_key_passphrase);
		tls->priv_key_passphrase = NULL;
	}

	if (priv_key_passphrase)
		tls->priv_key_passphrase = l_strdup(priv_key_passphrase);
}

LIB_EXPORT const char *l_tls_alert_to_str(enum l_tls_alert_desc desc)
{
	switch (desc) {
	case TLS_ALERT_CLOSE_NOTIFY:
		return "close_notify";
	case TLS_ALERT_UNEXPECTED_MESSAGE:
		return "unexpected_message";
	case TLS_ALERT_BAD_RECORD_MAC:
		return "bad_record_mac";
	case TLS_ALERT_DECRYPT_FAIL_RESERVED:
		return "decryption_failure_RESERVED";
	case TLS_ALERT_RECORD_OVERFLOW:
		return "record_overflow";
	case TLS_ALERT_DECOMPRESS_FAIL:
		return "decompression_failure";
	case TLS_ALERT_HANDSHAKE_FAIL:
		return "handshake_failure";
	case TLS_ALERT_NO_CERT_RESERVED:
		return "no_certificate_RESERVED";
	case TLS_ALERT_BAD_CERT:
		return "bad_certificate";
	case TLS_ALERT_UNSUPPORTED_CERT:
		return "unsupported_certificate";
	case TLS_ALERT_CERT_REVOKED:
		return "certificate_revoked";
	case TLS_ALERT_CERT_EXPIRED:
		return "certificate_expired";
	case TLS_ALERT_CERT_UNKNOWN:
		return "certificate_unknown";
	case TLS_ALERT_ILLEGAL_PARAM:
		return "illegal_parameter";
	case TLS_ALERT_UNKNOWN_CA:
		return "unknown_ca";
	case TLS_ALERT_ACCESS_DENIED:
		return "access_denied";
	case TLS_ALERT_DECODE_ERROR:
		return "decode_error";
	case TLS_ALERT_DECRYPT_ERROR:
		return "decrypt_error";
	case TLS_ALERT_EXPORT_RES_RESERVED:
		return "export_restriction_RESERVED";
	case TLS_ALERT_PROTOCOL_VERSION:
		return "protocol_version";
	case TLS_ALERT_INSUFFICIENT_SECURITY:
		return "insufficient_security";
	case TLS_ALERT_INTERNAL_ERROR:
		return "internal_error";
	case TLS_ALERT_USER_CANCELED:
		return "user_canceled";
	case TLS_ALERT_NO_RENEGOTIATION:
		return "no_renegotiation";
	case TLS_ALERT_UNSUPPORTED_EXTENSION:
		return "unsupported_extension";
	}

	return NULL;
}
