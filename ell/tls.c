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
#include <time.h>
#include <stdlib.h>

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

static void tls_write_random(uint8_t *buf)
{
	l_put_be32(time(NULL), buf);

	l_getrandom(buf + 4, 28);
}

static struct tls_cipher_suite tls_cipher_suite_pref[] = {
};

static struct tls_cipher_suite *tls_find_cipher_suite(const uint8_t *id)
{
	int i;

	for (i = 0; i < (int) L_ARRAY_SIZE(tls_cipher_suite_pref); i++)
		if (tls_cipher_suite_pref[i].id[0] == id[0] &&
				tls_cipher_suite_pref[i].id[1] == id[1])
			return &tls_cipher_suite_pref[i];

	return NULL;
}

static struct tls_compression_method tls_compression_pref[] = {
	/* CompressionMethod.null */
	{
		0,
	},
};

static struct tls_compression_method *tls_find_compression_method(
							const uint8_t id)
{
	int i;

	for (i = 0; i < (int) L_ARRAY_SIZE(tls_compression_pref); i++)
		if (tls_compression_pref[i].id == id)
			return &tls_compression_pref[i];

	return NULL;
}

enum tls_handshake_type {
	TLS_HELLO_REQUEST	= 0,
	TLS_CLIENT_HELLO	= 1,
	TLS_SERVER_HELLO	= 2,
	TLS_CERTIFICATE		= 11,
	TLS_SERVER_KEY_EXCHANGE	= 12,
	TLS_CERTIFICATE_REQUEST	= 13,
	TLS_SERVER_HELLO_DONE	= 14,
	TLS_CERTIFICATE_VERIFY	= 15,
	TLS_CLIENT_KEY_EXCHANGE	= 16,
	TLS_FINISHED		= 20,
};

static void tls_send_alert(struct l_tls *tls, bool fatal,
				enum l_tls_alert_desc alert_desc)
{
	uint8_t buf[2];

	buf[0] = fatal ? 2 : 1;
	buf[1] = alert_desc;

	tls_tx_record(tls, TLS_CT_ALERT, buf, 2);
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
	tls_send_alert(tls, true, desc);

	tls->ready = false;

	tls->disconnected(tls->user_data, local_desc ?: desc,
				local_desc && !desc);
}

#define TLS_HANDSHAKE_HEADER_SIZE	4

static void tls_tx_handshake(struct l_tls *tls, int type, uint8_t *buf,
				size_t length)
{
	/* Fill in the handshake header */

	buf[0] = type;
	buf[1] = (length - TLS_HANDSHAKE_HEADER_SIZE) >> 16;
	buf[2] = (length - TLS_HANDSHAKE_HEADER_SIZE) >>  8;
	buf[3] = (length - TLS_HANDSHAKE_HEADER_SIZE) >>  0;

	tls_tx_record(tls, TLS_CT_HANDSHAKE, buf, length);
}

static void tls_send_client_hello(struct l_tls *tls)
{
	uint8_t buf[128 + L_ARRAY_SIZE(tls_compression_pref) +
			2 * L_ARRAY_SIZE(tls_cipher_suite_pref)];
	uint8_t *ptr = buf + TLS_HANDSHAKE_HEADER_SIZE;
	int i;

	/* Fill in the Client Hello body */

	*ptr++ = (uint8_t) (TLS_VERSION >> 8);
	*ptr++ = (uint8_t) (TLS_VERSION >> 0);

	tls_write_random(tls->pending.client_random);
	memcpy(ptr, tls->pending.client_random, 32);
	ptr += 32;

	*ptr++ = 0; /* No SessionID */

	/*
	 * We can list all supported key exchange mechanisms regardless of the
	 * certificate type we are actually presenting (if any).
	 *
	 * TODO: perhaps scan /proc/crypto for supported ciphers so we don't
	 * include ones that will cause an internal error later in the
	 * handshake.  We can add camellia whan this is done.
	 */
	l_put_be16(L_ARRAY_SIZE(tls_cipher_suite_pref) * 2, ptr);
	ptr += 2;

	for (i = 0; i < (int) L_ARRAY_SIZE(tls_cipher_suite_pref); i++) {
		*ptr++ = tls_cipher_suite_pref[i].id[0];
		*ptr++ = tls_cipher_suite_pref[i].id[1];
	}

	*ptr++ = L_ARRAY_SIZE(tls_compression_pref);

	for (i = 0; i < (int) L_ARRAY_SIZE(tls_compression_pref); i++)
		*ptr++ = tls_compression_pref[i].id;

	tls_tx_handshake(tls, TLS_CLIENT_HELLO, buf, ptr - buf);
}

static void tls_handle_client_hello(struct l_tls *tls,
					const uint8_t *buf, size_t len)
{
	uint16_t cipher_suites_size;
	uint8_t session_id_size, compression_methods_size;
	const uint8_t *cipher_suites;
	const uint8_t *compression_methods;

	/* Do we have enough for ProtocolVersion + Random + SessionID size? */
	if (len < 2 + 32 + 1)
		goto decode_error;

	memcpy(tls->pending.client_random, buf + 2, 32);
	session_id_size = buf[34];
	len -= 35;

	/*
	 * Do we have enough to hold the actual session ID + 2 byte field for
	 * cipher_suite len + minimum of a single cipher suite identifier
	 */
	if (len < (size_t) session_id_size + 4)
		goto decode_error;

	len -= session_id_size + 2;

	cipher_suites_size = l_get_be16(buf + 35 + session_id_size);
	cipher_suites = buf + 37 + session_id_size;

	/*
	 * Check that size is not odd, more than 0 and we have enough
	 * data in the packet for cipher_suites_size + 2 bytes for
	 * compression_methods_size + a single compression method
	 */
	if (len < (size_t) cipher_suites_size + 2 ||
			(cipher_suites_size & 1) || cipher_suites_size == 0)
		goto decode_error;

	len -= cipher_suites_size + 1;

	compression_methods_size = cipher_suites[cipher_suites_size];
	compression_methods = cipher_suites + cipher_suites_size + 1;

	if (len < (size_t) compression_methods_size ||
			compression_methods_size == 0)
		goto decode_error;

	len -= compression_methods_size;

	if (len) {
		uint16_t extensions_size;

		if (len < 2 || len > 2 + 65535)
			goto decode_error;

		extensions_size = l_get_be16(compression_methods +
						compression_methods_size);
		len -= 2;

		if (len != extensions_size)
			goto decode_error;

		/* TODO: validate each extension in the vector, 7.4.1.4 */
		/* TODO: check for duplicates? */
	}

	/*
	 * Note: if the client is supplying a SessionID we know it is false
	 * because our server implementation never generates any SessionIDs
	 * yet so either the client is attempting something strange or was
	 * trying to connect somewhere else.  We might want to throw an error.
	 */

	/*
	 * TODO: Obligatory in 1.2: check for signature_algorithms extension,
	 * store the list of algorithms for later checking in
	 * tls_send_certificate on both server and client sides.  If not
	 * present assume only SHA1+RSA (7.4.1.4.1).
	 */

	/* Save client_version for Premaster Secret verification */
	tls->client_version = l_get_be16(buf);

	if (tls->client_version < TLS_MIN_VERSION) {
		tls_disconnect(tls, TLS_ALERT_PROTOCOL_VERSION, 0);
		return;
	}

	tls->negotiated_version = TLS_VERSION < tls->client_version ?
		TLS_VERSION : tls->client_version;

	/* Select a cipher suite according to client's preference list */
	while (cipher_suites_size) {
		/*
		 * TODO: filter supported cipher suites by the certificate/key
		 * type that was submitted by tls_set_auth_data() if any.
		 * Perhaps just call cipher_suite->verify_cert_type() on each
		 * cipher suite passing a pre-parsed certificate ASN.1 struct.
		 */
		tls->pending.cipher_suite =
					tls_find_cipher_suite(cipher_suites);

		if (tls->pending.cipher_suite)
			break;

		cipher_suites += 2;
		cipher_suites_size -= 2;
	}

	if (!cipher_suites_size) {
		tls_disconnect(tls, TLS_ALERT_HANDSHAKE_FAIL, 0);
		return;
	}

	/* Select a compression method */

	/* CompressionMethod.null must be present in the vector */
	if (!memchr(compression_methods, 0, compression_methods_size))
		goto decode_error;

	while (compression_methods_size) {
		tls->pending.compression_method =
			tls_find_compression_method(*compression_methods);

		if (tls->pending.compression_method)
			break;

		compression_methods++;
		compression_methods_size--;
	}

	return;

decode_error:
	tls_disconnect(tls, TLS_ALERT_DECODE_ERROR, 0);
}

static void tls_handle_handshake(struct l_tls *tls, int type,
					const uint8_t *buf, size_t len)
{
	switch (type) {
	case TLS_CLIENT_HELLO:
		if (!tls->server) {
			tls_disconnect(tls, TLS_ALERT_UNEXPECTED_MESSAGE, 0);
			break;
		}

		if (tls->state != TLS_HANDSHAKE_WAIT_HELLO &&
				tls->state != TLS_HANDSHAKE_DONE) {
			tls_disconnect(tls, TLS_ALERT_UNEXPECTED_MESSAGE, 0);
			break;
		}

		tls_handle_client_hello(tls, buf, len);

		break;

	default:
		tls_disconnect(tls, TLS_ALERT_UNEXPECTED_MESSAGE, 0);
	}
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

	/* If we're the client, start the handshake right away */
	if (!tls->server)
		tls_send_client_hello(tls);

	tls->state = TLS_HANDSHAKE_WAIT_HELLO;

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

LIB_EXPORT void l_tls_write(struct l_tls *tls, const uint8_t *data, size_t len)
{
	if (unlikely(!tls->ready)) {
		return;
	}

	tls_tx_record(tls, TLS_CT_APPLICATION_DATA, data, len);
}

bool tls_handle_message(struct l_tls *tls, const uint8_t *message,
			int len, enum tls_content_type type, uint16_t version)
{
	switch (type) {
	case TLS_CT_ALERT:
		/* Verify AlertLevel */
		if (message[0] != 0x01 && message[0] != 0x02) {
			tls_disconnect(tls, TLS_ALERT_DECODE_ERROR, 0);

			return false;
		}

		/*
		 * On a fatal alert we are obligated to respond with a
		 * fatal alert and disconnect but also not complain if
		 * the connection has been torn down by the peer before
		 * we were able to send our alert.  However on a non-fatal
		 * alert (warning) we're also allowed to panic and send
		 * a fatal alert, then disconnect, so we do that
		 * regardless of the alert level.
		 */
		tls_disconnect(tls, TLS_ALERT_CLOSE_NOTIFY, message[1]);

		return false;

	case TLS_CT_HANDSHAKE:
		tls_handle_handshake(tls, message[0],
					message + TLS_HANDSHAKE_HEADER_SIZE,
					len - TLS_HANDSHAKE_HEADER_SIZE);

		break;

	case TLS_CT_APPLICATION_DATA:
		if (!tls->ready) {
			tls_disconnect(tls, TLS_ALERT_UNEXPECTED_MESSAGE, 0);

			return false;
		}

		tls->rx(tls->user_data, message, len);

		break;
	default:
		return false;
	}

	return true;
}

LIB_EXPORT void l_tls_close(struct l_tls *tls)
{
	tls_disconnect(tls, TLS_ALERT_CLOSE_NOTIFY, 0);
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
