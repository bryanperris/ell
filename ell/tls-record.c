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
#include <alloca.h>

#include "private.h"
#include "tls.h"
#include "checksum.h"
#include "cipher.h"
#include "tls-private.h"
#include "random.h"

/* Implementation-specific max Record Layer fragment size (must be < 16kB) */
#define TX_RECORD_MAX_LEN	4096

/* TLSPlaintext + TLSCompressed + TLSCiphertext headers + seq_num sizes */
#define TX_RECORD_MAX_HEADERS	(5 + 5 + 8 + 5)
#define TX_RECORD_MAX_MAC	64

/* Head room and tail room for the buffer passed to the cipher */
#define TX_RECORD_HEADROOM	TX_RECORD_MAX_HEADERS
#define TX_RECORD_TAILROOM	TX_RECORD_MAX_MAC

static void tls_write_mac(struct l_tls *tls, uint8_t *compressed,
				uint16_t compressed_len, uint8_t *out_buf,
				bool txrx)
{
	uint8_t *in_buf;

	/* Prepend the sequence number to the TLSCompressed buffer */
	in_buf = compressed - 8;
	l_put_be64(tls->seq_num[txrx]++, in_buf);

	if (tls->mac[txrx]) {
		l_checksum_reset(tls->mac[txrx]);
		l_checksum_update(tls->mac[txrx], in_buf, compressed_len + 8);
		l_checksum_get_digest(tls->mac[txrx], out_buf,
					tls->mac_length[txrx]);
	}
}

static void tls_tx_record_plaintext(struct l_tls *tls,
					uint8_t *plaintext,
					uint16_t plaintext_len)
{
	uint8_t *compressed;
	uint16_t compressed_len;
	uint8_t *cipher_input;
	uint16_t cipher_input_len;
	uint8_t *ciphertext;
	uint16_t ciphertext_len;
	uint8_t padding_length;
	uint8_t buf[TX_RECORD_HEADROOM + TX_RECORD_MAX_LEN +
				TX_RECORD_TAILROOM];
	int offset;

	/*
	 * TODO: if DEFLATE is selected in current state, use a new buffer
	 * on stack to write a TLSCompressed structure there, otherwise use
	 * the provided buffer.  Since only null compression is supported
	 * today we always use the provided buffer.
	 */
	compressed_len = plaintext_len - 5;
	compressed = plaintext;

	/* Build a TLSCompressed struct */
	compressed[0] = plaintext[0]; /* Copy type and version fields */
	compressed[1] = plaintext[1];
	compressed[2] = plaintext[2];
	compressed[3] = compressed_len >> 8;
	compressed[4] = compressed_len >> 0;

	switch (tls->cipher_type[1]) {
	case TLS_CIPHER_STREAM:
		/* Append the MAC after TLSCompressed.fragment, if needed */
		tls_write_mac(tls, compressed, compressed_len + 5,
				compressed + compressed_len + 5, true);

		cipher_input = compressed + 5;
		cipher_input_len = compressed_len + tls->mac_length[1];

		if (!tls->cipher[1]) {
			ciphertext = cipher_input;
			ciphertext_len = cipher_input_len;
		} else {
			ciphertext = buf + TX_RECORD_HEADROOM;
			ciphertext_len = cipher_input_len;
			l_cipher_encrypt(tls->cipher[1], cipher_input,
						ciphertext, cipher_input_len);
		}

		break;

	case TLS_CIPHER_BLOCK:
		/* Append the MAC after TLSCompressed.fragment, if needed */
		cipher_input = compressed + 5;
		tls_write_mac(tls, compressed, compressed_len + 5,
				cipher_input + compressed_len, true);
		cipher_input_len = compressed_len + tls->mac_length[1];

		/* Add minimum padding */
		padding_length = (~cipher_input_len) &
			(tls->block_length[1] - 1);
		memset(cipher_input + cipher_input_len, padding_length,
				padding_length + 1);
		cipher_input_len += padding_length + 1;

		/* Generate an IV */
		ciphertext = buf + TX_RECORD_HEADROOM;

		offset = 0;

		if (tls->negotiated_version >= TLS_V12) {
			l_getrandom(ciphertext, tls->record_iv_length[1]);

			l_cipher_set_iv(tls->cipher[1], ciphertext,
					tls->record_iv_length[1]);

			offset = tls->record_iv_length[1];
		}

		l_cipher_encrypt(tls->cipher[1], cipher_input,
					ciphertext + offset, cipher_input_len);
		ciphertext_len = offset + cipher_input_len;

		break;

	case TLS_CIPHER_AEAD:
		/* No AEAD ciphers supported today */
	default:
		return;
	}

	/* Build a TLSCiphertext struct */
	ciphertext -= 5;
	ciphertext[0] = plaintext[0]; /* Copy type and version fields */
	ciphertext[1] = plaintext[1];
	ciphertext[2] = plaintext[2];
	ciphertext[3] = ciphertext_len >> 8;
	ciphertext[4] = ciphertext_len >> 0;

	tls->tx(ciphertext, ciphertext_len + 5, tls->user_data);
}

void tls_tx_record(struct l_tls *tls, enum tls_content_type type,
			const uint8_t *data, size_t len)
{
	uint8_t buf[TX_RECORD_HEADROOM + TX_RECORD_MAX_LEN +
				TX_RECORD_TAILROOM];
	uint8_t *fragment, *plaintext;
	uint16_t fragment_len;

	while (len) {
		fragment = buf + TX_RECORD_HEADROOM;
		fragment_len = len < TX_RECORD_MAX_LEN ?
			len : TX_RECORD_MAX_LEN;

		/* Build a TLSPlaintext struct */
		plaintext = fragment - 5;
		plaintext[0] = type;
		plaintext[1] = (uint8_t) (TLS_VERSION >> 8);
		plaintext[2] = (uint8_t) (TLS_VERSION >> 0);
		plaintext[3] = fragment_len >> 8;
		plaintext[4] = fragment_len >> 0;
		memcpy(plaintext + 5, data, fragment_len);

		tls_tx_record_plaintext(tls, plaintext, fragment_len + 5);

		data += fragment_len;
		len -= fragment_len;
	}
}

static bool tls_handle_plaintext(struct l_tls *tls, const uint8_t *plaintext,
					int len, uint8_t type, uint16_t version)
{
	int header_len, need_len;
	int chunk_len;

	uint32_t hs_len;

	if (len > (1 << 14)) {
		tls_disconnect(tls, TLS_ALERT_DECODE_ERROR, 0);
		return false;
	}

	switch (type) {
	case TLS_CT_CHANGE_CIPHER_SPEC:
	case TLS_CT_APPLICATION_DATA:
		return tls_handle_message(tls, plaintext, len, type, version);

	/*
	 * We need to perform input reassembly twice at different levels:
	 * once to make sure we're handling complete TLSCiphertext messages,
	 * in l_tls_handle_rx(), and again here so that the Alert and
	 * Handshake message type handlers deal with complete messages.
	 * This does not affect ChangeCipherSpec messages because they're
	 * just a single byte and there are never more than one such message
	 * in a row.  Similarly it doesn't affect application data because
	 * the application is not guaranteed that message boundaries are
	 * preserved in any way and we don't know its message lengths anyway.
	 * It does affect Alert because these messages are 2 byte long and
	 * could potentially be split over two TLSPlaintext messages but
	 * there are never more than one Alert in a TLSPlaintext for the same
	 * reason as with ChangeCipherSpec.  Handshake messages are the
	 * most affected although the need to do the reassembly twice still
	 * seems wasteful considering most of these messages are sent in
	 * plaintext and TLSCiphertext maps to TLSPlaintext records.
	 */
	case TLS_CT_ALERT:
	case TLS_CT_HANDSHAKE:
		break;

	default:
		tls_disconnect(tls, TLS_ALERT_DECODE_ERROR, 0);
		return false;
	}

	if (tls->message_buf_len && type != tls->message_content_type) {
		tls_disconnect(tls, TLS_ALERT_DECODE_ERROR, 0);
		return false;
	}

	tls->message_content_type = type;

	while (1) {
		/* Do we have a full header in tls->message_buf? */
		header_len = (type == TLS_CT_ALERT) ? 2 : 4;
		need_len = header_len;

		if (tls->message_buf_len >= header_len) {
			if (type == TLS_CT_HANDSHAKE) {
				hs_len = (tls->message_buf[1] << 16) |
					(tls->message_buf[2] << 8) |
					(tls->message_buf[3] << 0);
				if (hs_len > (1 << 14)) {
					tls_disconnect(tls,
						TLS_ALERT_DECODE_ERROR, 0);
					return false;
				}

				need_len += hs_len;
			}

			/* Do we have a full structure? */
			if (tls->message_buf_len == need_len) {
				if (!tls_handle_message(tls, tls->message_buf,
							need_len, type,
							version))
					return false;

				tls->message_buf_len = 0;

				continue;
			}

			if (!len)
				break;
		}

		/* Try to fill up tls->message_buf up to need_len */
		if (tls->message_buf_max_len < need_len) {
			tls->message_buf_max_len = need_len;
			tls->message_buf =
				l_realloc(tls->message_buf, need_len);
		}

		need_len -= tls->message_buf_len;
		chunk_len = need_len;
		if (len < chunk_len)
			chunk_len = len;

		memcpy(tls->message_buf + tls->message_buf_len, plaintext,
				chunk_len);
		tls->message_buf_len += chunk_len;
		plaintext += chunk_len;
		len -= chunk_len;

		if (chunk_len < need_len)
			break;
	}

	return true;
}

static bool tls_handle_ciphertext(struct l_tls *tls)
{
	uint8_t type;
	uint16_t version;
	uint16_t fragment_len;
	uint8_t mac_buf[TX_RECORD_MAX_MAC], i, padding_len;
	int cipher_output_len, error;
	uint8_t *compressed;
	int compressed_len;

	type = tls->record_buf[0];
	version = l_get_be16(tls->record_buf + 1);
	fragment_len = l_get_be16(tls->record_buf + 3);

	if (fragment_len > (1 << 14) + 2048) {
		tls_disconnect(tls, TLS_ALERT_RECORD_OVERFLOW, 0);
		return false;
	}

	if (version < TLS_MIN_VERSION || version > TLS_VERSION) {
		tls_disconnect(tls, TLS_ALERT_PROTOCOL_VERSION, 0);
		return false;
	}

	if (fragment_len < tls->mac_length[0]) {
		tls_disconnect(tls, TLS_ALERT_DECODE_ERROR, 0);
		return false;
	}

	compressed = alloca(8 + 5 + fragment_len);
	/* Copy the type and version fields */
	compressed[8] = type;
	l_put_be16(version, compressed + 9);

	switch (tls->cipher_type[0]) {
	case TLS_CIPHER_STREAM:
		cipher_output_len = fragment_len;
		compressed_len = cipher_output_len - tls->mac_length[0];
		l_put_be16(compressed_len, compressed + 11);

		if (!tls->cipher[0])
			memcpy(compressed + 13, tls->record_buf + 5,
					cipher_output_len);
		else if (!l_cipher_decrypt(tls->cipher[0], tls->record_buf + 5,
						compressed + 13,
						cipher_output_len)) {
			tls_disconnect(tls, TLS_ALERT_INTERNAL_ERROR, 0);
			return false;
		}

		/* Calculate the MAC if needed */
		tls_write_mac(tls, compressed + 8, 5 + compressed_len,
				mac_buf, false);

		if (tls->mac_length && memcmp(mac_buf, compressed + 13 +
					compressed_len, tls->mac_length[0])) {
			tls_disconnect(tls, TLS_ALERT_BAD_RECORD_MAC, 0);
			return false;
		}

		compressed += 13;

		break;

	case TLS_CIPHER_BLOCK:
		i = 0;
		if (tls->negotiated_version >= TLS_V12)
			i = tls->record_iv_length[0];

		if (fragment_len <= tls->mac_length[0] + i) {
			tls_disconnect(tls, TLS_ALERT_DECODE_ERROR, 0);
			return false;
		}

		cipher_output_len = fragment_len - i;

		if (cipher_output_len % tls->block_length[0] != 0) {
			tls_disconnect(tls, TLS_ALERT_BAD_RECORD_MAC, 0);
			return false;
		}

		if (tls->negotiated_version >= TLS_V12)
			if (!l_cipher_set_iv(tls->cipher[0],
						tls->record_buf + 5,
						tls->record_iv_length[0])) {
				tls_disconnect(tls, TLS_ALERT_INTERNAL_ERROR,
						0);
				return false;
			}

		if (!l_cipher_decrypt(tls->cipher[0], tls->record_buf + 5 + i,
					compressed + 13, cipher_output_len)) {
			tls_disconnect(tls, TLS_ALERT_INTERNAL_ERROR, 0);
			return false;
		}

		/*
		 * RFC 5246, page 24:
		 * In order to defend against this attack, implementations
		 * MUST ensure that record processing time is essentially the
		 * same whether or not the padding is correct.  In general,
		 * the best way to do this is to compute the MAC even if the
		 * padding is incorrect, and only then reject the packet.  For
		 * instance, if the pad appears to be incorrect, the
		 * implementation might assume a zero-length pad and then
		 * compute the MAC.
		 */
		padding_len = compressed[13 + cipher_output_len - 1];
		error = 0;
		if (padding_len + tls->mac_length[0] + 1 >=
				(size_t) cipher_output_len) {
			padding_len = 0;
			error = 1;
		}

		compressed_len = cipher_output_len - 1 - padding_len -
			tls->mac_length[0];
		l_put_be16(compressed_len, compressed + 11);

		for (i = 0; i < padding_len; i++)
			if (compressed[13 + cipher_output_len - 1 -
					padding_len + i] != padding_len)
				error = 1;

		/* Calculate the MAC if needed */
		tls_write_mac(tls, compressed + 8, 5 + compressed_len,
				mac_buf, false);

		if ((tls->mac_length[0] && memcmp(mac_buf, compressed + 13 +
					compressed_len, tls->mac_length[0])) ||
				error) {
			tls_disconnect(tls, TLS_ALERT_BAD_RECORD_MAC, 0);
			return false;
		}

		compressed += 13;

		break;

	case TLS_CIPHER_AEAD:
		/* No AEAD ciphers supported today */
	default:
		return false;
	}

	/* DEFLATE not supported so just pass on compressed / compressed_len */

	return tls_handle_plaintext(tls, compressed, compressed_len,
					type, version);
}

LIB_EXPORT void l_tls_handle_rx(struct l_tls *tls, const uint8_t *data,
				size_t len)
{
	int need_len;
	int chunk_len;

	/* Reassemble TLSCiphertext structures from the received chunks */

	while (1) {
		/* Do we have a full header in tls->record_buf? */
		if (tls->record_buf_len >= 5) {
			need_len = 5 + l_get_be16(tls->record_buf + 3);

			/* Do we have a full structure? */
			if (tls->record_buf_len == need_len) {
				if (!tls_handle_ciphertext(tls))
					return;

				tls->record_buf_len = 0;
				need_len = 5;
			}

			if (!len)
				break;
		} else
			need_len = 5;

		/* Try to fill up tls->record_buf up to need_len */
		if (tls->record_buf_max_len < need_len) {
			tls->record_buf_max_len = need_len;
			tls->record_buf = l_realloc(tls->record_buf, need_len);
		}

		need_len -= tls->record_buf_len;
		chunk_len = need_len;
		if (len < (size_t) chunk_len)
			chunk_len = len;

		memcpy(tls->record_buf + tls->record_buf_len, data, chunk_len);
		tls->record_buf_len += chunk_len;
		data += chunk_len;
		len -= chunk_len;

		if (chunk_len < need_len)
			break;
	}
}
