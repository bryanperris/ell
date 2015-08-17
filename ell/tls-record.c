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

#define TX_RECORD_MAX_MAC	64

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

static bool tls_handle_plaintext(struct l_tls *tls, const uint8_t *plaintext,
					int len, uint8_t type, uint16_t version)
{
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
