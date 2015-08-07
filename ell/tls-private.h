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

/* Only TLS 1.2 supported */
#define TLS_V12		((3 << 8) | 3)
#define TLS_V11		((3 << 8) | 2)
#define TLS_V10		((3 << 8) | 1)

#define TLS_VERSION	TLS_V12
#define TLS_MIN_VERSION	TLS_V10

enum tls_cipher_type {
	TLS_CIPHER_STREAM,
	TLS_CIPHER_BLOCK,
	TLS_CIPHER_AEAD,
};

struct l_tls {
	bool server;

	l_tls_write_cb_t tx, rx;
	l_tls_ready_cb_t ready_handle;
	l_tls_disconnect_cb_t disconnected;
	void *user_data;

	char *ca_cert_path;
	char *cert_path;
	char *priv_key_path;
	char *priv_key_passphrase;

	/* Record layer */

	uint8_t *record_buf;
	int record_buf_len;
	int record_buf_max_len;

	uint16_t negotiated_version;

	enum tls_cipher_type cipher_type[2];
	struct l_cipher *cipher[2];
	struct l_checksum *mac[2];
	size_t mac_length[2];
	size_t block_length[2];
	size_t record_iv_length[2];
	uint64_t seq_num[2];
	/*
	 * Some of the key and IV parts of the "current" state are kept
	 * inside the cipher and mac states in the kernel so we don't
	 * duplicate them here.
	 */

	bool ready;
};

void tls10_prf(const uint8_t *secret, size_t secret_len,
		const char *label,
		const uint8_t *seed, size_t seed_len,
		uint8_t *out, size_t out_len);

void tls12_prf(enum l_checksum_type type, size_t hash_len,
		const uint8_t *secret, size_t secret_len,
		const char *label,
		const uint8_t *seed, size_t seed_len,
		uint8_t *out, size_t out_len);

void tls_disconnect(struct l_tls *tls, enum l_tls_alert_desc desc,
			enum l_tls_alert_desc local_desc);
