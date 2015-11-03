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

struct tls_cert;

enum tls_cipher_type {
	TLS_CIPHER_STREAM,
	TLS_CIPHER_BLOCK,
	TLS_CIPHER_AEAD,
};

struct tls_bulk_encryption_algorithm {
	enum tls_cipher_type cipher_type;
	enum l_cipher_type l_id;
	size_t key_length;
	size_t iv_length;
	size_t block_length;
};

struct tls_hash_algorithm {
	uint8_t tls_id;
	enum l_checksum_type l_id;
	size_t length;
};

typedef bool (*tls_get_hash_t)(struct l_tls *tls, uint8_t tls_id,
				uint8_t *out, size_t *len,
				enum l_checksum_type *type);

struct tls_key_exchange_algorithm {
	uint8_t id;

	bool certificate_check;

	bool (*validate_cert_key_type)(struct tls_cert *cert);

	bool (*send_client_key_exchange)(struct l_tls *tls);
	void (*handle_client_key_exchange)(struct l_tls *tls,
						const uint8_t *buf, size_t len);

	bool (*sign)(struct l_tls *tls, uint8_t **out,
			tls_get_hash_t get_hash);
	bool (*verify)(struct l_tls *tls, const uint8_t *in, size_t len,
			tls_get_hash_t get_hash);
};

struct tls_mac_algorithm {
	uint8_t id;
	enum l_checksum_type hmac_type;
	size_t mac_length;
};

struct tls_cipher_suite {
	uint8_t id[2];
	const char *name;
	int verify_data_length;

	struct tls_bulk_encryption_algorithm *encryption;
	struct tls_key_exchange_algorithm *key_xchg;
	struct tls_mac_algorithm *mac;
};

struct tls_compression_method {
	int id;
};

enum tls_handshake_state {
	TLS_HANDSHAKE_WAIT_HELLO,
	TLS_HANDSHAKE_WAIT_CERTIFICATE,
	TLS_HANDSHAKE_WAIT_KEY_EXCHANGE,
	TLS_HANDSHAKE_WAIT_HELLO_DONE,
	TLS_HANDSHAKE_WAIT_CERTIFICATE_VERIFY,
	TLS_HANDSHAKE_WAIT_CHANGE_CIPHER_SPEC,
	TLS_HANDSHAKE_WAIT_FINISHED,
	TLS_HANDSHAKE_DONE,
};

enum tls_content_type {
	TLS_CT_CHANGE_CIPHER_SPEC	= 20,
	TLS_CT_ALERT			= 21,
	TLS_CT_HANDSHAKE		= 22,
	TLS_CT_APPLICATION_DATA		= 23,
};

/*
 * Support the minimum required set of handshake hash types for the
 * Certificate Verify digital signature and the Finished PRF seed so we
 * don't have to accumulate all of messages full contents until the
 * Finished message.  If we're sent a hash of a different type (in TLS 1.2+)
 * and need to verify we'll give up.
 * SHA1 and MD5 are explicitly required by versions < 1.2 and 1.2 requires
 * that the Finished hash is the same as used for the PRF, which in all
 * our supported cipher suites is defined to be SHA256.
 */
enum handshake_hash_type {
	HANDSHAKE_HASH_SHA256,
	HANDSHAKE_HASH_MD5,
	HANDSHAKE_HASH_SHA1,
	__HANDSHAKE_HASH_COUNT,
};
#define HANDSHAKE_HASH_MAX_SIZE	32

#define HANDSHAKE_HASH_TLS12 HANDSHAKE_HASH_SHA256

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

	uint8_t *message_buf;
	int message_buf_len;
	int message_buf_max_len;
	enum tls_content_type message_content_type;

	/* Handshake protocol layer */

	enum tls_handshake_state state;
	struct l_checksum *handshake_hash[__HANDSHAKE_HASH_COUNT];
	uint8_t prev_digest[__HANDSHAKE_HASH_COUNT][HANDSHAKE_HASH_MAX_SIZE];

	uint16_t client_version;
	uint16_t negotiated_version;
	bool cert_requested, cert_sent;
	bool peer_authenticated;
	struct tls_cert *peer_cert;
	uint8_t *peer_pubkey;
	size_t peer_pubkey_length;

	/* SecurityParameters current and pending */

	struct {
		struct tls_cipher_suite *cipher_suite;
		struct tls_compression_method *compression_method;
		uint8_t master_secret[48];
		uint8_t client_random[32];
		uint8_t server_random[32];
		/*
		 * Max key block size per 6.3 v1.1 is 136 bytes but if we
		 * allow AES_256_CBC_SHA256 with v1.0 we get 128 per section
		 * 6.3 v1.2 + two IVs of 32 bytes.
		 */
		uint8_t key_block[192];
	} pending;

	enum tls_cipher_type cipher_type[2];
	struct tls_cipher_suite *cipher_suite[2];
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

void tls_tx_record(struct l_tls *tls, enum tls_content_type type,
			const uint8_t *data, size_t len);
bool tls_handle_message(struct l_tls *tls, const uint8_t *message,
			int len, enum tls_content_type type, uint16_t version);

/* X509 Certificates and Certificate Chains */

struct tls_cert {
	size_t size;
	struct tls_cert *issuer;
	uint8_t asn1[0];
};

enum tls_cert_key_type {
	TLS_CERT_KEY_RSA,
	TLS_CERT_KEY_UNKNOWN,
};

struct tls_cert *tls_cert_load_file(const char *filename);

bool tls_cert_find_certchain(struct tls_cert *cert,
				const char *cacert_filename);

bool tls_cert_verify_certchain(struct tls_cert *certchain,
				struct tls_cert *ca_cert);

void tls_cert_free_certchain(struct tls_cert *cert);

uint8_t *tls_cert_find_pubkey(struct tls_cert *cert, int *pubkey_len);

enum tls_cert_key_type tls_cert_get_pubkey_type(struct tls_cert *cert);

void tls_prf_get_bytes(struct l_tls *tls,
				enum l_checksum_type type, size_t hash_len,
				const uint8_t *secret, size_t secret_len,
				const char *label,
				const uint8_t *seed, size_t seed_len,
				uint8_t *buf, size_t len);
