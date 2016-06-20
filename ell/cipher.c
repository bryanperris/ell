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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "util.h"
#include "cipher.h"
#include "cipher-private.h"
#include "private.h"
#include "random.h"

#ifndef HAVE_LINUX_IF_ALG_H
#ifndef HAVE_LINUX_TYPES_H
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#else
#include <linux/types.h>
#endif

#ifndef AF_ALG
#define AF_ALG	38
#define PF_ALG	AF_ALG
#endif

struct sockaddr_alg {
	__u16	salg_family;
	__u8	salg_type[14];
	__u32	salg_feat;
	__u32	salg_mask;
	__u8	salg_name[64];
};

struct af_alg_iv {
	__u32   ivlen;
	__u8    iv[0];
};

/* Socket options */
#define ALG_SET_KEY	1
#define ALG_SET_IV	2
#define ALG_SET_OP	3

/* Operations */
#define ALG_OP_DECRYPT	0
#define ALG_OP_ENCRYPT	1
#else
#include <linux/if_alg.h>
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_OP_SIGN
#define ALG_OP_SIGN	2
#endif
#ifndef ALG_OP_VERIFY
#define ALG_OP_VERIFY	3
#endif

#ifndef ALG_SET_PUBKEY
#define ALG_SET_PUBKEY	6
#endif

#define is_valid_type(type)  ((type) <= L_CIPHER_DES3_EDE_CBC)

struct l_cipher {
	int type;
	int encrypt_sk;
	int decrypt_sk;
};

static int create_alg(const char *alg_type, const char *alg_name,
			const void *key, size_t key_length, bool public)
{
	struct sockaddr_alg salg;
	int sk;
	int keyopt;
	int ret;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -errno;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, alg_type);
	strcpy((char *) salg.salg_name, alg_name);

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(sk);
		return -1;
	}

	keyopt = public ? ALG_SET_PUBKEY : ALG_SET_KEY;
	if (setsockopt(sk, SOL_ALG, keyopt, key, key_length) < 0) {
		close(sk);
		return -1;
	}

	ret = accept4(sk, NULL, 0, SOCK_CLOEXEC);
	close(sk);

	return ret;
}

LIB_EXPORT struct l_cipher *l_cipher_new(enum l_cipher_type type,
						const void *key,
						size_t key_length)
{
	struct l_cipher *cipher;
	const char *alg_name;

	if (unlikely(!key))
		return NULL;

	if (!is_valid_type(type))
		return NULL;

	cipher = l_new(struct l_cipher, 1);
	cipher->type = type;

	switch (type) {
	case L_CIPHER_AES:
		alg_name = "ecb(aes)";
		break;
	case L_CIPHER_AES_CBC:
		alg_name = "cbc(aes)";
		break;
	case L_CIPHER_ARC4:
		alg_name = "ecb(arc4)";
		break;
	case L_CIPHER_DES3_EDE_CBC:
		alg_name = "cbc(des3_ede)";
		break;
	}

	cipher->encrypt_sk = create_alg("skcipher", alg_name, key, key_length,
					false);
	if (cipher->encrypt_sk < 0)
		goto error_free;

	cipher->decrypt_sk = create_alg("skcipher", alg_name, key, key_length,
					false);
	if (cipher->decrypt_sk < 0)
		goto error_close;

	return cipher;

error_close:
	close(cipher->encrypt_sk);
error_free:
	l_free(cipher);
	return NULL;
}

LIB_EXPORT void l_cipher_free(struct l_cipher *cipher)
{
	if (unlikely(!cipher))
		return;

	close(cipher->encrypt_sk);
	close(cipher->decrypt_sk);

	l_free(cipher);
}

static ssize_t operate_cipher(int sk, __u32 operation,
				const void *in, void *out, size_t len_in,
				size_t len_out)
{
	char c_msg_buf[CMSG_SPACE(sizeof(operation))];
	struct msghdr msg;
	struct cmsghdr *c_msg;
	struct iovec iov;
	ssize_t result;

	memset(&c_msg_buf, 0, sizeof(c_msg_buf));
	memset(&msg, 0, sizeof(msg));

	msg.msg_control = c_msg_buf;
	msg.msg_controllen = sizeof(c_msg_buf);

	c_msg = CMSG_FIRSTHDR(&msg);
	c_msg->cmsg_level = SOL_ALG;
	c_msg->cmsg_type = ALG_SET_OP;
	c_msg->cmsg_len = CMSG_LEN(sizeof(operation));
	memcpy(CMSG_DATA(c_msg), &operation, sizeof(operation));

	iov.iov_base = (void *) in;
	iov.iov_len = len_in;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	result = sendmsg(sk, &msg, 0);
	if (result < 0)
		return -errno;

	result = read(sk, out, len_out);
	if (result < 0)
		return -errno;

	return result;
}

LIB_EXPORT bool l_cipher_encrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->encrypt_sk, ALG_OP_ENCRYPT, in, out, len,
				len) >= 0;
}

LIB_EXPORT bool l_cipher_decrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->decrypt_sk, ALG_OP_DECRYPT, in, out, len,
				len) >= 0;
}

LIB_EXPORT bool l_cipher_set_iv(struct l_cipher *cipher, const uint8_t *iv,
				size_t iv_length)
{
	char c_msg_buf[CMSG_SPACE(4 + iv_length)];
	struct msghdr msg;
	struct cmsghdr *c_msg;
	uint32_t len = iv_length;

	if (unlikely(!cipher))
		return false;

	memset(&c_msg_buf, 0, sizeof(c_msg_buf));
	memset(&msg, 0, sizeof(struct msghdr));

	msg.msg_control = c_msg_buf;
	msg.msg_controllen = sizeof(c_msg_buf);

	c_msg = CMSG_FIRSTHDR(&msg);
	c_msg->cmsg_level = SOL_ALG;
	c_msg->cmsg_type = ALG_SET_IV;
	c_msg->cmsg_len = CMSG_LEN(4 + iv_length);
	memcpy(CMSG_DATA(c_msg) + 0, &len, 4);
	memcpy(CMSG_DATA(c_msg) + 4, iv, iv_length);

	msg.msg_iov = NULL;
	msg.msg_iovlen = 0;

	if (sendmsg(cipher->encrypt_sk, &msg, 0) < 0)
		return false;

	if (sendmsg(cipher->decrypt_sk, &msg, 0) < 0)
		return false;

	return true;
}

struct l_asymmetric_cipher {
	int type;
	int sk;
	int key_size;
};

static inline int parse_asn1_definite_length(const uint8_t **buf,
						size_t *len)
{
	int n;
	size_t result = 0;

	(*len)--;

	if (!(**buf & 0x80))
		return *(*buf)++;

	n = *(*buf)++ & 0x7f;
	if ((size_t) n > *len)
		return -1;

	*len -= n;
	while (n--)
		result = (result << 8) | *(*buf)++;

	return result;
}

/* Return index'th element in a DER SEQUENCE */
uint8_t *der_find_elem(uint8_t *buf, size_t len_in, int index,
			uint8_t *tag, size_t *len_out)
{
	int tlv_len;

	while (1) {
		if (len_in < 2)
			return NULL;

		*tag = *buf++;
		len_in--;

		tlv_len = parse_asn1_definite_length((void *) &buf, &len_in);
		if (tlv_len < 0 || (size_t) tlv_len > len_in)
			return NULL;

		if (index-- == 0) {
			*len_out = tlv_len;
			return buf;
		}

		buf += tlv_len;
		len_in -= tlv_len;
	}
}

static bool parse_rsa_key(struct l_asymmetric_cipher *cipher, const void *key,
				size_t key_length)
{
	/*
	 * Parse the DER-encoded public or private RSA key to find
	 * and cache the size of the modulus n for later use.
	 * (RFC3279)
	 */
	size_t seq_length;
	size_t n_length;
	uint8_t *seq;
	uint8_t *der;
	uint8_t tag;

	if (key_length < 8)
		return false;

	/* Unpack the outer SEQUENCE */
	seq = der_find_elem((uint8_t *) key, key_length, 0, &tag, &seq_length);
	if (!seq || tag != ASN1_ID_SEQUENCE)
		return false;

	/* First INTEGER may be a 1-byte version (for private key) or
	 * the modulus (public key)
	 */
	der = der_find_elem(seq, seq_length, 0, &tag, &n_length);
	if (der && tag == ASN1_ID_INTEGER && n_length == 1) {
		/* Found version number, implies this is a private key. */
		der = der_find_elem(seq, seq_length, 1, &tag, &n_length);
	}

	if (!der || tag != ASN1_ID_INTEGER || n_length < 4)
		return false;

	/* Skip leading zeros */
	while (n_length && der[0] == 0x00) {
		der++;
		n_length--;
	}

	cipher->key_size = n_length;

	return true;
}

LIB_EXPORT struct l_asymmetric_cipher *l_asymmetric_cipher_new(
					enum l_asymmetric_cipher_type type,
					const void *key, size_t key_length,
					bool public_key)
{
	struct l_asymmetric_cipher *cipher;
	const char *alg_name;

	if (unlikely(!key))
		return NULL;

	if (type != L_CIPHER_RSA_PKCS1_V1_5)
		return NULL;

	cipher = l_new(struct l_asymmetric_cipher, 1);
	cipher->type = type;

	switch (type) {
	case L_CIPHER_RSA_PKCS1_V1_5:
		if (!parse_rsa_key(cipher, key, key_length))
			goto error_free;

		alg_name = "pkcs1pad(rsa)";
		break;
	}

	cipher->sk = create_alg("akcipher", alg_name, key, key_length,
				public_key);
	if (cipher->sk < 0)
		goto error_free;

	return cipher;

error_free:
	l_free(cipher);
	return NULL;
}

LIB_EXPORT void l_asymmetric_cipher_free(struct l_asymmetric_cipher *cipher)
{
	if (unlikely(!cipher))
		return;

	close(cipher->sk);

	l_free(cipher);
}

LIB_EXPORT int l_asymmetric_cipher_get_key_size(
					struct l_asymmetric_cipher *cipher)
{
	return cipher->key_size;
}

LIB_EXPORT ssize_t l_asymmetric_cipher_encrypt(struct l_asymmetric_cipher *cipher,
						const void *in, void *out,
						size_t len_in, size_t len_out)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->sk, ALG_OP_ENCRYPT, in, out, len_in,
				len_out);
}

LIB_EXPORT ssize_t l_asymmetric_cipher_decrypt(struct l_asymmetric_cipher *cipher,
						const void *in, void *out,
						size_t len_in, size_t len_out)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->sk, ALG_OP_DECRYPT, in, out, len_in,
				len_out);
}

LIB_EXPORT ssize_t l_asymmetric_cipher_sign(struct l_asymmetric_cipher *cipher,
						const void *in, void *out,
						size_t len_in, size_t len_out)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->sk, ALG_OP_SIGN, in, out, len_in,
				len_out);
}

LIB_EXPORT ssize_t l_asymmetric_cipher_verify(struct l_asymmetric_cipher *cipher,
						const void *in, void *out,
						size_t len_in, size_t len_out)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->sk, ALG_OP_VERIFY, in, out, len_in,
				len_out);
}
