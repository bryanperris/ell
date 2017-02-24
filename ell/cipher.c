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
#include <alloca.h>

#include "util.h"
#include "cipher.h"
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

#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN	4
#endif

#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE	5
#endif

#define is_valid_type(type)  ((type) <= L_CIPHER_DES3_EDE_CBC)

struct l_cipher {
	int type;
	int encrypt_sk;
	int decrypt_sk;
};

struct l_aead_cipher {
	int type;
	int encrypt_sk;
	int decrypt_sk;
};

static int create_alg(const char *alg_type, const char *alg_name,
			const void *key, size_t key_length, size_t tag_length)
{
	struct sockaddr_alg salg;
	int sk;
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

	if (setsockopt(sk, SOL_ALG, ALG_SET_KEY, key, key_length) < 0) {
		close(sk);
		return -1;
	}

	if (tag_length && setsockopt(sk, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL,
					tag_length)) {
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
	case L_CIPHER_DES:
		alg_name = "ecb(des)";
		break;
	case L_CIPHER_DES3_EDE_CBC:
		alg_name = "cbc(des3_ede)";
		break;
	}

	cipher->encrypt_sk = create_alg("skcipher", alg_name, key, key_length,
					0);
	if (cipher->encrypt_sk < 0)
		goto error_free;

	cipher->decrypt_sk = create_alg("skcipher", alg_name, key, key_length,
					0);
	if (cipher->decrypt_sk < 0)
		goto error_close;

	return cipher;

error_close:
	close(cipher->encrypt_sk);
error_free:
	l_free(cipher);
	return NULL;
}

LIB_EXPORT struct l_aead_cipher *l_aead_cipher_new(enum l_aead_cipher_type type,
							const void *key,
							size_t key_length,
							size_t tag_length)
{
	struct l_aead_cipher *cipher;
	const char *alg_name;

	if (unlikely(!key))
		return NULL;

	if (type != L_AEAD_CIPHER_AES_CCM)
		return NULL;

	cipher = l_new(struct l_aead_cipher, 1);
	cipher->type = type;

	switch (type) {
	case L_AEAD_CIPHER_AES_CCM:
		alg_name = "ccm(aes)";
		break;
	}

	cipher->encrypt_sk = create_alg("aead", alg_name, key, key_length,
					tag_length);
	if (cipher->encrypt_sk < 0)
		goto error_free;

	cipher->decrypt_sk = create_alg("aead", alg_name, key, key_length,
					tag_length);
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

LIB_EXPORT void l_aead_cipher_free(struct l_aead_cipher *cipher)
{
	if (unlikely(!cipher))
		return;

	close(cipher->encrypt_sk);
	close(cipher->decrypt_sk);

	l_free(cipher);
}

static ssize_t build_iv(const void *nonce, uint8_t nonce_len, uint8_t *iv,
			uint8_t iv_len)
{
	const size_t iv_overhead = 2;

	if (nonce_len + iv_overhead > iv_len)
		return -EINVAL;

	iv[0] = iv_len - iv_overhead - nonce_len;
	memcpy(iv + 1, nonce, nonce_len);

	/* Assumes that remaining bytes in iv were already zeroed out */

	return iv_len;
}

static ssize_t operate_cipher(int sk, __u32 operation,
				const void *in, size_t in_len,
				const void *ad, size_t ad_len,
				const void *nonce, size_t nonce_len,
				void *out, size_t out_len,
				size_t iv_len)
{
	char *c_msg_buf;
	size_t c_msg_size;
	struct msghdr msg;
	struct cmsghdr *c_msg;
	struct iovec iov[2];
	ssize_t result;

	c_msg_size = CMSG_SPACE(sizeof(operation));
	c_msg_size += ad_len ? CMSG_SPACE(sizeof(uint32_t)) : 0;
	c_msg_size += (nonce && iv_len) ?
		CMSG_SPACE(sizeof(struct af_alg_iv) + iv_len) : 0;

	c_msg_buf = alloca(c_msg_size);

	memset(c_msg_buf, 0, c_msg_size);
	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = iov;

	msg.msg_control = c_msg_buf;
	msg.msg_controllen = c_msg_size;

	c_msg = CMSG_FIRSTHDR(&msg);
	c_msg->cmsg_level = SOL_ALG;
	c_msg->cmsg_type = ALG_SET_OP;
	c_msg->cmsg_len = CMSG_LEN(sizeof(operation));
	memcpy(CMSG_DATA(c_msg), &operation, sizeof(operation));

	if (ad_len) {
		uint32_t *ad_data;

		c_msg = CMSG_NXTHDR(&msg, c_msg);
		c_msg->cmsg_level = SOL_ALG;
		c_msg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
		c_msg->cmsg_len = CMSG_LEN(sizeof(*ad_data));
		ad_data = (void *) CMSG_DATA(c_msg);
		*ad_data = ad_len;

		iov[0].iov_base = (void *) ad;
		iov[0].iov_len = ad_len;
		iov[1].iov_base = (void *) in;
		iov[1].iov_len = in_len;
		msg.msg_iovlen = 2;
	} else {
		iov[0].iov_base = (void *) in;
		iov[0].iov_len = in_len;
		msg.msg_iovlen = 1;
	}

	if (nonce && iv_len) {
		struct af_alg_iv *algiv;

		c_msg = CMSG_NXTHDR(&msg, c_msg);
		c_msg->cmsg_level = SOL_ALG;
		c_msg->cmsg_type = ALG_SET_IV;
		c_msg->cmsg_len = CMSG_LEN(sizeof(*algiv) + iv_len);

		algiv = (void *)CMSG_DATA(c_msg);
		algiv->ivlen = iv_len;
		result = build_iv(nonce, nonce_len, &algiv->iv[0], iv_len);
		if (result < 0)
			return result;
	}

	result = sendmsg(sk, &msg, 0);
	if (result < 0)
		return -errno;

	if (ad) {
		/*
		 * When AEAD additional data is passed to sendmsg() for
		 * use in computing the tag, those bytes also appear at
		 * the beginning of the encrypt or decrypt results.  Rather
		 * than force the caller to pad their result buffer with
		 * the correct number of bytes for the additional data,
		 * the necessary space is allocated here and then the
		 * duplicate AAD is discarded.
		 */
		iov[0].iov_base = l_malloc(ad_len);
		iov[0].iov_len = ad_len;
		iov[1].iov_base = (void *) out;
		iov[1].iov_len = out_len;
		msg.msg_iovlen = 2;

		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		result = recvmsg(sk, &msg, 0);

		if (result > (ssize_t) ad_len)
			result -= ad_len;

		l_free(iov[0].iov_base);
	} else {
		result = read(sk, out, out_len);
	}

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

	return operate_cipher(cipher->encrypt_sk, ALG_OP_ENCRYPT, in, len,
				NULL, 0, NULL, 0, out, len, 0) >= 0;
}

LIB_EXPORT bool l_cipher_decrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->decrypt_sk, ALG_OP_DECRYPT, in, len,
				NULL, 0, NULL, 0, out, len, 0) >= 0;
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

static size_t l_aead_cipher_get_ivlen(struct l_aead_cipher *cipher)
{
	size_t ret;

	switch (cipher->type) {
	case L_AEAD_CIPHER_AES_CCM:
		ret = 16;
		break;
	}

	return ret;
}

LIB_EXPORT bool l_aead_cipher_encrypt(struct l_aead_cipher *cipher,
					const void *in, size_t in_len,
					const void *ad, size_t ad_len,
					const void *nonce, size_t nonce_len,
					void *out, size_t out_len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->encrypt_sk, ALG_OP_ENCRYPT, in, in_len,
				ad, ad_len, nonce, nonce_len, out, out_len,
				l_aead_cipher_get_ivlen(cipher)) >= 0;
}

LIB_EXPORT bool l_aead_cipher_decrypt(struct l_aead_cipher *cipher,
					const void *in, size_t in_len,
					const void *ad, size_t ad_len,
					const void *nonce, size_t nonce_len,
					void *out, size_t out_len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->decrypt_sk, ALG_OP_DECRYPT, in, in_len,
				ad, ad_len, nonce, nonce_len, out, out_len,
				l_aead_cipher_get_ivlen(cipher)) >= 0;
}
