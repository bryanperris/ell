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

static uint32_t supported_ciphers;
static uint32_t supported_aead_ciphers;

struct l_cipher {
	int type;
	int encrypt_sk;
	int decrypt_sk;
};

struct l_aead_cipher {
	int type;
	int sk;
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

static const char *cipher_type_to_name(enum l_cipher_type type)
{
	switch (type) {
	case L_CIPHER_AES:
		return "ecb(aes)";
	case L_CIPHER_AES_CBC:
		return "cbc(aes)";
	case L_CIPHER_AES_CTR:
		return "ctr(aes)";
	case L_CIPHER_ARC4:
		return "ecb(arc4)";
	case L_CIPHER_DES:
		return "ecb(des)";
	case L_CIPHER_DES_CBC:
		return "cbc(des)";
	case L_CIPHER_DES3_EDE_CBC:
		return "cbc(des3_ede)";
	}

	return NULL;
}

LIB_EXPORT struct l_cipher *l_cipher_new(enum l_cipher_type type,
						const void *key,
						size_t key_length)
{
	struct l_cipher *cipher;
	const char *uninitialized_var(alg_name);

	if (unlikely(!key))
		return NULL;

	if (!is_valid_type(type))
		return NULL;

	cipher = l_new(struct l_cipher, 1);
	cipher->type = type;
	alg_name = cipher_type_to_name(type);

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

static const char *aead_cipher_type_to_name(enum l_aead_cipher_type type)
{
	switch (type) {
	case L_AEAD_CIPHER_AES_CCM:
		return "ccm(aes)";
	case L_AEAD_CIPHER_AES_GCM:
		return "gcm(aes)";
	}

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

	if (type != L_AEAD_CIPHER_AES_CCM && type != L_AEAD_CIPHER_AES_GCM)
		return NULL;

	cipher = l_new(struct l_aead_cipher, 1);
	cipher->type = type;
	alg_name = aead_cipher_type_to_name(type);

	cipher->sk = create_alg("aead", alg_name, key, key_length, tag_length);
	if (cipher->sk >= 0)
		return cipher;

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

	close(cipher->sk);

	l_free(cipher);
}

static ssize_t operate_cipher(int sk, __u32 operation,
				const void *in, size_t in_len,
				const void *ad, size_t ad_len,
				const void *iv, size_t iv_len,
				void *out, size_t out_len)
{
	char *c_msg_buf;
	size_t c_msg_size;
	struct msghdr msg;
	struct cmsghdr *c_msg;
	struct iovec iov[2];
	ssize_t result;

	c_msg_size = CMSG_SPACE(sizeof(operation));
	c_msg_size += ad_len ? CMSG_SPACE(sizeof(uint32_t)) : 0;
	c_msg_size += iv_len ?
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

	if (iv_len) {
		struct af_alg_iv *algiv;

		c_msg = CMSG_NXTHDR(&msg, c_msg);
		c_msg->cmsg_level = SOL_ALG;
		c_msg->cmsg_type = ALG_SET_IV;
		c_msg->cmsg_len = CMSG_LEN(sizeof(*algiv) + iv_len);

		algiv = (void *)CMSG_DATA(c_msg);
		algiv->ivlen = iv_len;
		memcpy(algiv->iv, iv, iv_len);
	}

	result = sendmsg(sk, &msg, 0);
	if (result < 0)
		return -errno;

	if (ad_len) {
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

		if (result >= (ssize_t) ad_len)
			result -= ad_len;
		else if (result > 0)
			result = 0;

		l_free(iov[0].iov_base);
	} else {
		result = read(sk, out, out_len);
	}

	if (result < 0)
		return -errno;

	return result;
}

static ssize_t operate_cipherv(int sk, __u32 operation,
				const struct iovec *in, size_t in_cnt,
				const struct iovec *out, size_t out_cnt)
{
	char *c_msg_buf;
	size_t c_msg_size;
	struct msghdr msg;
	struct cmsghdr *c_msg;
	ssize_t result;

	c_msg_size = CMSG_SPACE(sizeof(operation));
	c_msg_buf = alloca(c_msg_size);

	memset(c_msg_buf, 0, c_msg_size);
	memset(&msg, 0, sizeof(msg));

	msg.msg_iov = (struct iovec *) in;
	msg.msg_iovlen = in_cnt;

	msg.msg_control = c_msg_buf;
	msg.msg_controllen = c_msg_size;

	c_msg = CMSG_FIRSTHDR(&msg);
	c_msg->cmsg_level = SOL_ALG;
	c_msg->cmsg_type = ALG_SET_OP;
	c_msg->cmsg_len = CMSG_LEN(sizeof(operation));
	memcpy(CMSG_DATA(c_msg), &operation, sizeof(operation));

	result = sendmsg(sk, &msg, 0);
	if (result < 0)
		return -errno;

	result = readv(sk, out, out_cnt);

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
				NULL, 0, NULL, 0, out, len) >= 0;
}

LIB_EXPORT bool l_cipher_encryptv(struct l_cipher *cipher,
					const struct iovec *in, size_t in_cnt,
					const struct iovec *out, size_t out_cnt)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipherv(cipher->encrypt_sk, ALG_OP_ENCRYPT, in, in_cnt,
				out, out_cnt) >= 0;
}

LIB_EXPORT bool l_cipher_decrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->decrypt_sk, ALG_OP_DECRYPT, in, len,
				NULL, 0, NULL, 0, out, len) >= 0;
}

LIB_EXPORT bool l_cipher_decryptv(struct l_cipher *cipher,
					const struct iovec *in, size_t in_cnt,
					const struct iovec *out, size_t out_cnt)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipherv(cipher->decrypt_sk, ALG_OP_DECRYPT, in, in_cnt,
				out, out_cnt) >= 0;
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

#define CCM_IV_SIZE 16

static size_t l_aead_cipher_get_ivlen(struct l_aead_cipher *cipher)
{
	switch (cipher->type) {
	case L_AEAD_CIPHER_AES_CCM:
		return CCM_IV_SIZE;
	case L_AEAD_CIPHER_AES_GCM:
		return 12;
	}

	return 0;
}

/* RFC3610 Section 2.3 */
static ssize_t build_ccm_iv(const void *nonce, uint8_t nonce_len,
				uint8_t (*iv)[CCM_IV_SIZE])
{
	const size_t iv_overhead = 2;
	int lprime = 15 - nonce_len - 1;

	if (unlikely(nonce_len + iv_overhead > CCM_IV_SIZE || lprime > 7))
		return -EINVAL;

	(*iv)[0] = lprime;
	memcpy(*iv + 1, nonce, nonce_len);
	memset(*iv + 1 + nonce_len, 0, lprime + 1);

	return CCM_IV_SIZE;
}

LIB_EXPORT bool l_aead_cipher_encrypt(struct l_aead_cipher *cipher,
					const void *in, size_t in_len,
					const void *ad, size_t ad_len,
					const void *nonce, size_t nonce_len,
					void *out, size_t out_len)
{
	uint8_t ccm_iv[CCM_IV_SIZE];
	const uint8_t *iv;
	ssize_t iv_len;

	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	if (cipher->type == L_AEAD_CIPHER_AES_CCM) {
		iv_len = build_ccm_iv(nonce, nonce_len, &ccm_iv);
		if (unlikely(iv_len < 0))
			return false;

		iv = ccm_iv;
	} else {
		if (unlikely(nonce_len != l_aead_cipher_get_ivlen(cipher)))
			return false;

		iv = nonce;
		iv_len = nonce_len;
	}

	return operate_cipher(cipher->sk, ALG_OP_ENCRYPT, in, in_len,
				ad, ad_len, iv, iv_len, out, out_len) ==
			(ssize_t)out_len;
}

LIB_EXPORT bool l_aead_cipher_decrypt(struct l_aead_cipher *cipher,
					const void *in, size_t in_len,
					const void *ad, size_t ad_len,
					const void *nonce, size_t nonce_len,
					void *out, size_t out_len)
{
	uint8_t ccm_iv[CCM_IV_SIZE];
	const uint8_t *iv;
	ssize_t iv_len;

	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	if (cipher->type == L_AEAD_CIPHER_AES_CCM) {
		iv_len = build_ccm_iv(nonce, nonce_len, &ccm_iv);
		if (unlikely(iv_len < 0))
			return false;

		iv = ccm_iv;
	} else {
		if (unlikely(nonce_len != l_aead_cipher_get_ivlen(cipher)))
			return false;

		iv = nonce;
		iv_len = nonce_len;
	}

	return operate_cipher(cipher->sk, ALG_OP_DECRYPT, in, in_len,
				ad, ad_len, iv, iv_len, out, out_len) ==
			(ssize_t)out_len;
}

static void init_supported()
{
	static bool initialized = false;
	struct sockaddr_alg salg;
	int sk;
	enum l_cipher_type c;
	enum l_aead_cipher_type a;

	if (likely(initialized))
		return;

	initialized = true;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "skcipher");

	for (c = L_CIPHER_AES; c <= L_CIPHER_DES3_EDE_CBC; c++) {
		strcpy((char *) salg.salg_name, cipher_type_to_name(c));

		if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0)
			continue;

		supported_ciphers |= 1 << c;
	}

	strcpy((char *) salg.salg_type, "aead");

	for (a = L_AEAD_CIPHER_AES_CCM; a <= L_AEAD_CIPHER_AES_GCM; a++) {
		strcpy((char *) salg.salg_name, aead_cipher_type_to_name(a));

		if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0)
			continue;

		supported_aead_ciphers |= 1 << a;
	}

	close(sk);
}

LIB_EXPORT bool l_cipher_is_supported(enum l_cipher_type type)
{
	if (!is_valid_type(type))
		return false;

	init_supported();

	return supported_ciphers & (1 << type);
}

LIB_EXPORT bool l_aead_cipher_is_supported(enum l_aead_cipher_type type)
{
	if (type != L_AEAD_CIPHER_AES_CCM && type != L_AEAD_CIPHER_AES_GCM)
		return false;

	init_supported();

	return supported_aead_ciphers & (1 << type);
}
