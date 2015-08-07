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

#define is_valid_type(type)  ((type) <= L_CIPHER_DES3_EDE_CBC)

struct l_cipher {
	int type;
	int encrypt_sk;
	int decrypt_sk;
};

static int create_alg(const char *alg_type, const char *alg_name,
				const void *key, size_t key_length)
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

	cipher->encrypt_sk = create_alg("skcipher", alg_name, key, key_length);
	if (cipher->encrypt_sk < 0)
		goto error_free;

	cipher->decrypt_sk = create_alg("skcipher", alg_name, key, key_length);
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

static bool operate_cipher(int sk, __u32 operation,
				const void *in, void *out, size_t len)
{
	char c_msg_buf[CMSG_SPACE(sizeof(operation))];
	struct msghdr msg;
	struct cmsghdr *c_msg;
	struct iovec iov;

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
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sk, &msg, 0) < 0)
		return false;

	if (read(sk, out, len) < 0)
		return false;

	return true;
}

LIB_EXPORT bool l_cipher_encrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->encrypt_sk, ALG_OP_ENCRYPT, in, out, len);
}

LIB_EXPORT bool l_cipher_decrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->decrypt_sk, ALG_OP_DECRYPT, in, out, len);
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
	struct l_cipher cipher;
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
static uint8_t *der_find_elem(uint8_t *buf, size_t len_in, int index,
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
	size_t n_length;
	uint8_t *der;
	uint8_t tag;

	if (key_length < 8)
		return false;

	/* Unpack the outer SEQUENCE */
	der = der_find_elem((uint8_t *) key, key_length, 0, &tag, &n_length);
	if (!der || tag != ASN1_ID_SEQUENCE)
		return false;

	/* Take first INTEGER as the modulus */
	der = der_find_elem(der, n_length, 0, &tag, &n_length);
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

static void write_asn1_definite_length(uint8_t **buf, size_t len)
{
	int n;

	if (len < 0x80) {
		*(*buf)++ = len;

		return;
	}

	for (n = 1; len >> (n * 8); n++);
	*(*buf)++ = 0x80 | n;

	while (n--)
		*(*buf)++ = len >> (n * 8);
}

/*
 * Extract a ASN1 RsaKey-formatted public+private key structure in the
 * form used in the kernel.  It is simpler than the PKCS#1 form as it only
 * contains the N, E and D integers and also correctly parses as a PKCS#1
 * RSAPublicKey.
 */
uint8_t *extract_rsakey(uint8_t *pkcs1_key, size_t pkcs1_key_len,
			size_t *out_len)
{
	uint8_t *key, *ptr, *ver, *n, *e, *d;
	uint8_t tag;
	size_t ver_len, n_len, e_len, d_len;
	int pos;

	/* Unpack the outer SEQUENCE */
	pkcs1_key = der_find_elem(pkcs1_key, pkcs1_key_len, 0, &tag,
					&pkcs1_key_len);
	if (!pkcs1_key || tag != ASN1_ID_SEQUENCE)
		return NULL;

	/* Check if the version element if present */
	ver = der_find_elem(pkcs1_key, pkcs1_key_len, 0, &tag, &ver_len);
	if (!ver || tag != ASN1_ID_INTEGER)
		return NULL;

	pos = (ver_len == 1 && ver[0] == 0x00) ? 1 : 0;

	n = der_find_elem(pkcs1_key, pkcs1_key_len, pos + 0, &tag, &n_len);
	if (!n || tag != ASN1_ID_INTEGER)
		return NULL;

	e = der_find_elem(pkcs1_key, pkcs1_key_len, pos + 1, &tag, &e_len);
	if (!e || tag != ASN1_ID_INTEGER)
		return NULL;

	d = der_find_elem(pkcs1_key, pkcs1_key_len, pos + 2, &tag, &d_len);
	if (!d || tag != ASN1_ID_INTEGER)
		return NULL;

	/* New SEQUENCE length including tags and lengths */
	*out_len = 1 + (n_len >= 0x80 ? n_len >= 0x100 ? 3 : 2 : 1) + n_len +
		1 + (e_len >= 0x80 ? e_len >= 0x100 ? 3 : 2 : 1) + e_len +
		1 + (d_len >= 0x80 ? d_len >= 0x100 ? 3 : 2 : 1) + d_len;
	ptr = key = l_malloc(*out_len +
		1 + (*out_len >= 0x80 ? *out_len >= 0x100 ? 3 : 2 : 1));

	*ptr++ = ASN1_ID_SEQUENCE;
	write_asn1_definite_length(&ptr, *out_len);

	*ptr++ = ASN1_ID_INTEGER;
	write_asn1_definite_length(&ptr, n_len);
	memcpy(ptr, n, n_len);
	ptr += n_len;

	*ptr++ = ASN1_ID_INTEGER;
	write_asn1_definite_length(&ptr, e_len);
	memcpy(ptr, e, e_len);
	ptr += e_len;

	*ptr++ = ASN1_ID_INTEGER;
	write_asn1_definite_length(&ptr, d_len);
	memcpy(ptr, d, d_len);
	ptr += d_len;

	*out_len = ptr - key;
	return key;
}

LIB_EXPORT struct l_asymmetric_cipher *l_asymmetric_cipher_new(
					enum l_asymmetric_cipher_type type,
					const void *key, size_t key_length)
{
	struct l_asymmetric_cipher *cipher;
	const char *alg_name;

	if (unlikely(!key))
		return NULL;

	if (type != L_CIPHER_RSA_PKCS1_V1_5)
		return NULL;

	cipher = l_new(struct l_asymmetric_cipher, 1);
	cipher->cipher.type = type;

	switch (type) {
	case L_CIPHER_RSA_PKCS1_V1_5:
		if (!parse_rsa_key(cipher, key, key_length))
			goto error_free;

		alg_name = "rsa";
		break;
	}

	cipher->cipher.encrypt_sk = create_alg("akcipher", alg_name,
						key, key_length);
	if (cipher->cipher.encrypt_sk < 0)
		goto error_free;

	cipher->cipher.decrypt_sk = create_alg("akcipher", alg_name,
						key, key_length);
	if (cipher->cipher.decrypt_sk < 0)
		goto error_close;

	return cipher;

error_close:
	close(cipher->cipher.encrypt_sk);
error_free:
	l_free(cipher);
	return NULL;
}

LIB_EXPORT void l_asymmetric_cipher_free(struct l_asymmetric_cipher *cipher)
{
	if (unlikely(!cipher))
		return;

	close(cipher->cipher.encrypt_sk);
	close(cipher->cipher.decrypt_sk);

	l_free(cipher);
}

LIB_EXPORT int l_asymmetric_cipher_get_key_size(
					struct l_asymmetric_cipher *cipher)
{
	return cipher->key_size;
}

static void getrandom_nonzero(uint8_t *buf, int len)
{
	while (len--) {
		l_getrandom(buf, 1);
		while (buf[0] == 0)
			l_getrandom(buf, 1);

		buf++;
	}
}

LIB_EXPORT bool l_asymmetric_cipher_encrypt(struct l_asymmetric_cipher *cipher,
					const void *in, void *out,
					size_t len_in, size_t len_out)
{
	if (cipher->cipher.type == L_CIPHER_RSA_PKCS1_V1_5) {
		/* PKCS#1 v1.5 RSA padding according to RFC3447 */
		uint8_t buf[cipher->key_size];
		int ps_len = cipher->key_size - len_in - 3;

		if (len_in > (size_t) cipher->key_size - 11)
			return false;
		if (len_out != (size_t) cipher->key_size)
			return false;

		buf[0] = 0x00;
		buf[1] = 0x02;
		getrandom_nonzero(buf + 2, ps_len);
		buf[ps_len + 2] = 0x00;
		memcpy(buf + ps_len + 3, in, len_in);

		if (!l_cipher_encrypt(&cipher->cipher, buf, out,
					cipher->key_size))
			return false;
	}

	return true;
}

LIB_EXPORT bool l_asymmetric_cipher_decrypt(struct l_asymmetric_cipher *cipher,
					const void *in, void *out,
					size_t len_in, size_t len_out)
{
	if (cipher->cipher.type == L_CIPHER_RSA_PKCS1_V1_5) {
		/* PKCS#1 v1.5 RSA padding according to RFC3447 */
		uint8_t buf[cipher->key_size];
		int pos;

		if (len_in != (size_t) cipher->key_size)
			return false;

		if (!l_cipher_decrypt(&cipher->cipher, in, buf,
					cipher->key_size))
			return false;

		if (buf[0] != 0x00)
			return false;
		if (buf[1] != 0x02)
			return false;

		for (pos = 2; pos < cipher->key_size; pos++)
			if (buf[pos] == 0)
				break;
		if (pos < 10 || pos == cipher->key_size)
			return false;

		pos++;
		if (len_out != (size_t) cipher->key_size - pos)
			return false;

		memcpy(out, buf + pos, cipher->key_size - pos);
	}

	return true;
}

LIB_EXPORT bool l_asymmetric_cipher_sign(struct l_asymmetric_cipher *cipher,
					const void *in, void *out,
					size_t len_in, size_t len_out)
{
	if (cipher->cipher.type == L_CIPHER_RSA_PKCS1_V1_5) {
		/* PKCS#1 v1.5 RSA padding according to RFC3447 */
		uint8_t buf[cipher->key_size];
		int ps_len = cipher->key_size - len_in - 3;

		if (len_in > (size_t) cipher->key_size - 11)
			return false;
		if (len_out != (size_t) cipher->key_size)
			return false;

		buf[0] = 0x00;
		buf[1] = 0x01;
		memset(buf + 2, 0xff, ps_len);
		buf[ps_len + 2] = 0x00;
		memcpy(buf + ps_len + 3, in, len_in);

		/*
		 * The RSA signing operation uses the same primitive as
		 * decryption so just call decrypt for now.
		 */
		if (!l_cipher_decrypt(&cipher->cipher, buf, out,
					cipher->key_size))
			return false;
	}

	return true;
}

LIB_EXPORT bool l_asymmetric_cipher_verify(struct l_asymmetric_cipher *cipher,
					const void *in, void *out,
					size_t len_in, size_t len_out)
{
	if (cipher->cipher.type == L_CIPHER_RSA_PKCS1_V1_5) {
		/* PKCS#1 v1.5 RSA padding according to RFC3447 */
		uint8_t buf[cipher->key_size];
		int pos;

		if (len_in != (size_t) cipher->key_size)
			return false;

		/*
		 * The RSA verify operation uses the same primitive as
		 * encryption so just call encrypt.
		 */
		if (!l_cipher_encrypt(&cipher->cipher, in, buf,
					cipher->key_size))
			return false;

		if (buf[0] != 0x00)
			return false;
		if (buf[1] != 0x01)
			return false;

		for (pos = 2; pos < cipher->key_size; pos++)
			if (buf[pos] != 0xff)
				break;
		if (pos < 10 || pos == cipher->key_size || buf[pos] != 0)
			return false;

		pos++;
		if (len_out != (size_t) cipher->key_size - pos)
			return false;

		memcpy(out, buf + pos, cipher->key_size - pos);
	}

	return true;
}
