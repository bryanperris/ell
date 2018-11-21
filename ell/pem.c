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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "util.h"
#include "private.h"
#include "pem.h"
#include "base64.h"
#include "utf8.h"
#include "asn1-private.h"
#include "pkcs5-private.h"
#include "cipher.h"
#include "cert-private.h"

#define PEM_START_BOUNDARY	"-----BEGIN "
#define PEM_END_BOUNDARY	"-----END "

static const uint8_t *is_start_boundary(const uint8_t *buf, size_t buf_len,
					size_t *label_len)
{
	const uint8_t *start, *end, *ptr;
	int prev_special, special;

	if (buf_len < strlen(PEM_START_BOUNDARY))
		return NULL;

	/* Check we have a "-----BEGIN " (RFC7468 section 2) */
	if (memcmp(buf, PEM_START_BOUNDARY, strlen(PEM_START_BOUNDARY)))
		return NULL;

	/*
	 * Check we have a string of printable characters in which no
	 * two consecutive characters are "special" nor is the first or the
	 * final character "special".  These special characters are space
	 * and hyphen.  (RFC7468 section 3)
	 * The loop will end on the second hyphen of the final "-----" if
	 * no error found earlier.
	 */
	start = buf + strlen(PEM_START_BOUNDARY);
	end = start;
	prev_special = 1;

	while (end < buf + buf_len && l_ascii_isprint(*end)) {
		special = *end == ' ' || *end == '-';

		if (prev_special && special)
			break;

		end++;
		prev_special = special;
	}

	/* Rewind to the first '-', but handle empty labels */
	if (end != start)
		end--;

	/* Check we have a "-----" (RFC7468 section 2) */
	if (end + 5 > buf + buf_len || memcmp(end, "-----", 5))
		return NULL;

	/* Check all remaining characters are horizontal whitespace (WSP) */
	for (ptr = end + 5; ptr < buf + buf_len; ptr++)
		if (*ptr != ' ' && *ptr != '\t')
			return NULL;

	*label_len = end - start;

	return start;
}

static bool is_end_boundary(const uint8_t *buf, size_t buf_len,
				const uint8_t *label, size_t label_len)
{
	size_t len = strlen(PEM_END_BOUNDARY) + label_len + 5;

	if (buf_len < len)
		return false;

	if (memcmp(buf, PEM_END_BOUNDARY, strlen(PEM_END_BOUNDARY)) ||
			memcmp(buf + strlen(PEM_END_BOUNDARY),
				label, label_len) ||
			memcmp(buf + (len - 5), "-----", 5))
		return false;

	/* Check all remaining characters are horizontal whitespace (WSP) */
	for (; len < buf_len; len++)
		if (buf[len] != ' ' && buf[len] != '\t')
			return false;

	return true;
}

static uint8_t *pem_load_buffer(const uint8_t *buf, size_t buf_len, int index,
				char **type_label, size_t *len,
				const uint8_t **endp)
{
	const uint8_t *base64_data = NULL, *label = NULL, *eol;
	uint8_t *data;
	size_t label_len = 0;

	/*
	 * The base64 parser uses the RFC7468 laxbase64text grammar but we
	 * do full checks on the encapsulation boundary lines, i.e. no
	 * leading spaces allowed, making sure quoted text and similar
	 * are not confused for actual PEM "textual encoding".
	 */
	while (buf_len) {
		for (eol = buf; eol < buf + buf_len; eol++)
			if (*eol == '\r' || *eol == '\n')
				break;

		if (!base64_data) {
			label = is_start_boundary(buf, eol - buf, &label_len);

			if (label)
				base64_data = eol;
		} else if (is_end_boundary(buf, eol - buf, label, label_len)) {
			if (index == 0) {
				data = l_base64_decode(
						(const char *) base64_data,
						buf - base64_data, len);
				if (!data)
					return NULL;

				*type_label = l_strndup((const char *) label,
							label_len);

				if (endp)
					*endp = eol + 1;

				return data;
			}

			base64_data = NULL;
			index--;
		}

		if (eol == buf + buf_len)
			break;

		buf_len -= eol + 1 - buf;
		buf = eol + 1;

		if (buf_len && *eol == '\r' && *buf == '\n') {
			buf++;
			buf_len--;
		}
	}

	/* If we found no label signal EOF rather than parse error */
	if (!base64_data && endp)
		*endp = NULL;

	return NULL;
}

LIB_EXPORT uint8_t *l_pem_load_buffer(const uint8_t *buf, size_t buf_len,
					int index, char **type_label,
					size_t *out_len)
{
	return pem_load_buffer(buf, buf_len, index, type_label, out_len, NULL);
}

struct pem_file_info {
	int fd;
	struct stat st;
	uint8_t *data;
};

static int pem_file_open(struct pem_file_info *info, const char *filename)
{
	info->fd = open(filename, O_RDONLY);
	if (info->fd < 0)
		return -errno;

	if (fstat(info->fd, &info->st) < 0) {
		int r = -errno;

		close(info->fd);
		return r;
	}

	info->data = mmap(NULL, info->st.st_size,
				PROT_READ, MAP_SHARED, info->fd, 0);
	if (info->data == MAP_FAILED) {
		int r = -errno;

		close(info->fd);
		return r;
	}

	return 0;
}

static void pem_file_close(struct pem_file_info *info)
{
	munmap(info->data, info->st.st_size);
	close(info->fd);
}

LIB_EXPORT uint8_t *l_pem_load_file(const char *filename, int index,
					char **type_label, size_t *len)
{
	struct pem_file_info file;
	uint8_t *result;

	if (pem_file_open(&file, filename) < 0)
		return NULL;

	result = pem_load_buffer(file.data, file.st.st_size, index,
					type_label, len, NULL);
	pem_file_close(&file);
	return result;
}

LIB_EXPORT uint8_t *l_pem_load_certificate(const char *filename, size_t *len)
{
	uint8_t *content;
	char *label;

	content = l_pem_load_file(filename, 0, &label, len);

	if (!content)
		return NULL;

	if (strcmp(label, "CERTIFICATE")) {
		l_free(content);
		content = NULL;
	}

	l_free(label);

	return content;
}

LIB_EXPORT struct l_certchain *l_pem_load_certificate_chain(
							const char *filename)
{
	struct l_queue *list = l_pem_load_certificate_list(filename);
	struct l_certchain *chain;

	if (!list)
		return NULL;

	chain = certchain_new_from_leaf(l_queue_pop_head(list));

	while (!l_queue_isempty(list))
		certchain_link_issuer(chain, l_queue_pop_head(list));

	l_queue_destroy(list, NULL);
	return chain;
}

LIB_EXPORT struct l_queue *l_pem_load_certificate_list(const char *filename)
{
	struct pem_file_info file;
	const uint8_t *ptr, *end;
	struct l_queue *list = NULL;

	if (pem_file_open(&file, filename) < 0)
		return NULL;

	ptr = file.data;
	end = file.data + file.st.st_size;

	while (ptr && ptr < end) {
		uint8_t *der;
		size_t der_len;
		char *label;
		struct l_cert *cert;

		der = pem_load_buffer(ptr, end - ptr, 0, &label, &der_len, &ptr);

		if (!der || strcmp(label, "CERTIFICATE")) {
			l_free(der);
			l_free(label);

			if (!ptr)	/* EOF */
				break;
			else
				goto error;
		}

		l_free(label);
		cert = l_cert_new_from_der(der, der_len);
		l_free(der);

		if (!cert)
			goto error;

		if (!list)
			list = l_queue_new();

		l_queue_push_tail(list, cert);
	}

	pem_file_close(&file);
	return list;

error:
	l_queue_destroy(list, (l_queue_destroy_func_t) l_cert_free);
	pem_file_close(&file);
	return NULL;
}

/**
 * l_pem_load_private_key
 * @filename: path string to the PEM file to load
 * @passphrase: private key encryption passphrase or NULL for unencrypted
 * @encrypted: receives indication whether the file was encrypted if non-NULL
 * @len: receives the length of the returned buffer
 *
 * Load the PEM encoded RSA Private Key file at @filename.  If it is an
 * encrypted private key and @passphrase was non-NULL, the file is
 * decrypted.  If it's unencrypted @passphrase is ignored.  @encrypted
 * stores information of whether the file was encrypted, both in a
 * success case and on error when NULL is returned.  This can be used to
 * check if a passphrase is required without prior information.
 *
 * Returns: Buffer containing raw DER data for the private key or NULL, to
 * be freed with l_free.
 **/
LIB_EXPORT uint8_t *l_pem_load_private_key(const char *filename,
						const char *passphrase,
						bool *encrypted, size_t *len)
{
	uint8_t *content;
	char *label;

	if (encrypted)
		*encrypted = false;

	content = l_pem_load_file(filename, 0, &label, len);

	if (!content)
		return NULL;

	/*
	 * RFC7469- and PKCS#8-compatible label (default in OpenSSL 1.0.1+)
	 * and the older (OpenSSL <= 0.9.8 default) label.
	 */
	if (!strcmp(label, "PRIVATE KEY") ||
			!strcmp(label, "RSA PRIVATE KEY"))
		goto done;

	/* RFC5958 (PKCS#8) section 3 type encrypted key label */
	if (!strcmp(label, "ENCRYPTED PRIVATE KEY")) {
		const uint8_t *key_info, *alg_id, *data;
		uint8_t tag;
		size_t key_info_len, alg_id_len, data_len, tmp_len;
		struct l_cipher *alg;
		uint8_t *decrypted;
		int i;

		if (encrypted)
			*encrypted = true;

		if (!passphrase)
			goto err;

		/* Technically this is BER, not limited to DER */
		key_info = asn1_der_find_elem(content, *len, 0, &tag,
						&key_info_len);
		if (!key_info || tag != ASN1_ID_SEQUENCE)
			goto err;

		alg_id = asn1_der_find_elem(key_info, key_info_len, 0, &tag,
						&alg_id_len);
		if (!alg_id || tag != ASN1_ID_SEQUENCE)
			goto err;

		data = asn1_der_find_elem(key_info, key_info_len, 1, &tag,
						&data_len);
		if (!data || tag != ASN1_ID_OCTET_STRING || data_len < 8 ||
				(data_len & 7) != 0)
			goto err;

		if (asn1_der_find_elem(content, *len, 2, &tag, &tmp_len))
			goto err;

		alg = pkcs5_cipher_from_alg_id(alg_id, alg_id_len, passphrase);
		if (!alg)
			goto err;

		decrypted = l_malloc(data_len);

		if (!l_cipher_decrypt(alg, data, decrypted, data_len)) {
			l_cipher_free(alg);
			l_free(decrypted);
			goto err;
		}

		l_cipher_free(alg);
		l_free(content);
		content = decrypted;

		/*
		 * Strip padding as defined in RFC8018 (for PKCS#5 v1) or
		 * RFC1423 / RFC5652 (for v2).
		 */

		if (content[data_len - 1] >= data_len ||
				content[data_len - 1] > 16)
			goto err;

		for (i = 1; i < content[data_len - 1]; i++)
			if (content[data_len - 1 - i] != content[data_len - 1])
				goto err;

		*len = data_len - content[data_len - 1];

		goto done;
	}

	/*
	 * TODO: handle RSA PRIVATE KEY format encrypted keys
	 * (as produced by "openssl rsa" commands), incompatible with
	 * RFC7468 parsing because of the headers present before
	 * base64-encoded data.
	 */

	/* Label not known */
err:
	l_free(content);
	content = NULL;

done:
	l_free(label);

	return content;
}
