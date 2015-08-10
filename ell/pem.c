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
#include "string.h"

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
				char **type_label, size_t *len)
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

	return NULL;
}

LIB_EXPORT uint8_t *l_pem_load_buffer(const uint8_t *buf, size_t buf_len,
					int index, char **type_label,
					size_t *out_len)
{
	return pem_load_buffer(buf, buf_len, index, type_label, out_len);
}

LIB_EXPORT uint8_t *l_pem_load_file(const char *filename, int index,
					char **type_label, size_t *len)
{
	int fd;
	struct stat st;
	uint8_t *data, *result;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);

		return NULL;
	}

	data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		close(fd);

		return NULL;
	}

	result = pem_load_buffer(data, st.st_size, index, type_label, len);

	munmap(data, st.st_size);
	close(fd);

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

LIB_EXPORT uint8_t *l_pem_load_private_key(const char *filename,
						const char *passphrase,
						size_t *len)
{
	uint8_t *content;
	char *label;

	content = l_pem_load_file(filename, 0, &label, len);

	if (!content)
		return NULL;

	/*
	 * RFC7469- and PKCS#8-compatible label (default in OpenSSL 1.0.1+)
	 * and the older (OpenSSL <= 0.9.8 default) label.
	 */
	if (strcmp(label, "PRIVATE KEY") && strcmp(label, "RSA PRIVATE KEY")) {
		l_free(content);
		content = NULL;
	}

	/*
	 * TODO: handle ENCRYPTED PRIVATE KEY - RFC5958 section 3.
	 *
	 * TODO: handle RSA PRIVATE KEY encrypted keys (OpenSSL <= 0.9.8),
	 * incompatible with RFC7468 parsing because of the headers present
	 * before base64 encoded data.
	 */

	l_free(label);

	return content;
}
